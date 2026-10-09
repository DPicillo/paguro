// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Command paguro-phantom-test drives the Phantom-mode datapath
// (internal/phantom) by hand: attach/detach programs, install the rules of a
// migration from a flow list, inspect rules and counters, and clean up. It
// is a test and debugging tool; the agent uses the package directly.
//
//	paguro-phantom-test attach   -kind pod|podhost|hostdev|hostlocal [-netns PATH] -if NAME
//	paguro-phantom-test detach   -kind ... [-netns PATH] -if NAME
//	paguro-phantom-test plan     -old IP -new IP -flows FILE|- [-target] [-pod-netns P -pod-if eth0 -pod-hostif H]
//	                           [-local-pod IP=NETNS,IF ...] [-host-ip IP ...] [-hostdev DEV ...] [-pending] [-apply|-revert]
//	paguro-phantom-test harvest  -netns PATH -ip OLDIP [-ct-netns P] [-cluster-net CIDR ...] (prints flows as JSON)
//	paguro-phantom-test listeners -netns PATH -ip OLDIP           (TCP listeners bound to OLD, comma-separated)
//	paguro-phantom-test selfip   -netns PATH -old IP -new IP [-ports P,Q] (nftables self-IP fix-up in the pod)
//	paguro-phantom-test clear-pending -id N
//	paguro-phantom-test rules | stats | attachments
//	paguro-phantom-test remove   -id N                          (delete all rules of a migration)
//	paguro-phantom-test enable|disable
//	paguro-phantom-test cleanup                                 (detach everything, remove pins)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"paguro.dev/paguro/internal/phantom"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// testPinPath is this tool's own bpffs directory.
const testPinPath = "/sys/fs/bpf/paguro/phantom-test"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: paguro-phantom-test <command> [flags] (see source header)")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	// Not the agent's pin directory by default: "cleanup" would wipe the
	// live translations of the node. -pin /sys/fs/bpf/paguro/phantom to
	// inspect those on purpose.
	pin := fs.String("pin", testPinPath, "bpffs pin directory")
	legacy := fs.Bool("legacy", false, "force legacy tc (clsact) instead of TCX")
	kind := fs.String("kind", "pod", "attachment kind")
	nsPath := fs.String("netns", "", "network namespace path")
	ifname := fs.String("if", "", "interface name")
	oldIP := fs.String("old", "", "old pod IP")
	newIP := fs.String("new", "", "new pod IP")
	newNode := fs.String("new-node", "", "target node IP (tunnel rewrite)")
	flowsFile := fs.String("flows", "", "flows JSON file ('-' = stdin)")
	target := fs.Bool("target", false, "this node is the target node")
	podNetns := fs.String("pod-netns", "", "migrated pod netns (target)")
	podIf := fs.String("pod-if", "eth0", "migrated pod interface (target)")
	podHostIf := fs.String("pod-hostif", "", "migrated pod host-side veth (target)")
	pending := fs.Bool("pending", false, "install migrated pod inbound rules as pending")
	apply := fs.Bool("apply", false, "install attachments, reservations and rules (default: print only)")
	revert := fs.Bool("revert", false, "remove the rules and reservations of the plan")
	noReserve := fs.Bool("no-reservations", false, "plan: skip wire-tuple reservations (negative tests only)")
	hostSide := fs.Bool("host-side", false, "attach pod programs on the host-side veth")
	tunnel := fs.Bool("tunnel", false, "rewrite tunnel remote on host-scope out rules")
	id := fs.Uint("id", 0, "migration id (default: derived from -old/-new)")
	ip := fs.String("ip", "", "local IP for harvest")
	ctNetns := fs.String("ct-netns", "", "harvest: resolve DNAT/SNAT with the conntrack table of this (old node) netns")
	portList := fs.String("ports", "", "selfip: OLD-bound listener ports harvested at freeze time (default: harvest -netns now)")
	var localPods, hostIPs, hostDevs, viaNF, clusterNets multi
	fs.Var(&clusterNets, "cluster-net", "harvest: in-cluster prefix (repeatable)")
	fs.Var(&localPods, "local-pod", "IP=NETNS,IF[,HOSTIF] of a local pod (repeatable)")
	fs.Var(&hostIPs, "host-ip", "address of this node's host netns (repeatable)")
	fs.Var(&hostDevs, "hostdev", "host device carrying pod traffic (repeatable)")
	fs.Var(&viaNF, "via-netfilter", "peer IP whose flows go through kernel DNAT (repeatable)")
	_ = fs.Parse(args)

	if cmd == "cleanup" {
		check(phantom.Cleanup(*pin))
		return
	}
	if cmd == "listeners" {
		// The source side of the self-IP fix-up: run at freeze time in the old
		// pod, while the listeners still exist (the target pod has none until
		// CRIU has restored the process).
		ports, err := phantom.HarvestOldBoundListeners(*nsPath, netip.MustParseAddr(*ip))
		check(err)
		fmt.Println(joinPorts(ports))
		return
	}
	if cmd == "selfip" {
		old := netip.MustParseAddr(*oldIP)
		var ports []uint16
		if *portList != "" {
			ports = parsePorts(*portList)
		} else {
			var err error
			ports, err = phantom.HarvestOldBoundListeners(*nsPath, old)
			check(err)
		}
		fmt.Printf("listeners bound to %s: %v\n", old, ports)
		check(phantom.InstallSelfIPFixup(nil, *nsPath, old, netip.MustParseAddr(*newIP), ports))
		return
	}
	if cmd == "harvest" {
		flows, err := phantom.HarvestFlows(*nsPath, netip.MustParseAddr(*ip))
		check(err)
		var nets []netip.Prefix
		for _, c := range clusterNets {
			nets = append(nets, netip.MustParsePrefix(c))
		}
		if *ctNetns != "" {
			flows, err = phantom.ResolveWithConntrack(*ctNetns, flows, nets)
			check(err)
		}
		if len(nets) > 0 {
			flows = phantom.Classify(flows, nets)
		}
		printJSON(flows)
		return
	}

	t, err := phantom.New(*pin, phantom.Options{ForceLegacyTC: *legacy})
	check(err)
	defer t.Close()

	switch cmd {
	case "attach", "detach":
		a := phantom.Attachment{Netns: *nsPath, Ifname: *ifname, Kind: phantom.Kind(*kind)}
		if cmd == "attach" {
			check(t.Attach(a))
		} else {
			check(t.Detach(a))
		}
	case "plan":
		m := phantom.Migration{OldIP: netip.MustParseAddr(*oldIP), NewIP: netip.MustParseAddr(*newIP)}
		if *newNode != "" {
			m.NewNodeIP = netip.MustParseAddr(*newNode)
		}
		m.ID = uint32(*id)
		if m.ID == 0 {
			m.ID = phantom.MigrationID(*oldIP + "->" + *newIP)
		}
		var r io.Reader = os.Stdin
		if *flowsFile != "-" {
			f, err := os.Open(*flowsFile)
			check(err)
			defer f.Close()
			r = f
		}
		var flows []phantom.Flow
		check(json.NewDecoder(r).Decode(&flows))
		ctx := phantom.NodeContext{
			IsTarget:          *target,
			Migrated:          phantom.PodEndpoint{Netns: *podNetns, Ifname: *podIf, HostIfname: *podHostIf},
			LocalPods:         map[netip.Addr]phantom.PodEndpoint{},
			HostIPs:           map[netip.Addr]bool{},
			HostDevices:       hostDevs,
			HostSidePlacement: *hostSide,
			Pending:           *pending,
			TunnelRewrite:     *tunnel,
		}
		for _, lp := range localPods {
			ipS, rest, _ := strings.Cut(lp, "=")
			parts := strings.Split(rest, ",")
			ep := phantom.PodEndpoint{Netns: parts[0]}
			if len(parts) > 1 {
				ep.Ifname = parts[1]
			}
			if len(parts) > 2 {
				ep.HostIfname = parts[2]
			}
			ctx.LocalPods[netip.MustParseAddr(ipS)] = ep
		}
		for _, h := range hostIPs {
			ctx.HostIPs[netip.MustParseAddr(h)] = true
		}
		if len(viaNF) > 0 {
			set := map[netip.Addr]bool{}
			for _, v := range viaNF {
				set[netip.MustParseAddr(v)] = true
			}
			ctx.ViaNetfilter = func(f phantom.Flow) bool { return set[f.Remote.Addr()] }
		}
		res, err := phantom.Plan(m, flows, ctx)
		check(err)
		if *noReserve {
			res.Reservations, res.ConntrackReservations = nil, nil
		}
		fmt.Printf("migration id %d\n", m.ID)
		for _, r := range res.Rules {
			fmt.Println("rule  ", r)
		}
		for _, a := range res.Attachments {
			fmt.Println("attach", a)
		}
		for _, r := range res.Reservations {
			ns := r.Netns
			if ns == "" {
				ns = "host"
			}
			fmt.Printf("reserve port %d in %s\n", r.Port, ns)
		}
		for _, w := range res.ConntrackReservations {
			fmt.Println("reserve conntrack", w)
		}
		for _, f := range res.Unsupported {
			fmt.Println("UNSUPPORTED", f)
		}
		switch {
		case *apply:
			check(t.Apply(res))
		case *revert:
			check(t.Revert(res))
		}
	case "clear-pending":
		rs, err := t.Rules()
		check(err)
		var sel []phantom.Rule
		for _, r := range rs {
			if r.Owner == uint32(*id) || *id == 0 {
				sel = append(sel, r.Rule)
			}
		}
		check(t.SetFlags(0, phantom.FlagPending, sel...))
	case "remove":
		n, err := t.DeleteOwner(uint32(*id))
		check(err)
		fmt.Printf("removed %d rules\n", n)
	case "rules":
		rs, err := t.Rules()
		check(err)
		for _, r := range rs {
			fmt.Printf("%v packets=%d idle=%s\n", r.Rule, r.Packets, r.Idle.Round(1e9))
		}
	case "stats":
		s, err := t.Stats()
		check(err)
		printJSON(s)
	case "attachments":
		as, err := t.Attachments()
		check(err)
		for _, a := range as {
			fmt.Printf("%s %s %s %s legacy=%v ifindex=%d link=%d\n", a.Netns, a.Ifname, a.Kind, a.Dir, a.Legacy, a.Ifindex, a.LinkID)
		}
	case "enable", "disable":
		check(t.SetEnabled(cmd == "enable"))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}

func printJSON(v any) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	check(e.Encode(v))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func joinPorts(ports []uint16) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(int(p))
	}
	return strings.Join(s, ",")
}

func parsePorts(list string) []uint16 {
	var ports []uint16
	for _, f := range strings.Split(list, ",") {
		p, err := strconv.ParseUint(strings.TrimSpace(f), 10, 16)
		check(err)
		ports = append(ports, uint16(p))
	}
	return ports
}

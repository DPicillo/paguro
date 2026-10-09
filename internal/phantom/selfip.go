// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Self-IP fix-up inside the migrated pod.
//
// The restored process still believes it has the OLD address (it may have
// read POD_IP at start). Two consequences that the 5-tuple datapath does not
// cover, because they concern NEW connections:
//
//  1. A listener bound to OLD:port specifically (not 0.0.0.0) is restored as
//     such; new connections arrive for NEW:port (EndpointSlice, kubelet
//     probes) and would be answered with RST.
//  2. A new outbound connection explicitly bound to OLD leaves with a source
//     the network cannot route back (and Cilium's source check drops).
//
// A small nftables table in the pod's network namespace (the same mechanism
// as Paguro's RST shield) rewrites only connection-opening SYNs:
// NEW:port -> OLD:port for OLD-bound listeners (DNAT) and OLD -> NEW for new
// outbound connections (SNAT). Restored flows are never touched: their
// packets are not SYNs and are translated by xl_pod_in before netfilter.

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

const selfIPTable = "paguro_phantom_selfip"

// Runner executes a program (replaceable in tests / for nsenter wrappers).
type Runner func(stdin string, name string, args ...string) (string, error)

// ExecRunner runs the command directly.
func ExecRunner(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// SelfIPRuleset renders the nftables script (one atomic transaction).
func SelfIPRuleset(oldIP, newIP netip.Addr, listenerPorts []uint16) (string, error) {
	if oldIP.Is4() != newIP.Is4() {
		return "", fmt.Errorf("phantom: selfip: mixed families")
	}
	fam := "ip"
	if !oldIP.Is4() {
		fam = "ip6"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\nflush table inet %s\ntable inet %s {\n", selfIPTable, selfIPTable, selfIPTable)
	if len(listenerPorts) > 0 {
		ports := make([]string, 0, len(listenerPorts))
		for _, p := range listenerPorts {
			ports = append(ports, fmt.Sprint(p))
		}
		fmt.Fprintf(&b, "\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
		fmt.Fprintf(&b, "\t\t%s daddr %s tcp dport { %s } tcp flags & (syn|ack) == syn counter dnat %s to %s\n", fam, newIP, strings.Join(ports, ", "), fam, oldIP)
		fmt.Fprintf(&b, "\t}\n")
	}
	fmt.Fprintf(&b, "\tchain post {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "\t\t%s saddr %s tcp flags & (syn|ack) == syn counter snat %s to %s\n", fam, oldIP, fam, newIP)
	fmt.Fprintf(&b, "\t}\n}\n")
	return b.String(), nil
}

// InstallSelfIPFixup installs (or atomically replaces) the table in the pod
// network namespace. listenerPorts are the TCP ports with a listener bound
// to OLD specifically (HarvestOldBoundListeners).
func InstallSelfIPFixup(run Runner, netnsPath string, oldIP, newIP netip.Addr, listenerPorts []uint16) error {
	if run == nil {
		run = ExecRunner
	}
	rs, err := SelfIPRuleset(oldIP, newIP, listenerPorts)
	if err != nil {
		return err
	}
	_, err = run(rs, "nsenter", "--net="+netnsPath, "nft", "-f", "-")
	return err
}

// RemoveSelfIPFixup removes the table; a missing table is not an error.
func RemoveSelfIPFixup(run Runner, netnsPath string) error {
	if run == nil {
		run = ExecRunner
	}
	out, err := run("", "nsenter", "--net="+netnsPath, "nft", "delete", "table", "inet", selfIPTable)
	if err != nil && (strings.Contains(out, "No such file") || strings.Contains(out, "does not exist")) {
		return nil
	}
	return err
}

// HarvestOldBoundListeners returns the TCP ports listening on oldIP
// specifically (not on a wildcard address) in a pod network namespace.
func HarvestOldBoundListeners(netnsPath string, oldIP netip.Addr) ([]uint16, error) {
	tcp, _, err := sockDiag(netnsPath, oldIP)
	if err != nil {
		return nil, err
	}
	seen := map[uint16]bool{}
	for _, s := range tcp {
		if s.State != tcpListen {
			continue
		}
		a, ok := netip.AddrFromSlice(s.ID.Source)
		if ok && a.Unmap() == oldIP && !net.IP(s.ID.Source).IsUnspecified() {
			seen[s.ID.SourcePort] = true
		}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

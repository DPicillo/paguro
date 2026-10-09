// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestSteerDiff(t *testing.T) {
	a := Tuple{TCP, ap("192.168.78.222:40001"), ap("192.168.93.41:25565")}
	b := Tuple{TCP, ap("192.168.83.93:40002"), ap("192.168.93.41:25565")}
	c := Tuple{UDP, ap("192.168.83.93:40002"), ap("192.168.93.41:19132")}
	add, del := steerDiff([]Tuple{a, b}, []Tuple{b, c, c})
	if !slices.Equal(add, []Tuple{c}) || !slices.Equal(del, []Tuple{a}) {
		t.Errorf("add %v del %v", add, del)
	}
	if add, del := steerDiff(nil, nil); add != nil || del != nil {
		t.Errorf("nothing to do: add %v del %v", add, del)
	}
}

// A rule reads back as the tuple it was made for; rules of others do not
// count.
func TestSteerRuleRoundTrip(t *testing.T) {
	for _, tu := range []Tuple{
		{TCP, ap("192.168.78.222:40001"), ap("192.168.93.41:25565")},
		{UDP, ap("[fd00::2]:5000"), ap("[fd00::41]:19132")},
	} {
		r := steerRule(tu)
		if got, ok := steerTupleOf(*r); !ok || got != tu {
			t.Errorf("%v: read back %v ok=%v", tu, got, ok)
		}
	}
	other := steerRule(Tuple{TCP, ap("10.0.0.1:1"), ap("10.0.0.2:2")})
	other.Priority = 512
	if _, ok := steerTupleOf(*other); ok {
		t.Error("a rule with another priority counts as Paguro's")
	}
	wide := steerRule(Tuple{TCP, ap("10.0.0.1:1"), ap("10.0.0.2:2")})
	wide.Src = &net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(24, 32)}
	if _, ok := steerTupleOf(*wide); ok {
		t.Error("a rule for a prefix counts as a flow's")
	}
}

// The kernel routes a flow before the NAT of POSTROUTING and after the one
// of PREROUTING: the tuple of the steering rule comes from conntrack.
func TestRoutingTuples(t *testing.T) {
	old := ap("192.168.93.41:25565")
	pod := Tuple{TCP, ap("192.168.83.93:40002"), old}       // pod -> ClusterIP, DNAT'ed to OLD
	nodePort := Tuple{TCP, ap("192.168.78.222:51000"), old} // entry node, masqueraded
	host := Tuple{TCP, ap("192.168.78.222:40001"), old}     // host socket connected to OLD
	lone := Tuple{UDP, ap("192.168.78.222:5000"), ap("192.168.93.41:19132")}
	vip := ap("10.96.0.10:25565")
	entries := []ctPair{
		// pod:40002 -> VIP:25565, reply OLD -> pod:40002
		{Tuple{TCP, ap("192.168.83.93:40002"), vip}, pod.Reverse()},
		// client:61000 -> node:30717, reply OLD -> node:51000
		{Tuple{TCP, ap("203.0.113.7:61000"), ap("192.168.78.222:30717")}, nodePort.Reverse()},
		{host, host.Reverse()},
		{Tuple{TCP, ap("10.1.1.1:1"), ap("10.1.1.2:2")}, Tuple{TCP, ap("10.1.1.2:2"), ap("10.1.1.1:1")}},
	}
	got := originals([]Tuple{pod, nodePort, host, lone}, entries)
	want := map[Tuple]Tuple{
		pod:      {TCP, ap("192.168.83.93:40002"), vip},
		nodePort: {TCP, ap("203.0.113.7:61000"), ap("192.168.78.222:30717")},
		host:     host,
	}
	if !maps.Equal(got, want) {
		t.Errorf("original tuples\n got %v\nwant %v", got, want)
	}
	// The routing tuple: the source before SNAT, the destination after DNAT.
	routing := map[Tuple]Tuple{}
	for t, o := range got {
		routing[t] = Tuple{t.Proto, o.Src, t.Dst}
	}
	if r := routing[nodePort]; r != (Tuple{TCP, ap("203.0.113.7:61000"), old}) || routing[pod] != pod {
		t.Errorf("routing tuples %v", routing)
	}
}

// The old address goes to another pod on another node (IP reuse, here the
// AWS VPC CNI after its cooldown) while a translated connection to it is
// alive. The translated connection goes on to the migrated pod, a new
// connection to the old address reaches its new owner. Node C has a host
// client (host scope, the programs on its uplink); the "VPC" is one L2
// segment on which every address is on-link, as on EKS.
func TestSteeringLeavesARecycledOldAddressAlone(t *testing.T) {
	needRoot(t)
	e := newNsEnv(t)
	vpc, c, mig, owner := e.ns("sv"), e.ns("sc"), e.ns("sm"), e.ns("so")
	e.in(vpc, "ip", "link", "add", "br0", "type", "bridge")
	e.in(vpc, "ip", "link", "set", "br0", "up")
	for _, n := range []struct{ ns, br, ip string }{{c, "vc", "10.80.0.2/24"}, {mig, "vm", "10.80.0.60/24"}, {owner, "vo", ""}} {
		e.veth(n.ns, "eth0", vpc, n.br)
		e.in(vpc, "ip", "link", "set", n.br, "master", "br0")
		if n.ip != "" {
			e.in(n.ns, "ip", "addr", "add", n.ip, "dev", "eth0")
		}
	}
	e.in(c, "sysctl", "-qw", "net.ipv4.ip_forward=1") // bpf_fib_lookup on the uplink
	// The migrated pod's node does not forward what is not its own (an ENI
	// with the source/destination check; new namespaces inherit the host's
	// IPv4 forwarding).
	e.in(mig, "sysctl", "-qw", "net.ipv4.ip_forward=0")
	old, new := netip.MustParseAddr("10.80.0.50"), netip.MustParseAddr("10.80.0.60")
	cIP := netip.MustParseAddr("10.80.0.2")

	// Servers: they greet with their name, then echo.
	serve := func(ns, name string) {
		l, _ := listenIn(t, e.path(ns), "tcp4", "0.0.0.0:25565")
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				s, err := l.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = s.Write([]byte(name)); _, _ = io.Copy(s, s) }()
			}
		}()
	}
	serve(mig, "mig")
	serve(owner, "own")
	greeting := func(local string, timeout time.Duration) (net.Conn, string, error) {
		conn, err := dialIn(e.path(c), "tcp4", local, netip.AddrPortFrom(old, 25565).String(), timeout)
		if err != nil {
			return nil, "", err
		}
		b := make([]byte, 3)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, b); err != nil {
			conn.Close()
			return nil, "", err
		}
		_ = conn.SetReadDeadline(time.Time{})
		return conn, string(b), nil
	}

	// Node C translates two host flows to OLD:25565 (ports 40001, 40003).
	tr, _ := newTestTranslator(t)
	if err := tr.Attach(Attachment{Netns: e.path(c), Ifname: "eth0", Kind: KindHostDevice}); err != nil {
		t.Fatal(err)
	}
	flows := []Flow{
		{Proto: TCP, Local: netip.AddrPortFrom(old, 25565), Remote: netip.AddrPortFrom(cIP, 40001), Server: true},
		{Proto: TCP, Local: netip.AddrPortFrom(old, 25565), Remote: netip.AddrPortFrom(cIP, 40003), Server: true},
	}
	res, err := Plan(Migration{ID: 5, OldIP: old, NewIP: new}, flows,
		NodeContext{HostIPs: map[netip.Addr]bool{cIP: true}, HostDevices: []string{"eth0"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Upsert(res.Rules...); err != nil {
		t.Fatal(err)
	}
	// As Apply would: no new connection picks a translated flow's port.
	if err := ReservePorts(e.path(c), 40001, 40003); err != nil {
		t.Fatal(err)
	}
	// The old address belongs to nobody: without its route the kernel finds
	// no neighbour for it, and nothing reaches the programs. Steered: the
	// flow of port 40001 only.
	if ok, err := ensureOffLinkRoute(e.path(c), true, old, new); err != nil || !ok {
		t.Fatalf("route for the old address: ok=%v err=%v", ok, err)
	}
	steered := Tuple{TCP, netip.AddrPortFrom(cIP, 40001), netip.AddrPortFrom(old, 25565)}
	// An address without a steering route gets no rule.
	unrouted := Tuple{TCP, netip.AddrPortFrom(cIP, 40005), ap("10.80.0.77:25565")}
	steering := &Steering{}
	if err := steering.Sync(e.path(c), true, []Tuple{steered, unrouted}); err != nil {
		t.Fatal(err)
	}
	if rs := steerRules(t, e.path(c)); !slices.Equal(rs, []Tuple{steered}) {
		t.Fatalf("steering rules %v, want only %v", rs, steered)
	}
	// A host socket's flow: a rule of its own, behind the gate.
	if g, m := steerGatesAndMarks(t, e.path(c)); g != 1 || m != 1 {
		t.Fatalf("%d gate and %d mark rules, want one each", g, m)
	}
	if _, _, err := greeting("10.80.0.2:40003", time.Second); err == nil {
		t.Fatal("negative control: an unsteered flow to an address nobody has reached a server")
	}
	alive, who, err := greeting("10.80.0.2:40001", 3*time.Second)
	if err != nil || who != "mig" {
		t.Fatalf("translated flow: %q %v", who, err)
	}
	defer alive.Close()

	// OLD goes to another pod while the translated flow lives.
	e.in(owner, "ip", "addr", "add", "10.80.0.50/24", "dev", "eth0")
	conn, who, err := greeting("", 3*time.Second)
	if err != nil || who != "own" {
		t.Fatalf("new connection to the recycled address: got %q %v, want its new owner", who, err)
	}
	conn.Close()
	echo := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		b := make([]byte, 4)
		_, err := io.ReadFull(c, b)
		return err
	}
	if err := echo(alive); err != nil {
		t.Fatalf("translated flow after the address was reused: %v", err)
	}

	// Negative control: the first version's route in the main table takes
	// every connection to the address – the new owner is cut off.
	e.in(c, "ip", "route", "add", "10.80.0.50/32", "via", "10.80.0.60", "dev", "eth0", "onlink", "proto", "122", "metric", "4242")
	if conn, who, err := greeting("", time.Second); err == nil {
		conn.Close()
		t.Fatalf("negative control: with the main-table route a new connection reached %q", who)
	}
	if err := delMainRoute(old); err != nil {
		t.Fatal(err)
	}
	if err := echo(alive); err != nil {
		t.Fatalf("translated flow at the end: %v", err)
	}

	// Steering ends with the flow.
	if err := steering.Sync(e.path(c), true, nil); err != nil || len(steerRules(t, e.path(c))) != 0 {
		t.Fatalf("rules left: %v %v", steerRules(t, e.path(c)), err)
	}
	if g, m := steerGatesAndMarks(t, e.path(c)); g+m != 0 {
		t.Fatalf("%d gate and %d mark rules left", g, m)
	}
	if err := RemoveOffLinkRoute(e.path(c), old); err != nil || ours(t, e.path(c), old) {
		t.Fatalf("route not removed: %v", err)
	}
}

// steerRules lists Paguro's steering rules in a namespace.
func steerRules(t *testing.T, netnsPath string) []Tuple {
	t.Helper()
	var out []Tuple
	err := inNetns(netnsPath, func() error {
		rules, err := netlink.RuleListFiltered(netlink.FAMILY_V4, &netlink.Rule{Table: SteerTable}, netlink.RT_FILTER_TABLE)
		for _, r := range rules {
			if tu, ok := steerTupleOf(r); ok {
				out = append(out, tu)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// steerGatesAndMarks counts Paguro's gate and mark rules (IPv4) in a
// namespace.
func steerGatesAndMarks(t *testing.T, netnsPath string) (gates, marks int) {
	t.Helper()
	err := inNetns(netnsPath, func() error {
		st, err := readSteering(false)
		gates, marks = len(st.gates[netlink.FAMILY_V4]), len(st.marks[netlink.FAMILY_V4])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return gates, marks
}

// The nftables table: one set element per forwarded flow and family, the
// mark set before routing and cleared after it.
func TestSteerRuleset(t *testing.T) {
	a := Tuple{TCP, ap("10.81.0.2:41000"), ap("10.80.0.50:25565")}
	b := Tuple{UDP, ap("[fd00:81::2]:5000"), ap("[fd00:80::50]:19132")}
	mapped := Tuple{TCP, ap("[::ffff:10.81.0.3]:41001"), ap("[::ffff:10.80.0.50]:25565")}
	rs := steerRuleset(0x2000, []Tuple{a, b, a, mapped})
	for _, want := range []string{
		"add table inet paguro_phantom_steer\n",
		"type filter hook prerouting priority 100;",
		"type filter hook forward priority -300;",
		"flush set inet paguro_phantom_steer v4\n",
		"meta l4proto . ip saddr . th sport . ip daddr . th dport @v4 meta mark set meta mark | 0x00002000\n",
		"meta l4proto . ip6 saddr . th sport . ip6 daddr . th dport @v6 meta mark set meta mark & 0xffffdfff\n",
		"add element inet paguro_phantom_steer v4 { 6 . 10.81.0.2 . 41000 . 10.80.0.50 . 25565, 6 . 10.81.0.3 . 41001 . 10.80.0.50 . 25565 }\n",
		"add element inet paguro_phantom_steer v6 { 17 . fd00:81::2 . 5000 . fd00:80::50 . 19132 }\n",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, rs)
		}
	}
	if n := strings.Count(rs, "10.81.0.2 . 41000"); n != 1 {
		t.Errorf("flow listed %d times", n)
	}
	if rs := steerRuleset(0x2000, nil); strings.Contains(rs, "add element") {
		t.Errorf("elements without flows:\n%s", rs)
	}
}

// Flows from the namespace's own addresses are local sockets' flows.
func TestSplitLocal(t *testing.T) {
	host := Tuple{TCP, ap("10.80.0.2:40001"), ap("10.80.0.50:25565")}
	pod := Tuple{TCP, ap("10.81.0.2:41000"), ap("10.80.0.50:25565")}
	own, fwd := splitLocal([]Tuple{host, pod}, map[netip.Addr]bool{netip.MustParseAddr("10.80.0.2"): true})
	if !slices.Equal(own, []Tuple{host}) || !slices.Equal(fwd, []Tuple{pod}) {
		t.Errorf("own %v fwd %v", own, fwd)
	}
}

// The gate keeps forwarded route lookups off the per-flow rules; a mark
// selects the table for them. Local lookups still walk the per-flow rules.
// Both families.
func TestSteerGate(t *testing.T) {
	needRoot(t)
	e := newNsEnv(t)
	n := e.ns("sg")
	e.in(n, "ip", "link", "add", "d0", "type", "dummy")
	e.in(n, "ip", "link", "set", "d0", "up")
	e.in(n, "ip", "addr", "add", "10.80.0.2/24", "dev", "d0")
	e.in(n, "ip", "-6", "addr", "add", "fd00:80::2/64", "dev", "d0", "nodad")
	e.in(n, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	e.in(n, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
	e.in(n, "ip", "route", "add", "10.80.0.50/32", "via", "10.80.0.60", "dev", "d0", "onlink", "table", "4242", "proto", "122")
	e.in(n, "ip", "-6", "route", "add", "fd00:80::50/128", "via", "fd00:80::60", "dev", "d0", "table", "4242", "proto", "122")
	flows := []Tuple{
		{TCP, ap("10.80.0.2:40001"), ap("10.80.0.50:25565")},       // local
		{TCP, ap("10.80.0.9:40002"), ap("10.80.0.50:25565")},       // forwarded, by its own rule
		{TCP, ap("[fd00:80::2]:40001"), ap("[fd00:80::50]:25565")}, // local
		{TCP, ap("[fd00:80::9]:40002"), ap("[fd00:80::50]:25565")}, // forwarded, by its own rule
	}
	if err := inNetns(e.path(n), func() error {
		cur, err := readSteering(true)
		if err != nil {
			return err
		}
		return syncSteerRules(cur, flows, nil, true, DefaultSteerMark)
	}); err != nil {
		t.Fatal(err)
	}
	get := func(args ...string) string {
		out, err := exec.Command("ip", append([]string{"netns", "exec", n, "ip"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	for _, f := range []struct{ fam, old, local, fwd string }{
		{"-4", "10.80.0.50", "10.80.0.2", "10.80.0.9"},
		{"-6", "fd00:80::50", "fd00:80::2", "fd00:80::9"},
	} {
		if out := get(f.fam, "route", "get", f.old, "from", f.local, "ipproto", "tcp", "sport", "40001", "dport", "25565"); !strings.Contains(out, "table 4242") {
			t.Errorf("%s: a local socket's flow is not steered by its rule:\n%s", f.fam, out)
		}
		if out := get(f.fam, "route", "get", f.old, "from", f.fwd, "iif", "d0", "ipproto", "tcp", "sport", "40002", "dport", "25565"); strings.Contains(out, "table 4242") {
			t.Errorf("%s: a forwarded lookup walked the per-flow rules:\n%s", f.fam, out)
		}
		if out := get(f.fam, "route", "get", f.old, "from", f.fwd, "iif", "d0", "mark", fmt.Sprintf("0x%x", DefaultSteerMark)); !strings.Contains(out, "table 4242") {
			t.Errorf("%s: a marked forwarded packet is not steered:\n%s", f.fam, out)
		}
		if out := get(f.fam, "route", "get", f.old, "from", f.fwd, "iif", "d0", "mark", "0x4000"); strings.Contains(out, "table 4242") {
			t.Errorf("%s: another mark steers:\n%s", f.fam, out)
		}
	}
	// Gone with the flows.
	if err := inNetns(e.path(n), func() error {
		cur, err := readSteering(true)
		if err != nil {
			return err
		}
		if err := syncSteerRules(cur, nil, nil, true, DefaultSteerMark); err != nil {
			return err
		}
		if cur, err = readSteering(true); err != nil {
			return err
		}
		if len(cur.flows)+len(cur.gates[netlink.FAMILY_V4])+len(cur.gates[netlink.FAMILY_V6])+
			len(cur.marks[netlink.FAMILY_V4])+len(cur.marks[netlink.FAMILY_V6]) != 0 {
			return fmt.Errorf("left: %+v", cur)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Many forwarded connections – a pod behind node C talks to the migrated
// server through it, as through a ClusterIP – are steered by one rule, not
// one each: the per-packet cost of the node's routing does not grow with
// them. Every one of them reaches the migrated server; after the old
// address went to another pod, a new connection reaches its new owner.
// Without nftables they fall back to a rule each.
func TestSteeringManyForwardedFlows(t *testing.T) {
	needRoot(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	const flows = 200
	e := newNsEnv(t)
	vpc, c, pod, mig, owner := e.ns("fv"), e.ns("fc"), e.ns("fp"), e.ns("fm"), e.ns("fo")
	e.in(vpc, "ip", "link", "add", "br0", "type", "bridge")
	e.in(vpc, "ip", "link", "set", "br0", "up")
	for _, n := range []struct{ ns, br, ip string }{{c, "vc", "10.80.0.2/24"}, {mig, "vm", "10.80.0.60/24"}, {owner, "vo", ""}} {
		e.veth(n.ns, "eth0", vpc, n.br)
		e.in(vpc, "ip", "link", "set", n.br, "master", "br0")
		if n.ip != "" {
			e.in(n.ns, "ip", "addr", "add", n.ip, "dev", "eth0")
		}
	}
	// The pod on node C.
	e.veth(pod, "eth0", c, "vp")
	e.in(pod, "ip", "addr", "add", "10.81.0.2/24", "dev", "eth0")
	e.in(pod, "ip", "route", "add", "default", "via", "10.81.0.1")
	e.in(c, "ip", "addr", "add", "10.81.0.1/24", "dev", "vp")
	e.in(c, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	e.in(mig, "sysctl", "-qw", "net.ipv4.ip_forward=0")
	for _, n := range []string{mig, owner} {
		e.in(n, "ip", "route", "add", "10.81.0.0/24", "via", "10.80.0.2", "onlink", "dev", "eth0")
	}
	old, new := netip.MustParseAddr("10.80.0.50"), netip.MustParseAddr("10.80.0.60")
	podIP, cIP := netip.MustParseAddr("10.81.0.2"), netip.MustParseAddr("10.80.0.2")

	serve := func(ns, name string) {
		l, _ := listenIn(t, e.path(ns), "tcp4", "0.0.0.0:25565")
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				s, err := l.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = s.Write([]byte(name)); _, _ = io.Copy(s, s) }()
			}
		}()
	}
	serve(mig, "mig")
	serve(owner, "own")
	greeting := func(from, local string, timeout time.Duration) (net.Conn, string, error) {
		conn, err := dialIn(e.path(from), "tcp4", local, netip.AddrPortFrom(old, 25565).String(), timeout)
		if err != nil {
			return nil, "", err
		}
		b := make([]byte, 3)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, b); err != nil {
			conn.Close()
			return nil, "", err
		}
		_ = conn.SetReadDeadline(time.Time{})
		return conn, string(b), nil
	}
	echo := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		b := make([]byte, 4)
		_, err := io.ReadFull(c, b)
		return err
	}

	// Node C translates the pod's flows (ports 41000…) as it does behind a
	// ClusterIP (host scope), and one of its own sockets' (port 40001).
	tr, _ := newTestTranslator(t)
	if err := tr.Attach(Attachment{Netns: e.path(c), Ifname: "eth0", Kind: KindHostDevice}); err != nil {
		t.Fatal(err)
	}
	var fl []Flow
	var ports []uint16
	for i := range flows {
		p := uint16(41000 + i)
		ports = append(ports, p)
		fl = append(fl, Flow{Proto: TCP, Local: netip.AddrPortFrom(old, 25565), Remote: netip.AddrPortFrom(podIP, p), Server: true})
	}
	fl = append(fl, Flow{Proto: TCP, Local: netip.AddrPortFrom(old, 25565), Remote: netip.AddrPortFrom(cIP, 40001), Server: true})
	res, err := Plan(Migration{ID: 6, OldIP: old, NewIP: new}, fl, NodeContext{
		HostIPs:      map[netip.Addr]bool{cIP: true},
		LocalPods:    map[netip.Addr]PodEndpoint{podIP: {Netns: e.path(pod), Ifname: "eth0", HostIfname: "vp"}},
		ViaNetfilter: func(Flow) bool { return true },
		HostDevices:  []string{"eth0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Upsert(res.Rules...); err != nil {
		t.Fatal(err)
	}
	if err := ReservePorts(e.path(pod), ports...); err != nil {
		t.Fatal(err)
	}
	if err := ReservePorts(e.path(c), 40001); err != nil {
		t.Fatal(err)
	}
	if ok, err := ensureOffLinkRoute(e.path(c), true, old, new); err != nil || !ok {
		t.Fatalf("route for the old address: ok=%v err=%v", ok, err)
	}
	var want []Tuple
	for _, p := range ports {
		want = append(want, Tuple{TCP, netip.AddrPortFrom(podIP, p), netip.AddrPortFrom(old, 25565)})
	}
	hostFlow := Tuple{TCP, netip.AddrPortFrom(cIP, 40001), netip.AddrPortFrom(old, 25565)}
	want = append(want, hostFlow)

	// Without nftables: a rule each, no gate.
	broken := &Steering{Run: func(stdin, name string, args ...string) (string, error) {
		if slices.Contains(args, "nft") || name == "nft" {
			return "", errors.New("nft: not found")
		}
		return ExecRunner(stdin, name, args...)
	}}
	if err := broken.Sync(e.path(c), true, want); err == nil || !strings.Contains(err.Error(), "a rule each") {
		t.Fatalf("a failing nft is not reported: %v", err)
	}
	if rs := steerRules(t, e.path(c)); len(rs) != flows+1 {
		t.Fatalf("fallback: %d per-flow rules, want %d", len(rs), flows+1)
	}
	if g, m := steerGatesAndMarks(t, e.path(c)); g+m != 0 {
		t.Fatalf("fallback: %d gate and %d mark rules", g, m)
	}

	steering := &Steering{}
	if err := steering.Sync(e.path(c), true, want); err != nil {
		t.Fatal(err)
	}
	if rs := steerRules(t, e.path(c)); !slices.Equal(rs, []Tuple{hostFlow}) {
		t.Fatalf("per-flow rules %v, want only the host socket's", rs)
	}
	if g, m := steerGatesAndMarks(t, e.path(c)); g != 1 || m != 1 {
		t.Fatalf("%d gate and %d mark rules, want one each", g, m)
	}
	if n := nftElements(t, c); n != flows {
		t.Fatalf("%d set elements, want %d", n, flows)
	}

	if _, _, err := greeting(pod, "10.81.0.2:40999", time.Second); err == nil {
		t.Fatal("negative control: an unsteered flow to an address nobody has reached a server")
	}
	var alive []net.Conn
	for _, p := range ports {
		conn, who, err := greeting(pod, fmt.Sprintf("10.81.0.2:%d", p), 3*time.Second)
		if err != nil || who != "mig" {
			t.Fatalf("translated flow from port %d: %q %v", p, who, err)
		}
		alive = append(alive, conn)
	}
	hostConn, who, err := greeting(c, "10.80.0.2:40001", 3*time.Second)
	if err != nil || who != "mig" {
		t.Fatalf("host socket's flow: %q %v", who, err)
	}
	alive = append(alive, hostConn)
	defer func() {
		for _, c := range alive {
			c.Close()
		}
	}()

	// OLD goes to another pod while the translated flows live.
	e.in(owner, "ip", "addr", "add", "10.80.0.50/24", "dev", "eth0")
	for _, from := range []string{pod, c} {
		conn, who, err := greeting(from, "", 3*time.Second)
		if err != nil || who != "own" {
			t.Fatalf("new connection to the recycled address from %s: got %q %v, want its new owner", from, who, err)
		}
		conn.Close()
	}
	for i, conn := range alive {
		if err := echo(conn); err != nil {
			t.Fatalf("translated flow %d after the address was reused: %v", i, err)
		}
	}
	// Written again unchanged: the table is not touched.
	if err := steering.Sync(e.path(c), true, want); err != nil {
		t.Fatal(err)
	}
	// Conntrack not readable: the steering in place stays, new flows are
	// added (here one forwarded, one local, and half of the others again).
	extraFwd := Tuple{TCP, netip.AddrPortFrom(podIP, 42000), netip.AddrPortFrom(old, 25565)}
	extraLocal := Tuple{TCP, netip.AddrPortFrom(cIP, 40002), netip.AddrPortFrom(old, 25565)}
	if err := steering.Extend(e.path(c), true, append(slices.Clone(want[:flows/2]), extraFwd, extraLocal)); err != nil {
		t.Fatal(err)
	}
	if rs := steerRules(t, e.path(c)); len(rs) != 2 || !slices.Contains(rs, hostFlow) || !slices.Contains(rs, extraLocal) {
		t.Fatalf("after Extend: per-flow rules %v", rs)
	}
	if n := nftElements(t, c); n != flows+1 {
		t.Fatalf("after Extend: %d set elements, want %d", n, flows+1)
	}
	for i, conn := range alive {
		if err := echo(conn); err != nil {
			t.Fatalf("translated flow %d after Extend: %v", i, err)
		}
	}
	if err := steering.Sync(e.path(c), true, want); err != nil {
		t.Fatal(err)
	}
	if rs := steerRules(t, e.path(c)); !slices.Equal(rs, []Tuple{hostFlow}) || nftElements(t, c) != flows {
		t.Fatalf("Sync after Extend: rules %v, %d elements", rs, nftElements(t, c))
	}

	// Steering ends with the flows: rules, gate, mark rule, table.
	if err := steering.Sync(e.path(c), true, nil); err != nil {
		t.Fatal(err)
	}
	if g, m := steerGatesAndMarks(t, e.path(c)); len(steerRules(t, e.path(c)))+g+m != 0 {
		t.Fatalf("rules left: %v, %d gates, %d marks", steerRules(t, e.path(c)), g, m)
	}
	if out, err := exec.Command("ip", "netns", "exec", c, "nft", "list", "table", "inet", steerNftTable).CombinedOutput(); err == nil {
		t.Fatalf("table left:\n%s", out)
	}
}

// nftElements counts the elements of the IPv4 steering set in a namespace.
func nftElements(t *testing.T, ns string) int {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", ns, "nft", "list", "set", "inet", steerNftTable, "v4").CombinedOutput()
	if err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	return strings.Count(string(out), ". 25565")
}

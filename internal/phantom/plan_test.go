// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

var (
	oldIP  = netip.MustParseAddr("10.244.2.10")
	newIP  = netip.MustParseAddr("10.244.3.20")
	peerIP = netip.MustParseAddr("10.244.1.10")
	hostA  = netip.MustParseAddr("192.168.50.1")
	hostT  = netip.MustParseAddr("192.168.50.3")
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func findRule(t *testing.T, rs []Rule, s Scope, d Direction, match Tuple) Rule {
	t.Helper()
	for _, r := range rs {
		if r.Scope == s && r.Dir == d && r.Match == match {
			return r
		}
	}
	t.Fatalf("no %d/%d rule matching %v in %v", s, d, match, rs)
	return Rule{}
}

func TestPlanTargetAndPodPeer(t *testing.T) {
	m := Migration{ID: 7, OldIP: oldIP, NewIP: newIP}
	flows := []Flow{{Proto: TCP, Local: ap("10.244.2.10:7000"), Remote: ap("10.244.1.10:40000")}}

	// Target node.
	res, err := Plan(m, flows, NodeContext{IsTarget: true, Pending: true,
		Migrated: PodEndpoint{Netns: "/run/netns/new", Ifname: "eth0", HostIfname: "lxc1"}})
	if err != nil {
		t.Fatal(err)
	}
	out := findRule(t, res.Rules, ScopePod, Out, Tuple{TCP, ap("10.244.2.10:7000"), ap("10.244.1.10:40000")})
	if out.Rewrite != (Tuple{TCP, ap("10.244.3.20:7000"), ap("10.244.1.10:40000")}) || out.Owner != 7 {
		t.Errorf("target out rule wrong: %v", out)
	}
	in := findRule(t, res.Rules, ScopePod, In, Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.3.20:7000")})
	if in.Rewrite != (Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.2.10:7000")}) || in.Flags&FlagPending == 0 {
		t.Errorf("target in rule wrong: %v", in)
	}
	if len(res.PendingRules()) != 1 {
		t.Errorf("want 1 pending rule, got %v", res.PendingRules())
	}
	if len(res.Attachments) != 1 || res.Attachments[0] != (Attachment{Netns: "/run/netns/new", Ifname: "eth0", Kind: KindPod}) {
		t.Errorf("target attachments: %v", res.Attachments)
	}
	// The wire tuple whose stale conntrack entries the target removes.
	if len(res.Wire) != 1 || res.Wire[0] != (Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.3.20:7000")}) {
		t.Errorf("target wire tuples: %v", res.Wire)
	}

	// Peer node with the client pod.
	res, err = Plan(m, flows, NodeContext{LocalPods: map[netip.Addr]PodEndpoint{peerIP: {Netns: "/run/netns/peer", Ifname: "eth0"}}})
	if err != nil {
		t.Fatal(err)
	}
	out = findRule(t, res.Rules, ScopePod, Out, Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.2.10:7000")})
	if out.Rewrite.Dst != ap("10.244.3.20:7000") || out.Rewrite.Src != ap("10.244.1.10:40000") {
		t.Errorf("peer out rule wrong: %v", out)
	}
	in = findRule(t, res.Rules, ScopePod, In, Tuple{TCP, ap("10.244.3.20:7000"), ap("10.244.1.10:40000")})
	if in.Rewrite.Src != ap("10.244.2.10:7000") || in.Flags != 0 {
		t.Errorf("peer in rule wrong: %v", in)
	}

	// A node that has neither the peer nor the pod installs nothing.
	res, err = Plan(m, flows, NodeContext{LocalPods: map[netip.Addr]PodEndpoint{}, HostIPs: map[netip.Addr]bool{hostA: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 0 || len(res.Attachments) != 0 || len(res.Wire) != 0 {
		t.Errorf("uninvolved node got %v / %v / %v", res.Rules, res.Attachments, res.Wire)
	}
}

func TestPlanHostScope(t *testing.T) {
	m := Migration{ID: 1, OldIP: oldIP, NewIP: newIP, NewNodeIP: hostT}
	flows := []Flow{
		{Proto: TCP, Local: ap("10.244.2.10:7001"), Remote: ap("192.168.50.1:41000")}, // host client / NodePort SNAT on A
		{Proto: TCP, Local: ap("10.244.2.10:7002"), Remote: ap("192.168.50.3:42000")}, // host client on the target node
		{Proto: TCP, Local: ap("10.244.2.10:7004"), Remote: ap("10.244.1.11:43000")},  // pod behind kube-proxy DNAT
	}
	viaNF := func(f Flow) bool { return f.Remote.Addr() == netip.MustParseAddr("10.244.1.11") }

	res, err := Plan(m, flows, NodeContext{
		HostIPs:       map[netip.Addr]bool{hostA: true},
		LocalPods:     map[netip.Addr]PodEndpoint{netip.MustParseAddr("10.244.1.11"): {Netns: "/x", Ifname: "eth0"}},
		HostDevices:   []string{"eth0", "cilium_vxlan"},
		ViaNetfilter:  viaNF,
		TunnelRewrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := findRule(t, res.Rules, ScopeHost, Out, Tuple{TCP, ap("192.168.50.1:41000"), ap("10.244.2.10:7001")})
	if out.Flags&FlagReroute == 0 || out.Flags&FlagTunnel == 0 || out.TunnelRemote != hostT {
		t.Errorf("host out flags: %v", out)
	}
	findRule(t, res.Rules, ScopeHost, In, Tuple{TCP, ap("10.244.3.20:7001"), ap("192.168.50.1:41000")})
	findRule(t, res.Rules, ScopeHost, Out, Tuple{TCP, ap("10.244.1.11:43000"), ap("10.244.2.10:7004")})
	for _, r := range res.Rules {
		if r.Scope == ScopePod {
			t.Errorf("DNAT'ed pod peer must get host-scope rules only, got %v", r)
		}
	}
	if len(res.Attachments) != 2 {
		t.Errorf("want 2 host device attachments, got %v", res.Attachments)
	}

	// Target node: its own host client gets FlagLocal and the hostlocal hook.
	res, err = Plan(m, flows, NodeContext{IsTarget: true, HostIPs: map[netip.Addr]bool{hostT: true},
		Migrated: PodEndpoint{Netns: "/new", Ifname: "eth0", HostIfname: "lxc9"}, HostDevices: []string{"eth0"}})
	if err != nil {
		t.Fatal(err)
	}
	in := findRule(t, res.Rules, ScopeHost, In, Tuple{TCP, ap("10.244.3.20:7002"), ap("192.168.50.3:42000")})
	if in.Flags&FlagLocal == 0 {
		t.Errorf("target host client needs FlagLocal: %v", in)
	}
	found := false
	for _, a := range res.Attachments {
		if a == (Attachment{Ifname: "lxc9", Kind: KindHostLocal}) {
			found = true
		}
	}
	if !found {
		t.Errorf("missing hostlocal attachment: %v", res.Attachments)
	}

	// Target node, local pod behind a DNAT: the replies' programs go on
	// the migrated pod's veth – re-injected into the host when the CNI
	// verifies source addresses on pod ports.
	local := NodeContext{IsTarget: true, HostIPs: map[netip.Addr]bool{hostT: true},
		LocalPods:    map[netip.Addr]PodEndpoint{netip.MustParseAddr("10.244.1.11"): {Netns: "/x", Ifname: "eth0"}},
		ViaNetfilter: viaNF, Migrated: PodEndpoint{Netns: "/new", Ifname: "eth0", HostIfname: "lxc9"}}
	for _, verify := range []bool{false, true} {
		local.SourceVerify = verify
		res, err = Plan(m, flows[2:], local)
		if err != nil {
			t.Fatal(err)
		}
		in := findRule(t, res.Rules, ScopeHost, In, Tuple{TCP, ap("10.244.3.20:7004"), ap("10.244.1.11:43000")})
		want := Attachment{Ifname: "lxc9", Kind: KindHostDevice}
		if verify {
			want.Kind = KindHostLocal
		}
		if !slices.Contains(res.Attachments, want) || (in.Flags&FlagLocal != 0) != verify {
			t.Errorf("SourceVerify=%v: attachments %v, in flags %v", verify, res.Attachments, in.Flags)
		}
	}
}

func TestPlanWireAndUnsupported(t *testing.T) {
	m := Migration{OldIP: oldIP, NewIP: newIP}
	flows := []Flow{
		// The pod connected to a ClusterIP; the old node DNAT'ed to a backend.
		{Proto: TCP, Local: ap("10.244.2.10:50000"), Remote: ap("10.96.0.10:80"), Wire: ap("10.244.1.10:8080")},
		{Proto: TCP, Local: ap("10.244.2.10:50001"), Remote: ap("1.2.3.4:443"), Class: ClassExternalSNAT},
	}
	res, err := Plan(m, flows, NodeContext{IsTarget: true, Migrated: PodEndpoint{Netns: "/n", Ifname: "eth0"},
		LocalPods: map[netip.Addr]PodEndpoint{}})
	if err != nil {
		t.Fatal(err)
	}
	out := findRule(t, res.Rules, ScopePod, Out, Tuple{TCP, ap("10.244.2.10:50000"), ap("10.96.0.10:80")})
	if out.Rewrite != (Tuple{TCP, ap("10.244.3.20:50000"), ap("10.244.1.10:8080")}) {
		t.Errorf("service flow must go to the backend the old node chose: %v", out)
	}
	in := findRule(t, res.Rules, ScopePod, In, Tuple{TCP, ap("10.244.1.10:8080"), ap("10.244.3.20:50000")})
	if in.Rewrite != (Tuple{TCP, ap("10.96.0.10:80"), ap("10.244.2.10:50000")}) {
		t.Errorf("service reply must come from the ClusterIP: %v", in)
	}
	if len(res.Unsupported) != 1 || res.Unsupported[0].Remote != ap("1.2.3.4:443") {
		t.Errorf("unsupported: %v", res.Unsupported)
	}

	// Backend node: the backend saw the pod directly (DNAT only).
	res, err = Plan(m, flows[:1], NodeContext{LocalPods: map[netip.Addr]PodEndpoint{peerIP: {Netns: "/b", Ifname: "eth0"}}})
	if err != nil {
		t.Fatal(err)
	}
	findRule(t, res.Rules, ScopePod, Out, Tuple{TCP, ap("10.244.1.10:8080"), ap("10.244.2.10:50000")})
}

func TestPlanPeerItselfMigrated(t *testing.T) {
	// B (old 10.244.1.10) migrated earlier to 10.244.4.40; now A migrates.
	bOld, bNew := peerIP, netip.MustParseAddr("10.244.4.40")
	m := Migration{OldIP: oldIP, NewIP: newIP}
	flows := []Flow{{Proto: TCP, Local: ap("10.244.2.10:7000"), Remote: ap("10.244.1.10:40000")}}
	remap := func(a netip.Addr) (netip.Addr, bool) {
		if a == bOld {
			return bNew, true
		}
		return a, false
	}
	// Target of A: wire peer is B's NEW address.
	res, err := Plan(m, flows, NodeContext{IsTarget: true, Migrated: PodEndpoint{Netns: "/a", Ifname: "eth0"}, Remap: remap})
	if err != nil {
		t.Fatal(err)
	}
	out := findRule(t, res.Rules, ScopePod, Out, Tuple{TCP, ap("10.244.2.10:7000"), ap("10.244.1.10:40000")})
	if out.Rewrite != (Tuple{TCP, ap("10.244.3.20:7000"), ap("10.244.4.40:40000")}) {
		t.Errorf("A out: %v", out)
	}
	// B's node: B is known locally by its NEW address; its out rule must
	// translate both sides (B's own migration and A's).
	res, err = Plan(m, flows, NodeContext{Remap: remap,
		LocalPods: map[netip.Addr]PodEndpoint{bNew: {Netns: "/b", Ifname: "eth0"}}})
	if err != nil {
		t.Fatal(err)
	}
	out = findRule(t, res.Rules, ScopePod, Out, Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.2.10:7000")})
	if out.Rewrite != (Tuple{TCP, ap("10.244.4.40:40000"), ap("10.244.3.20:7000")}) {
		t.Errorf("B out: %v", out)
	}
	in := findRule(t, res.Rules, ScopePod, In, Tuple{TCP, ap("10.244.3.20:7000"), ap("10.244.4.40:40000")})
	if in.Rewrite != (Tuple{TCP, ap("10.244.2.10:7000"), ap("10.244.1.10:40000")}) {
		t.Errorf("B in: %v", in)
	}
}

func TestPlanErrors(t *testing.T) {
	if _, err := Plan(Migration{OldIP: oldIP}, nil, NodeContext{}); err == nil {
		t.Error("missing NewIP accepted")
	}
	if _, err := Plan(Migration{OldIP: oldIP, NewIP: netip.MustParseAddr("fd00::1")}, nil, NodeContext{}); err == nil {
		t.Error("mixed families accepted")
	}
	_, err := Plan(Migration{OldIP: oldIP, NewIP: newIP}, []Flow{{Proto: TCP, Local: ap("10.9.9.9:1"), Remote: ap("10.1.1.1:2")}}, NodeContext{})
	if err == nil {
		t.Error("foreign flow accepted")
	}
}

func TestRuleEncoding(t *testing.T) {
	r := Rule{Scope: ScopeHost, Dir: Out, Owner: 3, Flags: FlagTunnel | FlagReroute,
		TunnelRemote: hostT,
		Match:        Tuple{UDP, ap("[fd00::1]:5353"), ap("[fd00::2]:53")},
		Rewrite:      Tuple{UDP, ap("[fd00::1]:5353"), ap("[fd00::3]:53")}}
	k, err := r.key()
	if err != nil {
		t.Fatal(err)
	}
	if k.Family != 6 || k.Proto != uint8(UDP) || fromBe16(k.Dport) != 53 || k.Daddr[15] != 2 {
		t.Errorf("bad key %+v", k)
	}
	v, err := r.value()
	if err != nil {
		t.Fatal(err)
	}
	if v.TunnelRemote4 != 0xc0a83203 || v.Daddr[15] != 3 || v.Owner != 3 {
		t.Errorf("bad value %+v", v)
	}
	// Family change is rejected.
	r.Rewrite.Dst = ap("10.0.0.1:53")
	if _, err := r.value(); err == nil {
		t.Error("family change accepted")
	}
	// v4 addresses are stored in the first 4 bytes.
	r4 := Rule{Scope: ScopePod, Dir: In, Match: Tuple{TCP, ap("10.0.0.1:1"), ap("10.0.0.2:2")}, Rewrite: Tuple{TCP, ap("10.0.0.1:1"), ap("10.0.0.3:2")}}
	k4, _ := r4.key()
	if k4.Family != 4 || k4.Daddr[3] != 2 || k4.Daddr[4] != 0 || fromBe16(k4.Sport) != 1 {
		t.Errorf("bad v4 key %+v", k4)
	}
}

func TestPlanReservations(t *testing.T) {
	m := Migration{OldIP: oldIP, NewIP: newIP}
	flows := []Flow{
		{Proto: TCP, Local: ap("10.244.2.10:7000"), Remote: ap("10.244.1.10:40000"), Server: true},  // peer pod is client
		{Proto: TCP, Local: ap("10.244.2.10:51000"), Remote: ap("10.244.1.10:9000")},                // migrated pod is client
		{Proto: TCP, Local: ap("10.244.2.10:7005"), Remote: ap("192.168.50.1:33000"), Server: true}, // NodePort SNAT / host client
	}
	tgt, err := Plan(m, flows, NodeContext{IsTarget: true, Migrated: PodEndpoint{Netns: "/new", Ifname: "eth0"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Reservations) != 1 || tgt.Reservations[0] != (Reservation{Netns: "/new", Port: 51000}) {
		t.Errorf("target reservations %v", tgt.Reservations)
	}
	peer, err := Plan(m, flows, NodeContext{
		LocalPods: map[netip.Addr]PodEndpoint{peerIP: {Netns: "/peer", Ifname: "eth0"}},
		HostIPs:   map[netip.Addr]bool{hostA: true}, HostDevices: []string{"eth0"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[Reservation]bool{{Netns: "/peer", Port: 40000}: true, {Netns: "", Port: 33000}: true}
	if len(peer.Reservations) != 2 || !want[peer.Reservations[0]] || !want[peer.Reservations[1]] {
		t.Errorf("peer reservations %v", peer.Reservations)
	}
	if len(peer.ConntrackReservations) != 1 || peer.ConntrackReservations[0] != (Tuple{TCP, ap("192.168.50.1:33000"), ap("10.244.3.20:7005")}) {
		t.Errorf("conntrack reservations %v", peer.ConntrackReservations)
	}
}

func TestPortList(t *testing.T) {
	set, err := parsePortList("80,8080-8082, 9000\n")
	if err != nil || len(set) != 5 || !set[8081] {
		t.Fatalf("parse: %v %v", set, err)
	}
	set[8083] = true
	set[1] = true
	if got := formatPortList(set); got != "1,80,8080-8083,9000" {
		t.Errorf("format: %q", got)
	}
	if got := formatPortList(map[uint16]bool{}); got != "" {
		t.Errorf("empty: %q", got)
	}
}

// bpffs rejects file names with '.', and interface names often have one
// (flannel.1, vxlan.calico, eth0.100).
func TestPinNamesAreDotFree(t *testing.T) {
	for _, ifname := range []string{"flannel.1", "vxlan.calico", "eth0.100", "lxc12ab", "odd:name/x%y"} {
		n := pinName("host", ifname, KindHostDevice, hookDir("egress"), 14)
		if strings.ContainsAny(n, "./") {
			t.Errorf("pin name %q contains '.' or '/'", n)
		}
		info, ok := parsePin(n)
		if !ok || info.ifname != ifname || info.ns != "host" || info.kind != KindHostDevice || info.l3off != 14 {
			t.Errorf("%q: parsed %+v ok=%v", n, info, ok)
		}
		m := legacyMarker(n, 7, "/var/run/netns/cni-1.2")
		if strings.ContainsAny(m, "./") {
			t.Errorf("legacy marker %q contains '.' or '/'", m)
		}
		if li, ok := parsePin(m); !ok || !li.legacy || li.netnsPath != "/var/run/netns/cni-1.2" || li.prio != 7 || li.ifname != ifname {
			t.Errorf("legacy %q: parsed %+v ok=%v", m, li, ok)
		}
	}
}

// A pod that came back to an address its connections still use: the rules
// are identities, and they must be there – they replace the previous
// migration's rules for the same 5-tuples.
func TestPlanIdentityReplacesOlderRules(t *testing.T) {
	m := Migration{ID: 2, OldIP: oldIP, NewIP: oldIP}
	flows := []Flow{{Proto: TCP, Local: ap("10.244.2.10:7000"), Remote: ap("10.244.1.10:40000")}}
	res, err := Plan(m, flows, NodeContext{LocalPods: map[netip.Addr]PodEndpoint{
		netip.MustParseAddr("10.244.1.10"): {Netns: "/peer", Ifname: "eth0"}}})
	if err != nil {
		t.Fatal(err)
	}
	out := findRule(t, res.Rules, ScopePod, Out, Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.2.10:7000")})
	if out.Rewrite != out.Match {
		t.Fatalf("want an identity rule, got %v", out)
	}
}

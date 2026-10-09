// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The host programs go on every device pod traffic can leave or arrive on,
// whichever routing table sends it there. Node C on EKS (AWS VPC CNI, an
// instance with several ENIs): pods with an address of a secondary ENI are
// routed out of that ENI by a rule of their own (`from <pod> lookup 2`), and
// the main table never names the ENI.
func TestHostDevicesCoverEveryRoutingTable(t *testing.T) {
	dev := func(i int, name string) netlink.Link {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: i, Name: name}}
	}
	podVeth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: 20, Name: "eni5f3a", NetNsID: 4}}
	links := map[int]netlink.Link{
		1: dev(1, "lo"), 2: dev(2, "enp39s0"), 3: dev(3, "enp40s0"), 4: dev(4, "enp41s0"),
		5: dev(5, "pod-id-link0"), 6: dev(6, "kube-ipvs0"), 20: podVeth,
	}
	cidr := func(s string) *net.IPNet { _, n, _ := net.ParseCIDR(s); return n }
	gw := net.ParseIP("192.168.64.1")
	routes := []netlink.Route{
		// main: the primary ENI
		{Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Dst: nil, Gw: gw, LinkIndex: 2},
		{Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Dst: cidr("192.168.64.0/19"), LinkIndex: 2},
		{Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Dst: cidr("192.168.72.98/32"), LinkIndex: 20},
		{Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Dst: cidr("169.254.170.23/32"), LinkIndex: 5},
		// table 2: the secondary ENI of the pods with `from <pod> lookup 2`
		{Table: 2, Type: unix.RTN_UNICAST, Dst: nil, Gw: gw, LinkIndex: 3},
		{Table: 2, Type: unix.RTN_UNICAST, Dst: cidr("192.168.64.1/32"), LinkIndex: 3},
		// table 3: an ENI ipamd attached later
		{Table: 3, Type: unix.RTN_UNICAST, Dst: cidr("0.0.0.0/0"), Gw: gw, LinkIndex: 4},
		// never: the local table, and routes that cannot carry traffic
		{Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_LOCAL, Dst: cidr("10.100.0.10/32"), LinkIndex: 6},
		{Table: 4, Type: unix.RTN_UNREACHABLE, Dst: nil, LinkIndex: 6},
	}
	old, new := netip.MustParseAddr("192.168.93.205"), netip.MustParseAddr("192.168.81.207")
	got := pickHostDevices([]netip.Addr{old, new}, []int{2}, routes, links)
	if want := []string{"enp39s0", "enp40s0", "enp41s0"}; !slices.Equal(got, want) {
		t.Errorf("devices %v, want %v", got, want)
	}

	// A route that covers an address counts in any table; the host side of
	// a pod's veth never does, nor does loopback.
	routes = []netlink.Route{
		{Table: 7, Type: unix.RTN_UNICAST, Dst: cidr("192.168.80.0/20"), LinkIndex: 4},
		{Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Dst: cidr("192.168.93.205/32"), LinkIndex: 20},
		{Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Dst: cidr("192.168.0.0/16"), LinkIndex: 1},
	}
	got = pickHostDevices([]netip.Addr{old, new}, []int{20, 1}, routes, links)
	if want := []string{"enp41s0"}; !slices.Equal(got, want) {
		t.Errorf("devices %v, want %v", got, want)
	}

	// Overlay devices count whenever they exist.
	links[30] = dev(30, "flannel.1")
	got = pickHostDevices(nil, nil, nil, links)
	if want := []string{"flannel.1"}; !slices.Equal(got, want) {
		t.Errorf("devices %v, want %v", got, want)
	}
}

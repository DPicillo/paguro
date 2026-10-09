// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The entry of a connection that is back at its old wire tuple goes – in
// either direction; entries with NAT (kube-proxy's live ones), other
// tuples and UDP stay.
func TestStaleConntrackFilter(t *testing.T) {
	wire := Tuple{TCP, ap("192.168.73.63:58056"), ap("192.168.90.95:25565")}
	f := staleFilter{want: map[Tuple]bool{wire: true, wire.Reverse(): true}}
	ct := func(proto uint8, oSrc, oDst, rSrc, rDst string, oSport, oDport, rSport, rDport uint16) *netlink.ConntrackFlow {
		return &netlink.ConntrackFlow{
			Forward: netlink.IPTuple{Protocol: proto, SrcIP: net.ParseIP(oSrc), DstIP: net.ParseIP(oDst), SrcPort: oSport, DstPort: oDport},
			Reverse: netlink.IPTuple{Protocol: proto, SrcIP: net.ParseIP(rSrc), DstIP: net.ParseIP(rDst), SrcPort: rSport, DstPort: rDport},
		}
	}
	tcp, udp := uint8(unix.IPPROTO_TCP), uint8(unix.IPPROTO_UDP)
	cases := []struct {
		name string
		c    *netlink.ConntrackFlow
		want bool
	}{
		{"peer opened it", ct(tcp, "192.168.73.63", "192.168.90.95", "192.168.90.95", "192.168.73.63", 58056, 25565, 25565, 58056), true},
		{"pod opened it", ct(tcp, "192.168.90.95", "192.168.73.63", "192.168.73.63", "192.168.90.95", 25565, 58056, 58056, 25565), true},
		{"through a ClusterIP (DNAT)", ct(tcp, "192.168.73.63", "10.100.210.102", "192.168.90.95", "192.168.73.63", 58056, 25565, 25565, 58056), false},
		{"source port rewritten (SNAT)", ct(tcp, "192.168.73.63", "192.168.90.95", "192.168.90.95", "192.168.73.63", 58056, 25565, 25565, 61000), false},
		{"another connection", ct(tcp, "192.168.73.63", "192.168.90.95", "192.168.90.95", "192.168.73.63", 58057, 25565, 25565, 58057), false},
		{"UDP", ct(udp, "192.168.73.63", "192.168.90.95", "192.168.90.95", "192.168.73.63", 58056, 25565, 25565, 58056), false},
	}
	for _, c := range cases {
		if got := f.MatchConntrackFlow(c.c); got != c.want {
			t.Errorf("%s: match = %v, want %v", c.name, got, c.want)
		}
	}
}

// Nothing to do for UDP flows or for tuples another migration holds as a
// placeholder: no netlink call at all.
func TestFlushStaleConntrackNothingToDo(t *testing.T) {
	wire := Tuple{TCP, ap("192.168.73.63:58056"), ap("192.168.90.95:25565")}
	udp := Tuple{UDP, ap("192.168.73.63:40000"), ap("192.168.90.95:28801")}
	n, err := FlushStaleConntrack("/nonexistent/netns", []Tuple{wire, udp}, []Tuple{wire.Reverse()})
	if err != nil || n != 0 {
		t.Fatalf("FlushStaleConntrack = %d, %v; want 0, nil", n, err)
	}
}

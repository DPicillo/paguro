// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
)

func udpSock(src string, dst string) *netlink.Socket {
	s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
	return &netlink.Socket{ID: netlink.SocketID{
		Source: net.IP(s.Addr().AsSlice()), SourcePort: s.Port(),
		Destination: net.IP(d.Addr().AsSlice()), DestinationPort: d.Port()}}
}

func TestUDPServerPorts(t *testing.T) {
	old := netip.MustParseAddr("192.168.90.1")
	socks := []*netlink.Socket{
		udpSock("0.0.0.0:26000", "0.0.0.0:0"),           // Xonotic: wildcard, unconnected
		udpSock("192.168.90.1:19132", "0.0.0.0:0"),      // bound to the pod IP
		udpSock("[::]:443", "[::]:0"),                   // dual-stack QUIC server
		udpSock("[::ffff:192.168.90.1]:5353", "[::]:0"), // v4-mapped pod IP
		udpSock("127.0.0.1:8125", "0.0.0.0:0"),          // loopback only
		udpSock("10.244.2.10:7000", "0.0.0.0:0"),        // an earlier IP (chained migration)
		udpSock("192.168.90.1:41000", "10.100.0.10:53"), // connected: a harvested flow
		udpSock("0.0.0.0:0", "0.0.0.0:0"),               // not bound
		udpSock("0.0.0.0:26000", "0.0.0.0:0"),           // SO_REUSEPORT twin
	}
	got := udpServerPorts(socks, old)
	if want := []uint16{443, 5353, 19132, 26000}; !slices.Equal(got, want) {
		t.Fatalf("ports %v, want %v", got, want)
	}
	if got := udpServerPorts(socks, netip.MustParseAddr("fd00::1")); !slices.Equal(got, []uint16{443, 26000}) {
		t.Fatalf("IPv6 pod: ports %v, want the wildcard sockets", got)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package ctguard

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func flow(proto uint8, os, od, rs, rd string) *netlink.ConntrackFlow {
	t := func(src, dst string) netlink.IPTuple {
		s, d := netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst)
		return netlink.IPTuple{Protocol: proto, SrcIP: net.IP(s.Addr().AsSlice()), SrcPort: s.Port(),
			DstIP: net.IP(d.Addr().AsSlice()), DstPort: d.Port()}
	}
	return &netlink.ConntrackFlow{FamilyType: unix.AF_INET, Forward: t(os, od), Reverse: t(rs, rd),
		ProtoInfo: &netlink.ProtoInfoTCP{State: tcpEstablished}}
}

// The lab's conntrack table on the NodePort entry node (k8s-c-1).
var (
	pod       = netip.MustParseAddr("10.245.215.131")
	nodePort  = flow(unix.IPPROTO_TCP, "203.0.113.24:56969", "10.42.0.52:30703", "10.245.215.131:7000", "10.245.30.192:1589")
	clusterIP = flow(unix.IPPROTO_TCP, "10.245.30.201:43122", "10.97.175.130:7000", "10.245.215.131:7000", "10.245.30.201:43122")
	direct    = flow(unix.IPPROTO_TCP, "10.245.30.200:52758", "10.245.215.131:7000", "10.245.215.131:7000", "10.245.30.200:52758")
	udp       = flow(unix.IPPROTO_UDP, "203.0.113.24:5353", "10.42.0.52:30053", "10.245.215.131:53", "10.245.30.192:999")
	other     = flow(unix.IPPROTO_TCP, "203.0.113.24:4000", "10.42.0.52:30080", "10.245.30.9:80", "10.42.0.52:4000")
)

func TestSelect(t *testing.T) {
	closing := flow(unix.IPPROTO_TCP, "203.0.113.24:50000", "10.42.0.52:30703", "10.245.215.131:7000", "10.245.30.192:2000")
	closing.ProtoInfo = &netlink.ProtoInfoTCP{State: 7} // TIME_WAIT
	// A UDP stream (refreshed to the stream timeout) is guarded, a one-shot
	// exchange is not.
	stream := flow(unix.IPPROTO_UDP, "203.0.113.24:58006", "10.42.0.52:30777", "10.245.215.131:7777", "10.245.30.192:32422")
	stream.TimeOut = 118
	udp.TimeOut = 27
	got := Select([]*netlink.ConntrackFlow{nodePort, clusterIP, direct, udp, other, closing, stream}, pod)
	if len(got) != 3 {
		t.Fatalf("selected %v, want the NodePort, the ClusterIP and the UDP stream entry (NATed entries of the pod)", got)
	}
	if !got[0].DNAT() || !got[0].SNAT() || !got[1].DNAT() || got[1].SNAT() || got[2].Proto != unix.IPPROTO_UDP {
		t.Fatalf("NAT kinds wrong: %v", got)
	}
}

func TestMissing(t *testing.T) {
	want := Select([]*netlink.ConntrackFlow{nodePort, clusterIP}, pod)
	// After Felix's flush the client's next packet created the NodePort
	// entry again – masqueraded to the node IP now that the pod is local.
	reNATed := flow(unix.IPPROTO_TCP, "203.0.113.24:56969", "10.42.0.52:30703", "10.245.215.131:7000", "10.42.0.52:41081")
	absent, rebound := Missing([]*netlink.ConntrackFlow{reNATed, direct}, want)
	if len(absent) != 1 || absent[0].OrigDst.Port() != 7000 {
		t.Errorf("absent = %v, want the ClusterIP entry", absent)
	}
	if len(rebound) != 1 || rebound[0].Want.ReplyDst != netip.MustParseAddrPort("10.245.30.192:1589") ||
		rebound[0].Found.ReplyDst != netip.MustParseAddrPort("10.42.0.52:41081") {
		t.Errorf("rebound = %v, want the NodePort entry with its original binding and the one found", rebound)
	}
	if a, r := Missing([]*netlink.ConntrackFlow{nodePort, clusterIP}, want); len(a)+len(r) != 0 {
		t.Errorf("intact table reported %v %v", a, r)
	}
}

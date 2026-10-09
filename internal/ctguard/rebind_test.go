// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package ctguard

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// The entry node's conntrack table on EKS (ip-192-168-78-222, kube-proxy
// iptables mode, MASQUERADE --random-fully), Xonotic on 192.168.90.1:26000.
var (
	xonOld   = netip.MustParseAddr("192.168.90.1")
	xonNew   = netip.MustParseAddr("192.168.93.7")
	xonPorts = []uint16{26000}
)

func udpFlow(os, od, rs, rd string, timeout uint32) *netlink.ConntrackFlow {
	f := flow(unix.IPPROTO_UDP, os, od, rs, rd)
	f.ProtoInfo = nil
	f.TimeOut = timeout
	return f
}

func TestSelectRebind(t *testing.T) {
	nlbPlayer := udpFlow("3.67.9.3:46683", "192.168.78.222:31716", "192.168.90.1:26000", "192.168.78.222:63723", 118)
	clusterIPPlayer := udpFlow("192.168.92.34:45639", "10.100.52.10:26000", "192.168.90.1:26000", "192.168.92.34:45639", 117)
	podIPClient := udpFlow("192.168.92.40:5000", "192.168.90.1:26000", "192.168.90.1:26000", "192.168.92.40:5000", 119)
	joinQuery := udpFlow("3.67.9.3:40001", "192.168.78.222:31716", "192.168.90.1:26000", "192.168.78.222:2000", 27)
	otherPort := udpFlow("3.67.9.3:46690", "192.168.78.222:31999", "192.168.90.1:27015", "192.168.78.222:2001", 118)
	tcp := flow(unix.IPPROTO_TCP, "3.67.9.3:50000", "192.168.78.222:31716", "192.168.90.1:26000", "192.168.78.222:2002")
	otherPod := udpFlow("3.67.9.3:46700", "192.168.78.222:31800", "192.168.95.5:26000", "192.168.78.222:2003", 118)
	translated := udpFlow("3.67.9.3:46710", "192.168.78.222:31716", "192.168.90.1:26000", "192.168.78.222:2004", 118)
	skip := func(e Entry) bool { return e.ReplyDst == netip.MustParseAddrPort("192.168.78.222:2004") }
	ovsZone := udpFlow("3.67.9.3:46720", "192.168.78.222:31716", "192.168.90.1:26000", "192.168.78.222:2005", 118)
	ovsZone.Zone = 65520 // Antrea's proxy: Service NAT in an OVS conntrack zone

	got := SelectRebind([]*netlink.ConntrackFlow{nlbPlayer, clusterIPPlayer, podIPClient, joinQuery, otherPort, tcp, otherPod, translated, ovsZone},
		xonOld, xonPorts, skip)
	if len(got) != 2 {
		t.Fatalf("selected %v, want the NLB player and the ClusterIP player", got)
	}
	if got[0].ReplyDst != netip.MustParseAddrPort("192.168.78.222:63723") || !got[0].SNAT() {
		t.Errorf("NLB player: %v", got[0])
	}
	if got[1].OrigSrc != netip.MustParseAddrPort("192.168.92.34:45639") || got[1].SNAT() {
		t.Errorf("ClusterIP player: %v", got[1])
	}
	if n := len(SelectRebind([]*netlink.ConntrackFlow{nlbPlayer}, xonOld, []uint16{27015}, nil)); n != 0 {
		t.Errorf("a port that is not a UDP server's selected %d entries", n)
	}
}

func TestRetarget(t *testing.T) {
	in := SelectRebind([]*netlink.ConntrackFlow{
		udpFlow("3.67.9.3:46683", "192.168.78.222:31716", "192.168.90.1:26000", "192.168.78.222:63723", 118),
	}, xonOld, xonPorts, nil)
	got := Retarget(in, xonNew)
	want := Entry{Proto: unix.IPPROTO_UDP,
		OrigSrc: netip.MustParseAddrPort("3.67.9.3:46683"), OrigDst: netip.MustParseAddrPort("192.168.78.222:31716"),
		ReplySrc: netip.MustParseAddrPort("192.168.93.7:26000"), ReplyDst: netip.MustParseAddrPort("192.168.78.222:63723")}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Retarget = %v, want %v (same client tuple and masquerade port, reply from the new IP)", got, want)
	}
	if in[0].ReplySrc.Addr() != xonOld {
		t.Error("Retarget changed its input")
	}
	if n := len(Retarget(in, netip.MustParseAddr("fd00::7"))); n != 0 {
		t.Errorf("an IPv4 entry moved to an IPv6 address: %d", n)
	}
}

// The sequence measured on EKS, as Missing sees it against the moved
// binding: the old entry, kube-proxy's delete and the client's next datagram
// NATed afresh, the moved binding in place.
func TestMissingRetargeted(t *testing.T) {
	old := udpFlow("3.67.9.3:46683", "192.168.78.222:31716", "192.168.90.1:26000", "192.168.78.222:63723", 118)
	want := Retarget(SelectRebind([]*netlink.ConntrackFlow{old}, xonOld, xonPorts, nil), xonNew)

	_, rebound := Missing([]*netlink.ConntrackFlow{old}, want)
	if len(rebound) != 1 || rebound[0].Found.ReplySrc != netip.MustParseAddrPort("192.168.90.1:26000") {
		t.Fatalf("old binding: rebound = %v, want the entry to the old IP replaced", rebound)
	}
	reNATed := udpFlow("3.67.9.3:46683", "192.168.78.222:31716", "192.168.93.7:26000", "192.168.78.222:34700", 30)
	_, rebound = Missing([]*netlink.ConntrackFlow{reNATed}, want)
	if len(rebound) != 1 || rebound[0].Found.ReplyDst.Port() != 34700 || rebound[0].Want.ReplyDst.Port() != 63723 {
		t.Fatalf("NATed afresh: rebound = %v, want port 34700 replaced by 63723", rebound)
	}
	absent, _ := Missing(nil, want)
	if len(absent) != 1 {
		t.Fatalf("deleted: absent = %v", absent)
	}
	moved := udpFlow("3.67.9.3:46683", "192.168.78.222:31716", "192.168.93.7:26000", "192.168.78.222:63723", 120)
	if a, r := Missing([]*netlink.ConntrackFlow{moved}, want); len(a)+len(r) != 0 {
		t.Fatalf("moved binding reported %v %v", a, r)
	}
}

func TestClashing(t *testing.T) {
	want := []Entry{{Proto: unix.IPPROTO_UDP,
		OrigSrc: netip.MustParseAddrPort("3.67.9.3:46683"), OrigDst: netip.MustParseAddrPort("192.168.78.222:31716"),
		ReplySrc: netip.MustParseAddrPort("192.168.93.7:26000"), ReplyDst: netip.MustParseAddrPort("192.168.78.222:63723")}}
	// The restored server wrote to the masquerade binding first.
	serverFirst := udpFlow("192.168.93.7:26000", "192.168.78.222:63723", "192.168.78.222:63723", "192.168.93.7:26000", 29)
	otherPlayer := udpFlow("3.67.9.3:46684", "192.168.78.222:31716", "192.168.93.7:26000", "192.168.78.222:40000", 118)
	tcp := flow(unix.IPPROTO_TCP, "192.168.93.7:26000", "192.168.78.222:63723", "192.168.78.222:63723", "192.168.93.7:26000")
	otherZone := udpFlow("192.168.93.7:26000", "192.168.78.222:63723", "192.168.78.222:63723", "192.168.93.7:26000", 29)
	otherZone.Zone = 65520
	got := Clashing([]*netlink.ConntrackFlow{serverFirst, otherPlayer, tcp, otherZone}, want)
	if len(got) != 1 || got[0].OrigSrc != want[0].ReplySrc || got[0].ReplySrc != want[0].ReplyDst {
		t.Fatalf("Clashing = %v, want only the server's own entry", got)
	}
	if z := zoneZero([]*netlink.ConntrackFlow{serverFirst, otherZone}); len(z) != 1 || z[0] != serverFirst {
		t.Fatalf("zoneZero kept %v", z)
	}
}

// attrs splits a serialized attribute list.
func attrs(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	list, err := nl.ParseRouteAttr(b)
	if err != nil {
		t.Fatal(err)
	}
	m := map[uint16][]byte{}
	for _, a := range list {
		m[a.Attr.Type&nl.NLA_TYPE_MASK] = a.Value
	}
	return m
}

func TestCreateData(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		e                      Entry
		family                 uint8
		ipSrc, ipDst           uint16
		natMin, natMax, ipSize int
	}{
		{"IPv4", Entry{Proto: unix.IPPROTO_UDP,
			OrigSrc: netip.MustParseAddrPort("3.67.9.3:46683"), OrigDst: netip.MustParseAddrPort("192.168.78.222:31716"),
			ReplySrc: netip.MustParseAddrPort("192.168.93.7:26000"), ReplyDst: netip.MustParseAddrPort("192.168.78.222:63723")},
			unix.AF_INET, nl.CTA_IP_V4_SRC, nl.CTA_IP_V4_DST, ctaNatV4MinIP, ctaNatV4MaxIP, 4},
		{"IPv6", Entry{Proto: unix.IPPROTO_UDP,
			OrigSrc: netip.MustParseAddrPort("[2001:db8::3]:46683"), OrigDst: netip.MustParseAddrPort("[fd00:78::222]:31716"),
			ReplySrc: netip.MustParseAddrPort("[fd00:93::7]:26000"), ReplyDst: netip.MustParseAddrPort("[fd00:78::222]:63723")},
			unix.AF_INET6, nl.CTA_IP_V6_SRC, nl.CTA_IP_V6_DST, ctaNatV6MinIP, ctaNatV6MaxIP, 16},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := createData(tt.e, true)
			if hdr := data[0].Serialize(); hdr[0] != tt.family {
				t.Fatalf("nfgenmsg family %d, want %d", hdr[0], tt.family)
			}
			var body []byte
			for _, d := range data[1:] {
				body = append(body, d.Serialize()...)
			}
			top := attrs(t, body)
			checkTuple := func(kind uint16, src, dst netip.AddrPort) {
				t.Helper()
				tuple := attrs(t, top[kind])
				ip := attrs(t, tuple[nl.CTA_TUPLE_IP])
				if !bytes.Equal(ip[tt.ipSrc], src.Addr().AsSlice()) || !bytes.Equal(ip[tt.ipDst], dst.Addr().AsSlice()) {
					t.Errorf("tuple %d addresses %v %v, want %s %s", kind, ip[tt.ipSrc], ip[tt.ipDst], src, dst)
				}
				p := attrs(t, tuple[nl.CTA_TUPLE_PROTO])
				if p[nl.CTA_PROTO_NUM][0] != unix.IPPROTO_UDP ||
					binary.BigEndian.Uint16(p[nl.CTA_PROTO_SRC_PORT]) != src.Port() ||
					binary.BigEndian.Uint16(p[nl.CTA_PROTO_DST_PORT]) != dst.Port() {
					t.Errorf("tuple %d ports wrong", kind)
				}
			}
			checkTuple(nl.CTA_TUPLE_ORIG, tt.e.OrigSrc, tt.e.OrigDst)
			// Untranslated reply: the kernel derives the bindings from the
			// NAT ranges (see create).
			checkTuple(nl.CTA_TUPLE_REPLY, tt.e.OrigDst, tt.e.OrigSrc)
			checkNAT := func(kind uint16, to netip.AddrPort) {
				t.Helper()
				n := attrs(t, top[kind])
				if len(n[uint16(tt.natMin)]) != tt.ipSize || !bytes.Equal(n[uint16(tt.natMin)], to.Addr().AsSlice()) ||
					!bytes.Equal(n[uint16(tt.natMax)], to.Addr().AsSlice()) {
					t.Errorf("NAT %d range %v-%v, want exactly %s", kind, n[uint16(tt.natMin)], n[uint16(tt.natMax)], to.Addr())
				}
				p := attrs(t, n[ctaNatProto])
				if binary.BigEndian.Uint16(p[ctaProtoNatPortLo]) != to.Port() || binary.BigEndian.Uint16(p[ctaProtoNatPortHi]) != to.Port() {
					t.Errorf("NAT %d ports wrong, want exactly %d", kind, to.Port())
				}
			}
			checkNAT(ctaNatDst, tt.e.ReplySrc) // to the new pod address
			checkNAT(ctaNatSrc, tt.e.ReplyDst) // the masquerade binding the server knows
			if v := binary.BigEndian.Uint32(top[nl.CTA_TIMEOUT]); v != udpEntryTimeout {
				t.Errorf("timeout %d", v)
			}
			if v := binary.BigEndian.Uint32(top[nl.CTA_STATUS]); v != ipsConfirmed|ipsSeenReply|ipsAssured {
				t.Errorf("status %#x", v)
			}
			if _, ok := top[nl.CTA_PROTOINFO]; ok {
				t.Error("UDP entry with TCP protoinfo")
			}
		})
	}
}

// The IPv4 tuple encoding is the one the kernel's events use (and the one
// the guard used before it learned IPv6).
func TestTupleAttrIPv4Encoding(t *testing.T) {
	src, dst := netip.MustParseAddrPort("203.0.113.24:58006"), netip.MustParseAddrPort("10.42.0.111:30777")
	if !bytes.Equal(tupleAttr(nl.CTA_TUPLE_ORIG, unix.IPPROTO_UDP, src, dst).Serialize(),
		tupleBytes(nl.CTA_TUPLE_ORIG, unix.IPPROTO_UDP, src, dst).Serialize()) {
		t.Fatal("IPv4 tuple encoding changed")
	}
	// A v4-mapped address is encoded as IPv4.
	mapped := netip.AddrPortFrom(netip.AddrFrom16(src.Addr().As16()), src.Port())
	if !bytes.Equal(tupleAttr(nl.CTA_TUPLE_ORIG, unix.IPPROTO_UDP, mapped, dst).Serialize(),
		tupleBytes(nl.CTA_TUPLE_ORIG, unix.IPPROTO_UDP, src, dst).Serialize()) {
		t.Fatal("v4-mapped address not encoded as IPv4")
	}
}

func TestParseTuplesIPv6(t *testing.T) {
	client := netip.MustParseAddrPort("[2001:db8::3]:46683")
	nodePort := netip.MustParseAddrPort("[fd00:78::222]:31716")
	pod := netip.MustParseAddrPort("[fd00:90::1]:26000")
	masq := netip.MustParseAddrPort("[fd00:78::222]:63723")
	data := []byte{unix.AF_INET6, 0, 0, 0}
	data = append(data, tupleAttr(nl.CTA_TUPLE_ORIG, unix.IPPROTO_UDP, client, nodePort).Serialize()...)
	data = append(data, tupleAttr(nl.CTA_TUPLE_REPLY, unix.IPPROTO_UDP, pod, masq).Serialize()...)
	orig, reply, ok := parseTuples(data)
	if !ok || orig != (origKey{unix.IPPROTO_UDP, client, nodePort}) || reply != (replyKey{pod, masq}) {
		t.Fatalf("parsed %v %+v %+v", ok, orig, reply)
	}
}

// Without masquerade (a ClusterIP client) the moved binding still pins the
// source: the kernel's null binding would silently pick another port when
// the reply tuple is taken. The keep-IP guard leaves it out, as before.
func TestCreateDataPinsSource(t *testing.T) {
	e := Entry{Proto: unix.IPPROTO_UDP,
		OrigSrc: netip.MustParseAddrPort("192.168.92.34:45639"), OrigDst: netip.MustParseAddrPort("10.100.52.10:26000"),
		ReplySrc: netip.MustParseAddrPort("192.168.93.7:26000"), ReplyDst: netip.MustParseAddrPort("192.168.92.34:45639")}
	natSrc := func(pin bool) []byte {
		var body []byte
		for _, d := range createData(e, pin)[1:] {
			body = append(body, d.Serialize()...)
		}
		return attrs(t, body)[ctaNatSrc]
	}
	if natSrc(false) != nil {
		t.Fatal("unpinned create of an entry without masquerade carries CTA_NAT_SRC")
	}
	n := attrs(t, natSrc(true))
	p := attrs(t, n[ctaNatProto])
	if !bytes.Equal(n[ctaNatV4MinIP], e.OrigSrc.Addr().AsSlice()) || binary.BigEndian.Uint16(p[ctaProtoNatPortLo]) != 45639 ||
		binary.BigEndian.Uint16(p[ctaProtoNatPortHi]) != 45639 {
		t.Fatalf("pinned source binding wrong: %v %v", n, p)
	}
}

// What the watch does on each event (namespace model, kube-proxy deleting
// the moved bindings while the restored server keeps sending).
func TestReactRetargeted(t *testing.T) {
	w := Entry{Proto: unix.IPPROTO_UDP,
		OrigSrc: netip.MustParseAddrPort("192.168.51.100:54715"), OrigDst: netip.MustParseAddrPort("192.168.51.1:30260"),
		ReplySrc: netip.MustParseAddrPort("10.245.3.20:26000"), ReplyDst: netip.MustParseAddrPort("192.168.51.1:8541")}
	orig := origKey{w.Proto, w.OrigSrc, w.OrigDst}
	right := replyKey{w.ReplySrc, w.ReplyDst}
	wrong := replyKey{w.ReplySrc, netip.MustParseAddrPort("192.168.51.1:13508")}
	// The server's datagram to the binding, with the binding gone.
	clashOrig := origKey{w.Proto, w.ReplySrc, w.ReplyDst}
	clashReply := replyKey{w.ReplyDst, w.ReplySrc}
	other := origKey{w.Proto, netip.MustParseAddrPort("192.168.51.100:1"), w.OrigDst}

	for _, retargeted := range []bool{false, true} {
		s := &Set{retargeted: retargeted}
		s.Add([]Entry{w})
		cases := []struct {
			name        string
			msg         uint8
			orig        origKey
			reply       replyKey
			act, remove bool
		}{
			{"binding destroyed", nl.IPCTNL_MSG_CT_DELETE, orig, right, true, false},
			{"own re-install", nl.IPCTNL_MSG_CT_NEW, orig, right, false, false},
			{"NATed afresh", nl.IPCTNL_MSG_CT_NEW, orig, wrong, true, true},
			{"wrong one removed", nl.IPCTNL_MSG_CT_DELETE, orig, wrong, false, false},
			{"server's datagram on the binding", nl.IPCTNL_MSG_CT_NEW, clashOrig, clashReply, retargeted, retargeted},
			{"that one removed", nl.IPCTNL_MSG_CT_DELETE, clashOrig, clashReply, false, false},
			{"another client", nl.IPCTNL_MSG_CT_NEW, other, wrong, false, false},
		}
		for _, c := range cases {
			act, ok := s.react(c.msg, c.orig, c.reply)
			if ok != c.act || (ok && (act.want != w || (act.remove != nil) != c.remove)) {
				t.Errorf("retargeted=%v %s: act=%v %+v", retargeted, c.name, ok, act)
				continue
			}
			if c.remove && act.remove != nil && (act.remove.ReplySrc != c.reply.src || act.remove.ReplyDst != c.reply.dst) {
				t.Errorf("retargeted=%v %s: removes %v, want the entry with reply %v", retargeted, c.name, act.remove, c.reply)
			}
		}
	}
}

// The kernel's answer to a lookup, and the exact delete built from it.
func TestParseEntryIDAndDeleteByID(t *testing.T) {
	clash := Entry{Proto: unix.IPPROTO_UDP,
		OrigSrc: netip.MustParseAddrPort("10.245.3.20:26000"), OrigDst: netip.MustParseAddrPort("192.168.51.1:28104"),
		ReplySrc: netip.MustParseAddrPort("192.168.51.1:28104"), ReplyDst: netip.MustParseAddrPort("10.245.3.20:26000")}
	data := []byte{unix.AF_INET, 0, 0, 0}
	data = append(data, tupleAttr(nl.CTA_TUPLE_ORIG, clash.Proto, clash.OrigSrc, clash.OrigDst).Serialize()...)
	data = append(data, tupleAttr(nl.CTA_TUPLE_REPLY, clash.Proto, clash.ReplySrc, clash.ReplyDst).Serialize()...)
	data = append(data, nl.NewRtAttr(nl.CTA_STATUS, be32(ipsConfirmed)).Serialize()...)
	data = append(data, nl.NewRtAttr(nl.CTA_ID, be32(0xdeadbeef)).Serialize()...)
	e, id, ok := parseEntryID(data)
	if !ok || e != clash || id != 0xdeadbeef {
		t.Fatalf("parsed %v %v %#x", ok, e, id)
	}
	if _, _, ok := parseEntryID(data[:len(data)-8]); ok {
		t.Fatal("entry without id accepted")
	}
	req := deleteByIDData(clash, id)
	var body []byte
	for _, d := range req[1:] {
		body = append(body, d.Serialize()...)
	}
	top := attrs(t, body)
	if binary.BigEndian.Uint32(top[nl.CTA_ID]) != 0xdeadbeef {
		t.Fatal("delete without the id")
	}
	if _, ok := top[nl.CTA_TUPLE_ORIG]; !ok || req[0].Serialize()[0] != unix.AF_INET {
		t.Fatal("delete without the original tuple or with the wrong family")
	}
}

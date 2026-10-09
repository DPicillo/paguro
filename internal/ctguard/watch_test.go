// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package ctguard

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func tupleBytes(kind int, proto uint8, src, dst netip.AddrPort) *nl.RtAttr {
	t := nl.NewRtAttr(unix.NLA_F_NESTED|kind, nil)
	ip := t.AddRtAttr(unix.NLA_F_NESTED|ctaTupleIP, nil)
	ip.AddRtAttr(ctaIPv4Src, src.Addr().AsSlice())
	ip.AddRtAttr(ctaIPv4Dst, dst.Addr().AsSlice())
	p := t.AddRtAttr(unix.NLA_F_NESTED|ctaTupleProto, nil)
	p.AddRtAttr(ctaProtoNum, []byte{proto})
	p.AddRtAttr(ctaProtoSrc, binary.BigEndian.AppendUint16(nil, src.Port()))
	p.AddRtAttr(ctaProtoDst, binary.BigEndian.AppendUint16(nil, dst.Port()))
	return t
}

// A conntrack event as the kernel sends it: nfgenmsg, then the tuples.
func TestParseTuples(t *testing.T) {
	client := netip.MustParseAddrPort("203.0.113.24:58006")
	nodePort := netip.MustParseAddrPort("10.42.0.111:30777")
	pod := netip.MustParseAddrPort("10.245.118.194:7777")
	masq := netip.MustParseAddrPort("10.245.215.128:32422")
	data := []byte{unix.AF_INET, 0, 0, 0}
	data = append(data, tupleBytes(nl.CTA_TUPLE_ORIG, unix.IPPROTO_UDP, client, nodePort).Serialize()...)
	data = append(data, tupleBytes(nl.CTA_TUPLE_REPLY, unix.IPPROTO_UDP, pod, masq).Serialize()...)
	orig, reply, ok := parseTuples(data)
	if !ok {
		t.Fatal("not parsed")
	}
	if orig != (origKey{unix.IPPROTO_UDP, client, nodePort}) {
		t.Errorf("orig %+v", orig)
	}
	if reply != (replyKey{pod, masq}) {
		t.Errorf("reply %+v", reply)
	}
	if _, _, ok := parseTuples([]byte{1, 2}); ok {
		t.Error("garbage parsed")
	}
}

func TestSetAddAndLookup(t *testing.T) {
	e := Entry{Proto: unix.IPPROTO_UDP, OrigSrc: netip.MustParseAddrPort("1.1.1.1:1"), OrigDst: netip.MustParseAddrPort("2.2.2.2:2"),
		ReplySrc: netip.MustParseAddrPort("3.3.3.3:3"), ReplyDst: netip.MustParseAddrPort("4.4.4.4:4")}
	s := &Set{}
	s.Add([]Entry{e})
	if got, ok := s.lookup(origKey{e.Proto, e.OrigSrc, e.OrigDst}); !ok || got != e || len(s.All()) != 1 {
		t.Fatalf("lookup %v %v", got, ok)
	}
}

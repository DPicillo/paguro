// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package ctguard keeps the netfilter NAT bindings of a migrated pod's
// connections across conntrack flushes (keep-IP mode).
//
// A client that reaches a pod through a NodePort or LoadBalancer Service
// with externalTrafficPolicy Cluster is NATed twice on its entry node:
// kube-proxy's DNAT to the pod and a masquerade to an address of the entry
// node. Which address depends on the way to the pod – the node IP while
// the pod is local, the tunnel device's address (vxlan.calico, …) while it
// is on another node. The restored socket knows the mapping of the moment
// it was frozen. As long as the conntrack entry lives, nothing changes. But
// Calico's Felix flushes every entry of a workload IP when the workload
// endpoint disappears (on the source) and when it appears (on the target):
// measured with bpftrace on ctnetlink_del_conntrack, comm=conntrack. The
// client's next packet is then NATed afresh, masquerade picks the other
// address, and the restored socket answers with a reset.
//
// The guard records the NATed entries of the pod at the freeze on the
// source and the target node and re-installs any that went missing or came
// back with another binding, until shortly after the restore. Entries
// that the CNI leaves alone are never touched.
package ctguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Entry is one NATed connection as conntrack keeps it.
type Entry struct {
	Proto uint8
	// Orig is the direction from the client, as it entered the node.
	OrigSrc, OrigDst netip.AddrPort
	// Reply is the direction from the pod: ReplySrc is the pod (after
	// DNAT), ReplyDst the address replies go to (after SNAT).
	ReplySrc, ReplyDst netip.AddrPort
}

// DNAT reports whether the destination was translated (Service to pod).
func (e Entry) DNAT() bool { return e.ReplySrc != e.OrigDst }

// SNAT reports whether the source was translated (masquerade).
func (e Entry) SNAT() bool { return e.ReplyDst != e.OrigSrc }

func (e Entry) String() string {
	return fmt.Sprintf("%s->%s (reply %s->%s)", e.OrigSrc, e.OrigDst, e.ReplySrc, e.ReplyDst)
}

type origKey struct {
	proto    uint8
	src, dst netip.AddrPort
}

func flowEntry(f *netlink.ConntrackFlow) (Entry, bool) {
	ap := func(ip net.IP, port uint16) (netip.AddrPort, bool) {
		a, ok := netip.AddrFromSlice(ip)
		return netip.AddrPortFrom(a.Unmap(), port), ok
	}
	os, ok1 := ap(f.Forward.SrcIP, f.Forward.SrcPort)
	od, ok2 := ap(f.Forward.DstIP, f.Forward.DstPort)
	rs, ok3 := ap(f.Reverse.SrcIP, f.Reverse.SrcPort)
	rd, ok4 := ap(f.Reverse.DstIP, f.Reverse.DstPort)
	return Entry{Proto: f.Forward.Protocol, OrigSrc: os, OrigDst: od, ReplySrc: rs, ReplyDst: rd}, ok1 && ok2 && ok3 && ok4
}

// Select returns the established TCP entries and the UDP entries whose reply
// comes from pod and that carry a NAT binding (closing and closed TCP ones
// need no guard). UDP matters as much: a game client's flow through a
// NodePort that is NATed afresh reaches the server from another source port
// – a new player to the server (measured on Calico).
func Select(flows []*netlink.ConntrackFlow, pod netip.Addr) []Entry {
	var out []Entry
	for _, f := range flows {
		e, ok := flowEntry(f)
		if !ok || (e.Proto != unix.IPPROTO_TCP && e.Proto != unix.IPPROTO_UDP) || e.ReplySrc.Addr() != pod || !(e.DNAT() || e.SNAT()) {
			continue
		}
		if tcp, isTCP := f.ProtoInfo.(*netlink.ProtoInfoTCP); isTCP && tcp.State != tcpEstablished {
			continue
		}
		// UDP: only streams. A one-shot exchange (a join request, a DNS
		// query) has at most the unreplied timeout left; guarding it would
		// re-create it after it expired (measured: hundreds of join flows).
		if e.Proto == unix.IPPROTO_UDP && f.TimeOut <= udpOneShotTimeout {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Snapshot lists this network namespace's NATed TCP and UDP entries of pod.
func Snapshot(pod netip.Addr) ([]Entry, error) {
	if !pod.Is4() {
		return nil, nil // IPv4 only for now
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	return Select(flows, pod), nil
}

// Missing returns the entries that are absent from flows, and those present
// with another reply tuple (another binding) – as found, so that exactly
// that entry can be removed.
func Missing(flows []*netlink.ConntrackFlow, want []Entry) (absent []Entry, rebound []Rebound) {
	cur := map[origKey]Entry{}
	for _, f := range flows {
		if e, ok := flowEntry(f); ok {
			cur[origKey{e.Proto, e.OrigSrc, e.OrigDst}] = e
		}
	}
	for _, w := range want {
		c, ok := cur[origKey{w.Proto, w.OrigSrc, w.OrigDst}]
		switch {
		case !ok:
			absent = append(absent, w)
		case c.ReplySrc != w.ReplySrc || c.ReplyDst != w.ReplyDst:
			rebound = append(rebound, Rebound{Want: w, Found: c})
		}
	}
	return absent, rebound
}

// Ensure re-installs the entries that went missing or came back with
// another binding. It returns what it repaired.
func Ensure(want []Entry) ([]Entry, error) {
	if len(want) == 0 {
		return nil, nil
	}
	flows, err := listFamilies(want)
	if err != nil {
		return nil, err
	}
	absent, rebound := Missing(flows, want)
	return repair(nil, absent, rebound, nil, func(c *conn, e Entry) error { return createWith(c, e, false) })
}

// repair removes the entries in the way – a connection's other binding
// (rebound), entries occupying a wanted reply tuple (clashing) – and then
// installs the wanted bindings with install, all on c.
func repair(c *conn, absent []Entry, rebound []Rebound, clashing []Entry, install func(*conn, Entry) error) ([]Entry, error) {
	var errs []error
	fixed := absent
	for _, r := range rebound {
		if err := deleteExactOn(c, r.Found); err != nil && !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, err)
		}
		fixed = append(fixed, r.Want)
	}
	for _, e := range clashing {
		if err := deleteExactOn(c, e); err != nil && !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, err)
		}
	}
	for _, e := range fixed {
		if err := install(c, e); err != nil && !errors.Is(err, syscall.EEXIST) {
			errs = append(errs, fmt.Errorf("%s: %w", e, err))
		}
	}
	return fixed, errors.Join(errs...)
}

// listFamilies dumps the conntrack table of each address family in want.
// A dump interrupted by concurrent changes (netlink.ErrDumpInterrupted)
// returns what it got together with that error.
func listFamilies(want []Entry) ([]*netlink.ConntrackFlow, error) {
	var fams []netlink.InetFamily
	for _, e := range want {
		if f := netlink.InetFamily(e.family()); !slices.Contains(fams, f) {
			fams = append(fams, f)
		}
	}
	var all []*netlink.ConntrackFlow
	var interrupted error
	for _, f := range fams {
		flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, f)
		if errors.Is(err, netlink.ErrDumpInterrupted) {
			interrupted = err
		} else if err != nil {
			return nil, err
		}
		all = append(all, flows...)
	}
	return all, interrupted
}

// family is the entry's address family (AF_INET or AF_INET6).
func (e Entry) family() uint8 {
	if e.OrigSrc.Addr().Unmap().Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

// Rebound is a guarded connection found with another binding.
type Rebound struct{ Want, Found Entry }

// deleteExactOn removes the entry with exactly e's reply tuple – never the
// guarded binding of the same connection: deleting by the original tuple
// alone, two repairs at once removed each other's re-installed entry, and
// the client's next packet got yet another random masquerade port
// (measured: a game client seen from a new address every 100–300 ms for
// 2 s).
func deleteExactOn(c *conn, e Entry) error {
	req := nl.NewNetlinkRequest((unix.NFNL_SUBSYS_CTNETLINK<<8)|nl.IPCTNL_MSG_CT_DELETE, unix.NLM_F_ACK)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: e.family(), Version: nl.NFNETLINK_V0})
	req.AddData(tupleAttr(nl.CTA_TUPLE_REPLY, e.Proto, e.ReplySrc, e.ReplyDst))
	_, err := c.exec(req)
	return err
}

// conn is one ctnetlink socket for a series of requests. Opening a netlink
// socket can cost far more than a request on it (measured on WSL2's 6.6
// kernel: 10 ms per socket, 7 µs per request): a repair that opened one per
// request lost its race against a client sending every 33 ms. A nil *conn
// opens a socket per request.
type conn struct{ sh *nl.SocketHandle }

// openConn opens a socket in the calling thread's network namespace.
func openConn() (*conn, error) {
	s, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	// Every request asks for an answer; a lost one must not stall the guard.
	if err := s.SetReceiveTimeout(&unix.Timeval{Sec: 2}); err != nil {
		s.Close()
		return nil, err
	}
	return &conn{sh: &nl.SocketHandle{Socket: s}}, nil
}

func (c *conn) close() {
	if c != nil {
		c.sh.Close()
	}
}

func (c *conn) exec(req *nl.NetlinkRequest) ([][]byte, error) {
	if c != nil {
		req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: c.sh}
	}
	return req.Execute(unix.NETLINK_NETFILTER, 0)
}

// ctnetlink attributes the netlink package does not define
// (include/uapi/linux/netfilter/nfnetlink_conntrack.h).
const (
	ctaNatSrc         = 6
	ctaNatDst         = 13
	ctaNatV4MinIP     = 1
	ctaNatV4MaxIP     = 2
	ctaNatProto       = 3
	ctaNatV6MinIP     = 4
	ctaNatV6MaxIP     = 5
	ctaProtoNatPortLo = 1
	ctaProtoNatPortHi = 2

	ipsSeenReply = 1 << 1
	ipsAssured   = 1 << 2
	ipsConfirmed = 1 << 3
	// IP_CT_TCP_FLAG_BE_LIBERAL (struct nf_ct_tcp_flags: flags, mask)
	tcpFlagBeLiberal = 0x08
	tcpEstablished   = 3
	// timeout of a re-created entry; traffic refreshes it to the node's
	// established timeout
	entryTimeout = 300
	// UDP: a re-created stream, and the most an entry that is not a stream
	// has left (nf_conntrack_udp_timeout, default 30 s; streams 120 s)
	udpEntryTimeout   = 120
	udpOneShotTimeout = 30
)

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func tupleAttr(kind int, proto uint8, src, dst netip.AddrPort) *nl.RtAttr {
	t := nl.NewRtAttr(unix.NLA_F_NESTED|kind, nil)
	ip := t.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
	if src.Addr().Unmap().Is4() {
		s, d := src.Addr().Unmap().As4(), dst.Addr().Unmap().As4()
		ip.AddRtAttr(nl.CTA_IP_V4_SRC, s[:])
		ip.AddRtAttr(nl.CTA_IP_V4_DST, d[:])
	} else {
		s, d := src.Addr().As16(), dst.Addr().As16()
		ip.AddRtAttr(nl.CTA_IP_V6_SRC, s[:])
		ip.AddRtAttr(nl.CTA_IP_V6_DST, d[:])
	}
	p := t.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	p.AddRtAttr(nl.CTA_PROTO_NUM, []byte{proto})
	p.AddRtAttr(nl.CTA_PROTO_SRC_PORT, be16(src.Port()))
	p.AddRtAttr(nl.CTA_PROTO_DST_PORT, be16(dst.Port()))
	return t
}

// natAttr pins a NAT binding to exactly one address and port.
func natAttr(kind int, to netip.AddrPort) *nl.RtAttr {
	n := nl.NewRtAttr(unix.NLA_F_NESTED|kind, nil)
	if to.Addr().Unmap().Is4() {
		a := to.Addr().Unmap().As4()
		n.AddRtAttr(ctaNatV4MinIP, a[:])
		n.AddRtAttr(ctaNatV4MaxIP, a[:])
	} else {
		a := to.Addr().As16()
		n.AddRtAttr(ctaNatV6MinIP, a[:])
		n.AddRtAttr(ctaNatV6MaxIP, a[:])
	}
	p := n.AddRtAttr(unix.NLA_F_NESTED|ctaNatProto, nil)
	p.AddRtAttr(ctaProtoNatPortLo, be16(to.Port()))
	p.AddRtAttr(ctaProtoNatPortHi, be16(to.Port()))
	return n
}

// create installs an established entry with its NAT bindings. Without the
// CTA_NAT attributes the kernel would store the two tuples but never
// translate a packet.
func create(e Entry) error { return createWith(nil, e, false) }

// createPinned is create with the source binding pinned even where there is
// no masquerade (ReplyDst = OrigSrc). Without CTA_NAT_SRC the kernel sets up
// a null binding, which keeps the client's port only while that reply tuple
// is free – otherwise it silently picks another port (measured: a ClusterIP
// client re-installed with a random port next to an entry in the way). Pinned,
// the create fails instead (EEXIST), and the repair removes what is in the way.
func createPinned(c *conn, e Entry) error { return createWith(c, e, true) }

func createWith(c *conn, e Entry, pin bool) error {
	req := nl.NewNetlinkRequest((unix.NFNL_SUBSYS_CTNETLINK<<8)|nl.IPCTNL_MSG_CT_NEW,
		unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	for _, d := range createData(e, pin) {
		req.AddData(d)
	}
	_, err := c.exec(req)
	return err
}

// createData is the body of create's request: the family header and the
// attributes.
func createData(e Entry, pinSource bool) []nl.NetlinkRequestData {
	var req []nl.NetlinkRequestData
	add := func(d nl.NetlinkRequestData) { req = append(req, d) }
	add(&nl.Nfgenmsg{NfgenFamily: e.family(), Version: nl.NFNETLINK_V0})
	add(tupleAttr(nl.CTA_TUPLE_ORIG, e.Proto, e.OrigSrc, e.OrigDst))
	// The reply tuple goes in untranslated (the inverse of the original):
	// nf_nat_setup_info derives what to translate from it and the NAT
	// ranges, and computes the translated reply itself. Passing the
	// translated reply makes it see nothing to do – the entry then matches
	// but never rewrites a packet (measured: the client's packet ended on
	// the node's NodePort and drew a reset).
	add(tupleAttr(nl.CTA_TUPLE_REPLY, e.Proto, e.OrigDst, e.OrigSrc))
	if e.DNAT() {
		add(natAttr(ctaNatDst, e.ReplySrc))
	}
	if e.SNAT() || pinSource {
		add(natAttr(ctaNatSrc, e.ReplyDst))
	}
	timeout := uint32(entryTimeout)
	if e.Proto == unix.IPPROTO_UDP {
		timeout = udpEntryTimeout
	}
	add(nl.NewRtAttr(nl.CTA_TIMEOUT, be32(timeout)))
	// The kernel marks a created entry confirmed before it applies
	// CTA_STATUS and refuses a status that would flip that bit (EBUSY).
	add(nl.NewRtAttr(nl.CTA_STATUS, be32(ipsConfirmed|ipsSeenReply|ipsAssured)))
	if e.Proto != unix.IPPROTO_TCP {
		return req
	}
	pi := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO, nil)
	tcp := pi.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_PROTOINFO_TCP, nil)
	tcp.AddRtAttr(nl.CTA_PROTOINFO_TCP_STATE, []byte{tcpEstablished})
	// The entry starts without the connection's window and window scale:
	// with window tracking the next segments would count as out of window
	// (INVALID – Calico drops those; measured: the client hung). Liberal
	// tracking for this one connection, as for a connection the kernel
	// picks up in the middle.
	tcp.AddRtAttr(nl.CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, []byte{tcpFlagBeLiberal, tcpFlagBeLiberal})
	tcp.AddRtAttr(nl.CTA_PROTOINFO_TCP_FLAGS_REPLY, []byte{tcpFlagBeLiberal, tcpFlagBeLiberal})
	add(pi)
	return req
}

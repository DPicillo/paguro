// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package ctguard

// Moving NAT bindings to a new pod address (Phantom mode, UDP servers).
//
// An unconnected UDP socket (a game server, QUIC, DNS) knows its clients
// by the address their datagrams come from. A client that reaches it
// through a NodePort or LoadBalancer with externalTrafficPolicy Cluster is
// masqueraded on its entry node, and the server knows it by the entry
// node's address and the port the masquerade chose. When the pod gets a new
// IP, kube-proxy deletes the stale UDP entries to the old address, and the
// client's next datagram is NATed afresh. kube-proxy masquerades with
// --random-fully wherever iptables supports it, so that is another port: the
// server sees a stranger and never answers its player (measured on EKS:
// the reply port 63723 became 34700 43 ms after kube-proxy's delete).
//
// The fix keeps the binding and moves only its pod side: for each client
// entry whose reply comes from old:port, an entry with the same original
// tuple (client to the Service address), the reply from new:port and the
// same reply destination – the masquerade address and port the server
// knows. It is installed like a guarded entry (create: CTA_NAT_DST to
// new:port, CTA_NAT_SRC to the masquerade binding), so netfilter applies it
// as an established NAT binding: the client's datagrams go to the new
// address from the port the server knows, without a pass through
// kube-proxy's rules. kube-proxy's clean-up leaves it alone: it deletes
// UDP entries whose reply source is not a serving endpoint of the Service,
// and the new address serves (Paguro's endpoint bridge lists it as ready
// before the old endpoint leaves).

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// SelectRebind returns the UDP entries whose reply comes from old on one of
// ports and that a Service translated (DNAT from another address): the
// clients of the pod's UDP servers that came through a ClusterIP, NodePort
// or LoadBalancer, with or without masquerade. Clients that write to old
// directly are not selected (nothing on their way translates them), nor
// one-shot exchanges (a query, a join request: at most the unreplied
// timeout left) – re-created, they would outlive their exchange. Only
// conntrack zone 0, where kube-proxy's NAT lives: CNIs that translate
// Services in Open vSwitch (Antrea's proxy, OVN-Kubernetes) keep their
// entries in zones of their own, and a zone-0 copy would translate packets
// they never meant to. skip, if set, leaves entries out (connections
// Phantom mode translates itself).
func SelectRebind(flows []*netlink.ConntrackFlow, old netip.Addr, ports []uint16, skip func(Entry) bool) []Entry {
	old = old.Unmap()
	var out []Entry
	for _, f := range flows {
		if f.Zone != 0 {
			continue
		}
		e, ok := flowEntry(f)
		if !ok || e.Proto != unix.IPPROTO_UDP || e.ReplySrc.Addr() != old || !slices.Contains(ports, e.ReplySrc.Port()) {
			continue
		}
		if !e.DNAT() || e.OrigDst.Addr() == old {
			continue // written to the pod address itself
		}
		if f.TimeOut <= udpOneShotTimeout {
			continue
		}
		if skip != nil && skip(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Retarget returns the entries with their pod side moved to new: the same
// original tuple, the reply from new on the same port and to the same
// destination (the masquerade binding). Entries of another address family
// than new are dropped.
func Retarget(entries []Entry, new netip.Addr) []Entry {
	new = new.Unmap()
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.ReplySrc.Addr().Is4() != new.Is4() {
			continue
		}
		e.ReplySrc = netip.AddrPortFrom(new, e.ReplySrc.Port())
		out = append(out, e)
	}
	return out
}

// Clashing returns the entries that the new address opened towards a
// wanted entry's masquerade binding: a datagram the restored server sent
// to the client's masquerade address before the binding was moved found no
// NAT binding on this node and became an entry of its own (original tuple
// = the wanted reply tuple). The kernel would refuse the wanted entry
// (EEXIST), and the client would be NATed afresh. Such an entry carries
// nothing: no socket on this node listens on a masquerade port.
func Clashing(flows []*netlink.ConntrackFlow, want []Entry) []Entry {
	type key struct {
		proto    uint8
		src, dst netip.AddrPort
	}
	replies := map[key]bool{}
	for _, w := range want {
		replies[key{w.Proto, w.ReplySrc, w.ReplyDst}] = true
	}
	var out []Entry
	for _, f := range flows {
		if e, ok := flowEntry(f); ok && f.Zone == 0 && replies[key{e.Proto, e.OrigSrc, e.OrigDst}] {
			out = append(out, e)
		}
	}
	return out
}

// SnapshotRebind lists this network namespace's entries that SelectRebind
// selects. A dump interrupted by concurrent changes is retried; the last
// attempt's partial list is used rather than none.
func SnapshotRebind(old netip.Addr, ports []uint16, skip func(Entry) bool) ([]Entry, error) {
	fam := netlink.InetFamily(unix.AF_INET6)
	if old.Unmap().Is4() {
		fam = unix.AF_INET
	}
	var flows []*netlink.ConntrackFlow
	var err error
	for range 3 {
		flows, err = netlink.ConntrackTableList(netlink.ConntrackTable, fam)
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return nil, err
	}
	return SelectRebind(flows, old, ports, skip), nil
}

// EnsureRetargeted is Ensure for entries moved by Retarget: it also removes
// entries in the way of their reply tuple (Clashing).
func EnsureRetargeted(want []Entry) ([]Entry, error) {
	if len(want) == 0 {
		return nil, nil
	}
	flows, err := listFamilies(want)
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return nil, err
	}
	// An interrupted dump may miss entries: they are taken for absent and
	// their create fails with EEXIST, which repair ignores.
	flows = zoneZero(flows)
	absent, rebound := Missing(flows, want)
	c, err := openConn()
	if err != nil {
		c = nil // a socket per request
	}
	defer c.close()
	return repair(c, absent, rebound, Clashing(flows, want), installExclusive)
}

// zoneZero keeps the entries of conntrack zone 0 (see SelectRebind): the
// moved bindings live there, and only entries there are in their way.
func zoneZero(flows []*netlink.ConntrackFlow) []*netlink.ConntrackFlow {
	out := flows[:0:0]
	for _, f := range flows {
		if f.Zone == 0 {
			out = append(out, f)
		}
	}
	return out
}

// installExclusive creates a moved binding and clears what is in its way.
// While the binding is gone – kube-proxy's clean-up, or the move itself –
// two sources keep re-creating obstacles: the client's next datagram (a
// fresh binding on the same original tuple) and the restored server's
// next datagram to the client (an entry on the binding's reply tuple).
// Removing what a dump or an event showed and then creating loses against
// whichever comes next (measured in the namespace model without the hold:
// one player's binding re-installed for 1.5 s). So on EEXIST it asks the
// kernel which entries hold the two tuples, removes exactly those (by
// their conntrack id) unless one is the wanted binding itself, and tries
// again. It removes only those two kinds: an entry of the same client
// flow, and the server's own entry towards the binding (Clashing) – not
// another client's binding that happens to hold the same reply tuple.
func installExclusive(c *conn, w Entry) error {
	var err error
	for range 4 {
		if err = createPinned(c, w); !errors.Is(err, syscall.EEXIST) {
			return err
		}
		cleared := false
		for _, t := range [2][2]netip.AddrPort{{w.OrigSrc, w.OrigDst}, {w.ReplySrc, w.ReplyDst}} {
			holder, id, ok := lookupTuple(c, w.Proto, t[0], t[1])
			if !ok {
				continue
			}
			if holder == w {
				return nil // in place: created meanwhile
			}
			if holder.OrigSrc != t[0] || holder.OrigDst != t[1] {
				continue // holds the tuple as its reply: not one of the two
			}
			if deleteByID(c, holder, id) == nil {
				cleared = true
			}
		}
		if !cleared {
			return err
		}
	}
	return err
}

// lookupTuple returns the entry that holds a tuple in either direction
// (zone 0) and its conntrack id. The request asks for an ACK: the kernel
// marks its answer NLM_F_MULTI and sends no NLMSG_DONE, so without the ACK
// the netlink package would wait for more (measured: the lookup hung).
func lookupTuple(c *conn, proto uint8, src, dst netip.AddrPort) (Entry, uint32, bool) {
	e := Entry{Proto: proto, OrigSrc: src, OrigDst: dst}
	req := nl.NewNetlinkRequest((unix.NFNL_SUBSYS_CTNETLINK<<8)|nl.IPCTNL_MSG_CT_GET, unix.NLM_F_ACK)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: e.family(), Version: nl.NFNETLINK_V0})
	req.AddData(tupleAttr(nl.CTA_TUPLE_ORIG, proto, src, dst))
	msgs, err := c.exec(req)
	if err != nil || len(msgs) == 0 {
		return Entry{}, 0, false
	}
	return parseEntryID(msgs[0])
}

// deleteByID removes exactly the entry with id: the kernel finds it by its
// original tuple and refuses (ENOENT) if the entry there now is another
// one.
func deleteByID(c *conn, e Entry, id uint32) error {
	req := nl.NewNetlinkRequest((unix.NFNL_SUBSYS_CTNETLINK<<8)|nl.IPCTNL_MSG_CT_DELETE, unix.NLM_F_ACK)
	for _, d := range deleteByIDData(e, id) {
		req.AddData(d)
	}
	_, err := c.exec(req)
	return err
}

func deleteByIDData(e Entry, id uint32) []nl.NetlinkRequestData {
	return []nl.NetlinkRequestData{
		&nl.Nfgenmsg{NfgenFamily: e.family(), Version: nl.NFNETLINK_V0},
		tupleAttr(nl.CTA_TUPLE_ORIG, e.Proto, e.OrigSrc, e.OrigDst),
		nl.NewRtAttr(nl.CTA_ID, be32(id)),
	}
}

// parseEntryID reads an entry and its id from a ctnetlink message (after
// the netlink header).
func parseEntryID(data []byte) (Entry, uint32, bool) {
	orig, reply, ok := parseTuples(data)
	if !ok {
		return Entry{}, 0, false
	}
	attrs, err := nl.ParseRouteAttr(data[4:])
	if err != nil {
		return Entry{}, 0, false
	}
	for _, a := range attrs {
		if a.Attr.Type&nl.NLA_TYPE_MASK == nl.CTA_ID && len(a.Value) == 4 {
			e := Entry{Proto: orig.proto, OrigSrc: orig.src, OrigDst: orig.dst, ReplySrc: reply.src, ReplyDst: reply.dst}
			return e, binary.BigEndian.Uint32(a.Value), true
		}
	}
	return Entry{}, 0, false
}

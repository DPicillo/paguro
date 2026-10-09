// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package ctguard

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// ctnetlink multicast groups and tuple attributes
// (include/uapi/linux/netfilter/nfnetlink_compat.h, nfnetlink_conntrack.h).
const (
	groupNew      = 1 // NFNLGRP_CONNTRACK_NEW
	groupDestroy  = 3 // NFNLGRP_CONNTRACK_DESTROY
	ctaTupleIP    = 1
	ctaTupleProto = 2
	ctaIPv4Src    = 1
	ctaIPv4Dst    = 2
	ctaIPv6Src    = 3
	ctaIPv6Dst    = 4
	ctaProtoNum   = 1
	ctaProtoSrc   = 2
	ctaProtoDst   = 3
)

// Set is the guarded entries of one pod on this node; entries can be
// added while it is watched.
type Set struct {
	mu sync.Mutex
	m  map[origKey]Entry
	// byReply: the entries by their reply tuple (RetargetedSet).
	byReply    map[origKey]Entry
	retargeted bool
}

// RetargetedSet guards entries moved to a new pod address (Retarget). Their
// bindings are installed exactly or not at all (the source binding pinned
// even without masquerade), and an entry the new address opens towards a
// binding's reply tuple is removed (Clashing): with the binding gone for a
// moment – kube-proxy's clean-up – the restored server's next datagram to
// a client opens one, the re-install fails on it, and the client's next
// datagram is NATed afresh (measured in the namespace model: the server's
// datagram 3 ms before the re-install, then a new random port with every
// repair until the poll removed it).
func RetargetedSet(entries []Entry) *Set {
	s := &Set{retargeted: true}
	s.Add(entries)
	return s
}

// Add adds entries (a later snapshot wins for the same connection).
func (s *Set) Add(entries []Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[origKey]Entry{}
		s.byReply = map[origKey]Entry{}
	}
	for _, e := range entries {
		s.m[origKey{e.Proto, e.OrigSrc, e.OrigDst}] = e
		s.byReply[origKey{e.Proto, e.ReplySrc, e.ReplyDst}] = e
	}
}

// All returns the entries.
func (s *Set) All() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.m))
	for _, e := range s.m {
		out = append(out, e)
	}
	return out
}

func (s *Set) lookup(k origKey) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	return e, ok
}

// install creates a guarded entry (for a retargeted set pinned, clearing
// what is in its way: installExclusive).
func (s *Set) install(c *conn, e Entry) error {
	if s.retargeted {
		return installExclusive(c, e)
	}
	return createWith(c, e, false)
}

// repairAction is what an event asks for: delete remove (if set, by its
// exact reply tuple), then install want.
type repairAction struct {
	want   Entry
	remove *Entry
}

// react decides what a conntrack event asks for. It converges by reacting
// only to what is wrong: an entry with the guarded binding destroyed
// (re-created), an entry with another binding created (replaced), and for
// a retargeted set an entry created on a binding's reply tuple (removed,
// the binding re-installed). Its own repairs produce exactly the opposite
// events.
func (s *Set) react(msgType uint8, orig origKey, reply replyKey) (repairAction, bool) {
	w, guarded := s.lookup(orig)
	if !guarded {
		if !s.retargeted || msgType != nl.IPCTNL_MSG_CT_NEW {
			return repairAction{}, false
		}
		s.mu.Lock()
		w, clash := s.byReply[orig]
		s.mu.Unlock()
		if !clash {
			return repairAction{}, false
		}
		found := Entry{Proto: orig.proto, OrigSrc: orig.src, OrigDst: orig.dst, ReplySrc: reply.src, ReplyDst: reply.dst}
		return repairAction{want: w, remove: &found}, true
	}
	right := reply == replyKey{w.ReplySrc, w.ReplyDst}
	switch {
	case msgType == nl.IPCTNL_MSG_CT_DELETE && right:
		return repairAction{want: w}, true
	case msgType == nl.IPCTNL_MSG_CT_NEW && !right:
		found := w
		found.ReplySrc, found.ReplyDst = reply.src, reply.dst
		return repairAction{want: w, remove: &found}, true
	}
	return repairAction{}, false
}

// Watch repairs guarded entries the moment the kernel reports them – the
// polling in Ensure is too slow for a client that sends every 33 ms:
// Calico's Felix flushed every entry of the moved address on every node,
// and the client's next packet was NATed afresh within 30 ms. Runs until
// ctx ends; repaired reports each repair. What it repairs: Set.react.
func Watch(ctx context.Context, set *Set, repaired func(Entry, error)) error {
	s, err := nl.Subscribe(unix.NETLINK_NETFILTER, groupNew, groupDestroy)
	if err != nil {
		return err
	}
	defer s.Close()
	// One socket for all repairs; without it, each request opens its own.
	c, err := openConn()
	if err != nil {
		c = nil
	}
	defer c.close()
	fds := []unix.PollFd{{Fd: int32(s.GetFd()), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		n, err := unix.Poll(fds, 100)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if n <= 0 {
			continue
		}
		msgs, _, err := s.Receive()
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.ENOBUFS) {
				continue // ENOBUFS: events lost – the polling in Ensure catches up
			}
			return err
		}
		for _, m := range msgs {
			orig, reply, ok := parseTuples(m.Data)
			if !ok {
				continue
			}
			act, ok := set.react(uint8(m.Header.Type&0xff), orig, reply)
			if !ok {
				continue
			}
			var err error
			if act.remove != nil {
				err = deleteExactOn(c, *act.remove)
			}
			if err == nil || errors.Is(err, syscall.ENOENT) {
				err = set.install(c, act.want)
			}
			if errors.Is(err, syscall.EEXIST) {
				// Re-created meanwhile, or another entry won the race:
				// a wrong binding or a clash shows as NEW and comes next.
				continue
			}
			repaired(act.want, err)
		}
	}
	return nil
}

type replyKey struct{ src, dst netip.AddrPort }

// parseTuples extracts the original direction and the reply addresses of a
// ctnetlink event (IPv4 or IPv6).
func parseTuples(data []byte) (origKey, replyKey, bool) {
	if len(data) < 4 {
		return origKey{}, replyKey{}, false
	}
	attrs, err := nl.ParseRouteAttr(data[4:]) // after struct nfgenmsg
	if err != nil {
		return origKey{}, replyKey{}, false
	}
	var o, r tuple
	var haveO, haveR bool
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case nl.CTA_TUPLE_ORIG:
			o, haveO = parseTuple(a.Value)
		case nl.CTA_TUPLE_REPLY:
			r, haveR = parseTuple(a.Value)
		}
	}
	if !haveO || !haveR {
		return origKey{}, replyKey{}, false
	}
	return origKey(o), replyKey{r.src, r.dst}, true
}

type tuple struct {
	proto    uint8
	src, dst netip.AddrPort
}

func parseTuple(b []byte) (tuple, bool) {
	attrs, err := nl.ParseRouteAttr(b)
	if err != nil {
		return tuple{}, false
	}
	var t tuple
	var sip, dip netip.Addr
	var sport, dport uint16
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case ctaTupleIP:
			ips, err := nl.ParseRouteAttr(a.Value)
			if err != nil {
				return tuple{}, false
			}
			for _, ip := range ips {
				addr, ok := netip.AddrFromSlice(ip.Value)
				switch ip.Attr.Type & nl.NLA_TYPE_MASK {
				case ctaIPv4Src, ctaIPv6Src:
					if ok {
						sip = addr.Unmap()
					}
				case ctaIPv4Dst, ctaIPv6Dst:
					if ok {
						dip = addr.Unmap()
					}
				}
			}
		case ctaTupleProto:
			ps, err := nl.ParseRouteAttr(a.Value)
			if err != nil {
				return tuple{}, false
			}
			for _, p := range ps {
				switch p.Attr.Type & nl.NLA_TYPE_MASK {
				case ctaProtoNum:
					if len(p.Value) > 0 {
						t.proto = p.Value[0]
					}
				case ctaProtoSrc:
					if len(p.Value) >= 2 {
						sport = binary.BigEndian.Uint16(p.Value)
					}
				case ctaProtoDst:
					if len(p.Value) >= 2 {
						dport = binary.BigEndian.Uint16(p.Value)
					}
				}
			}
		}
	}
	if !sip.IsValid() || !dip.IsValid() {
		return tuple{}, false
	}
	t.src, t.dst = netip.AddrPortFrom(sip, sport), netip.AddrPortFrom(dip, dport)
	return t, true
}

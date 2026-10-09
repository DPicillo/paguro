// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Conntrack entries left from an earlier stay of the pod.
//
// A pod that comes back to a node can get an address it held there before
// (the AWS VPC CNI hands a freed address out again after its cooldown). Its
// connections from back then then show the same tuples on the wire again –
// and the node still has their conntrack entries, with the sequence numbers
// of the moment the pod left. Window tracking rates every packet of the
// restored connection INVALID, and kube-proxy drops INVALID packets in
// FORWARD (`-m conntrack --ctstate INVALID -j DROP`), in both directions:
// the connection hangs until the application gives up. Measured on EKS: a
// Minecraft player behind the browser proxy timed out about 15 s after
// every migration back to such an address, while the bots (little traffic,
// still inside the old window) stayed.
//
// The target node deletes these entries before it translates: an entry
// whose tuples are exactly a migrated flow's wire tuple (either direction)
// and its reverse, so never one with NAT – a live entry of kube-proxy keeps
// a ClusterIP or NodePort in it. Without the entry, conntrack picks the
// connection up mid-stream (net.netfilter.nf_conntrack_tcp_loose, on by
// default).

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// FlushStaleConntrack deletes the TCP conntrack entries of netnsPath (""
// = host) that carry one of the wire tuples without NAT, in either
// direction, except the tuples in keep (placeholders other migrations
// hold, see ReserveConntrack). Returns how many went.
func FlushStaleConntrack(netnsPath string, wire, keep []Tuple) (int, error) {
	f := staleFilter{want: map[Tuple]bool{}}
	v4, v6 := false, false
	for _, t := range wire {
		if t.Proto != TCP || t.valid() != nil {
			continue
		}
		t = unmapped(t)
		f.want[t], f.want[t.Reverse()] = true, true
		if t.Src.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	for _, t := range keep {
		t = unmapped(t)
		delete(f.want, t)
		delete(f.want, t.Reverse())
	}
	if len(f.want) == 0 {
		return 0, nil
	}
	total := 0
	err := inNetns(netnsPath, func() error {
		for _, fam := range []struct {
			on  bool
			fam netlink.InetFamily
		}{{v4, unix.AF_INET}, {v6, unix.AF_INET6}} {
			if !fam.on {
				continue
			}
			n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, fam.fam, f)
			total += int(n)
			if err != nil {
				return fmt.Errorf("phantom: conntrack delete: %w", err)
			}
		}
		return nil
	})
	return total, err
}

func unmapped(t Tuple) Tuple {
	u := func(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }
	return Tuple{t.Proto, u(t.Src), u(t.Dst)}
}

type staleFilter struct {
	want map[Tuple]bool // wire tuples, both directions
}

// MatchConntrackFlow: a TCP entry for a wanted tuple whose reply is the
// exact reverse of its original direction (no NAT).
func (f staleFilter) MatchConntrackFlow(c *netlink.ConntrackFlow) bool {
	if c.Forward.Protocol != unix.IPPROTO_TCP {
		return false
	}
	orig, ok1 := ctTuple(c.Forward)
	reply, ok2 := ctTuple(c.Reverse)
	return ok1 && ok2 && reply == orig.Reverse() && f.want[orig]
}

func ctTuple(t netlink.IPTuple) (Tuple, bool) {
	src, ok1 := netip.AddrFromSlice(t.SrcIP)
	dst, ok2 := netip.AddrFromSlice(t.DstIP)
	if !ok1 || !ok2 {
		return Tuple{}, false
	}
	return Tuple{Proto(t.Protocol), netip.AddrPortFrom(src.Unmap(), t.SrcPort), netip.AddrPortFrom(dst.Unmap(), t.DstPort)}, true
}

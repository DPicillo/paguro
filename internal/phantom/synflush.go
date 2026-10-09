// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Connection attempts that went to the old address.
//
// A client that connects to a Service while the pod is frozen is DNAT'ed by
// kube-proxy to the old address – the only endpoint the proxy knows then.
// Its SYN is dropped behind the shield, and its retransmissions stay with
// the old address: the conntrack entry has fixed the backend, and an
// attempt that never got an answer is not one of the harvested flows, so
// nothing translates it. Measured on EKS: a connect() at the freeze hung
// for the client's whole timeout (12 s) although the replacement served
// 1.5 s later. Deleting the entry while it waits for an answer hands the
// next retransmission back to the Service: kube-proxy chooses a backend
// for it again – the replacement, once it is ready.

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// tcpConntrackSynSent is TCP_CONNTRACK_SYN_SENT: a SYN seen, no answer.
const tcpConntrackSynSent = 1

// DropUnansweredSYNs deletes the conntrack entries of this namespace for
// TCP connection attempts that a NAT sent to old and that got no answer for
// a second since their last SYN (a handshake in flight to a live owner of
// the address is never touched). Attempts addressed to old itself are left
// alone: they would go there again.
func DropUnansweredSYNs(old netip.Addr) (int, error) {
	fam := netlink.InetFamily(unix.AF_INET)
	if !old.Is4() {
		fam = unix.AF_INET6
	}
	f := synFilter{old: old.Unmap(), timeout: synSentTimeout()}
	n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, fam, f)
	if err != nil {
		return int(n), fmt.Errorf("phantom: conntrack delete: %w", err)
	}
	return int(n), nil
}

// synSentTimeout is the conntrack timeout of an unanswered SYN, in
// seconds; every SYN of the attempt starts it again.
func synSentTimeout() uint32 {
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent")
	if err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil && v > 1 {
			return uint32(v)
		}
	}
	return 120
}

type synFilter struct {
	old     netip.Addr
	timeout uint32 // synSentTimeout
}

// MatchConntrackFlow: an unanswered TCP attempt whose reply would come
// from old although the client addressed something else (a ClusterIP, a
// NodePort), at least a second after its last SYN.
func (f synFilter) MatchConntrackFlow(c *netlink.ConntrackFlow) bool {
	if c.Forward.Protocol != unix.IPPROTO_TCP {
		return false
	}
	tcp, ok := c.ProtoInfo.(*netlink.ProtoInfoTCP)
	if !ok || tcp.State != tcpConntrackSynSent || c.TimeOut+1 > f.timeout {
		return false
	}
	replySrc, ok1 := netip.AddrFromSlice(c.Reverse.SrcIP)
	origDst, ok2 := netip.AddrFromSlice(c.Forward.DstIP)
	return ok1 && ok2 && replySrc.Unmap() == f.old && origDst.Unmap() != f.old
}

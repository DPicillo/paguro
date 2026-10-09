// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TCP states (include/net/tcp_states.h).
const (
	tcpEstablished = 1
	tcpSynSent     = 2
	tcpSynRecv     = 3
	tcpFinWait1    = 4
	tcpFinWait2    = 5
	tcpTimeWait    = 6
	tcpClose       = 7
	tcpCloseWait   = 8
	tcpLastAck     = 9
	tcpListen      = 10
	tcpClosing     = 11
)

// harvestedState reports whether a socket in this state is a connection
// that a restore keeps alive (and therefore needs translation).
func harvestedState(s uint8) bool {
	switch s {
	case tcpEstablished, tcpSynSent, tcpSynRecv, tcpFinWait1, tcpFinWait2, tcpCloseWait, tcpLastAck, tcpClosing:
		return true
	}
	return false
}

func addrPort(ip net.IP, port uint16) (netip.AddrPort, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), port), true
}

// sockDiag lists the TCP and UDP sockets that can carry localIP's family in
// a network namespace. For an IPv4 address that includes AF_INET6 sockets:
// dual-stack servers (Go, Java, Node listening on ":port") accept IPv4
// clients on IPv6 sockets with v4-mapped addresses (::ffff:a.b.c.d);
// addrPort unmaps them. The netlink handle API only opens route/xfrm/
// netfilter sockets in a foreign netns, so the dump runs on a thread
// switched into the namespace.
func sockDiag(path string, localIP netip.Addr) (tcp, udp []*netlink.Socket, err error) {
	fams := []uint8{unix.AF_INET, unix.AF_INET6}
	if localIP.Is6() && !localIP.Is4In6() {
		fams = []uint8{unix.AF_INET6}
	}
	err = inNetns(path, func() error {
		for _, fam := range fams {
			t, e := netlink.SocketDiagTCP(fam)
			if e != nil {
				return fmt.Errorf("phantom: sock_diag tcp: %w", e)
			}
			u, e := netlink.SocketDiagUDP(fam)
			if e != nil {
				return fmt.Errorf("phantom: sock_diag udp: %w", e)
			}
			tcp, udp = append(tcp, t...), append(udp, u...)
		}
		return nil
	})
	return tcp, udp, err
}

// BoundAddrs returns the distinct local addresses that sockets in a pod
// network namespace are bound to – listeners and connections, both
// families, v4-mapped addresses unmapped – except wildcard and loopback.
// After a migration with a new IP, a pod's sockets can still be bound to
// any earlier IP; a restore must configure all of them first, or CRIU fails
// with "Can't bind inet socket back".
func BoundAddrs(netnsPath string) ([]netip.Addr, error) {
	var socks []*netlink.Socket
	err := inNetns(netnsPath, func() error {
		for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
			t, err := netlink.SocketDiagTCP(fam)
			if err != nil {
				return fmt.Errorf("phantom: sock_diag tcp: %w", err)
			}
			u, err := netlink.SocketDiagUDP(fam)
			if err != nil {
				return fmt.Errorf("phantom: sock_diag udp: %w", err)
			}
			socks = append(append(socks, t...), u...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, s := range socks {
		a, ok := netip.AddrFromSlice(s.ID.Source)
		if !ok {
			continue
		}
		a = a.Unmap()
		if a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

// HarvestFlows lists the connections in a pod network namespace whose local
// address is localIP: TCP connections in a state CRIU restores, and
// connected UDP sockets. Call it while the pod is frozen (after the CRIU
// network lock), so the list is final. Peers are classified ClassInCluster;
// the caller reclassifies external peers.
func HarvestFlows(netnsPath string, localIP netip.Addr) ([]Flow, error) {
	tcp, udp, err := sockDiag(netnsPath, localIP)
	if err != nil {
		return nil, err
	}
	// Listening ports decide which side initiated a flow.
	listenTCP, boundUDP := map[uint16]bool{}, map[uint16]bool{}
	for _, s := range tcp {
		if s.State == tcpListen {
			listenTCP[s.ID.SourcePort] = true
		}
	}
	for _, s := range udp {
		if s.ID.DestinationPort == 0 {
			boundUDP[s.ID.SourcePort] = true
		}
	}
	var out []Flow
	for _, s := range tcp {
		if !harvestedState(s.State) {
			continue
		}
		if f, ok := sockFlow(TCP, s, localIP); ok {
			f.Server = listenTCP[f.Local.Port()]
			out = append(out, f)
		}
	}
	for _, s := range udp {
		// Only connected UDP sockets have a peer we can translate.
		if s.ID.DestinationPort == 0 || s.ID.Destination.IsUnspecified() {
			continue
		}
		if f, ok := sockFlow(UDP, s, localIP); ok {
			f.Server = boundUDP[f.Local.Port()]
			out = append(out, f)
		}
	}
	return out, nil
}

func sockFlow(p Proto, s *netlink.Socket, localIP netip.Addr) (Flow, bool) {
	l, ok1 := addrPort(s.ID.Source, s.ID.SourcePort)
	r, ok2 := addrPort(s.ID.Destination, s.ID.DestinationPort)
	if !ok1 || !ok2 || l.Addr() != localIP.Unmap() {
		return Flow{}, false
	}
	return Flow{Proto: p, Local: l, Remote: r}, true
}

// ResolveWithConntrack fills Flow.Wire for flows the OLD node's kernel
// conntrack DNAT'ed (the pod connected to a ClusterIP and kube-proxy picked a
// backend), and marks flows the old node masqueraded towards an address
// outside clusterNets as ClassExternalSNAT. Run it in the old node's host
// network namespace (netnsPath "" = current). Flows not found in conntrack
// are returned unchanged.
func ResolveWithConntrack(netnsPath string, flows []Flow, clusterNets []netip.Prefix) ([]Flow, error) {
	type k struct {
		p    Proto
		l, r netip.AddrPort
	}
	ct := map[k]*netlink.ConntrackFlow{}
	var all []*netlink.ConntrackFlow
	err := inNetns(netnsPath, func() error {
		for _, fam := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
			list, err := netlink.ConntrackTableList(netlink.ConntrackTable, fam)
			if err != nil {
				return fmt.Errorf("phantom: conntrack dump: %w", err)
			}
			all = append(all, list...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	{
		for _, c := range all {
			l, ok1 := addrPort(c.Forward.SrcIP, c.Forward.SrcPort)
			r, ok2 := addrPort(c.Forward.DstIP, c.Forward.DstPort)
			if ok1 && ok2 {
				ct[k{Proto(c.Forward.Protocol), l, r}] = c
			}
		}
	}
	inCluster := func(a netip.Addr) bool {
		for _, n := range clusterNets {
			if n.Contains(a) {
				return true
			}
		}
		return false
	}
	out := make([]Flow, len(flows))
	copy(out, flows)
	for i := range out {
		c := ct[k{out[i].Proto, out[i].Local, out[i].Remote}]
		if c == nil {
			continue
		}
		replySrc, ok1 := addrPort(c.Reverse.SrcIP, c.Reverse.SrcPort)
		replyDst, ok2 := addrPort(c.Reverse.DstIP, c.Reverse.DstPort)
		if !ok1 || !ok2 {
			continue
		}
		if replySrc != out[i].Remote {
			out[i].Wire = replySrc // DNAT: the real peer
		}
		if replyDst != out[i].Local && !inCluster(replySrc.Addr()) {
			out[i].Class = ClassExternalSNAT
		}
	}
	return out, nil
}

// LiveFlows returns the subset of flows whose socket still exists in the
// migrated pod (any state except LISTEN/CLOSE, including TIME_WAIT). Used by
// the target agent for exact garbage collection: a flow whose socket is gone
// needs no translation anymore, on any node.
func LiveFlows(netnsPath string, localIP netip.Addr, flows []Flow) (live, dead []Flow, err error) {
	type k struct {
		p    Proto
		l, r netip.AddrPort
	}
	have := map[k]bool{}
	tcp, udp, err := sockDiag(netnsPath, localIP)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range tcp {
		if s.State == tcpListen || s.State == tcpClose {
			continue
		}
		l, _ := addrPort(s.ID.Source, s.ID.SourcePort)
		r, _ := addrPort(s.ID.Destination, s.ID.DestinationPort)
		have[k{TCP, l, r}] = true
	}
	for _, s := range udp {
		l, _ := addrPort(s.ID.Source, s.ID.SourcePort)
		r, _ := addrPort(s.ID.Destination, s.ID.DestinationPort)
		have[k{UDP, l, r}] = true
	}
	for _, f := range flows {
		if have[k{f.Proto, f.Local, f.Remote}] {
			live = append(live, f)
		} else {
			dead = append(dead, f)
		}
	}
	return live, dead, nil
}

// Classify marks flows whose wire peer is outside clusterNets (pod CIDRs,
// node addresses, service CIDR) as external. Flows already marked
// ClassExternalSNAT keep that class.
func Classify(flows []Flow, clusterNets []netip.Prefix) []Flow {
	out := make([]Flow, len(flows))
	copy(out, flows)
	for i := range out {
		if out[i].Class != ClassInCluster {
			continue
		}
		a := out[i].wire().Addr()
		in := false
		for _, n := range clusterNets {
			if n.Contains(a) {
				in = true
				break
			}
		}
		if !in {
			out[i].Class = ClassExternalDirect
		}
	}
	return out
}

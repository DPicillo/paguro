// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// UDPServerPorts lists the ports of the unconnected UDP sockets in a pod
// network namespace that can receive datagrams for localIP: game servers,
// QUIC, DNS. They have no peer to harvest; their clients' NAT bindings are
// moved to the new IP on every node instead (internal/ctguard, rebind.go).
// For an IPv4 address that includes AF_INET6 sockets (dual-stack servers on
// "[::]:port"). Same definition as criuimg.Sockets.UDPServerPorts, read
// from the live sockets.
func UDPServerPorts(netnsPath string, localIP netip.Addr) ([]uint16, error) {
	fams := []uint8{unix.AF_INET, unix.AF_INET6}
	if !localIP.Unmap().Is4() {
		fams = []uint8{unix.AF_INET6}
	}
	var socks []*netlink.Socket
	err := inNetns(netnsPath, func() error {
		for _, fam := range fams {
			u, err := netlink.SocketDiagUDP(fam)
			if err != nil {
				return fmt.Errorf("phantom: sock_diag udp: %w", err)
			}
			socks = append(socks, u...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return udpServerPorts(socks, localIP), nil
}

// udpServerPorts: unconnected, bound to a port, not to loopback, and bound
// to localIP or a wildcard address.
func udpServerPorts(socks []*netlink.Socket, localIP netip.Addr) []uint16 {
	local := localIP.Unmap()
	var out []uint16
	for _, s := range socks {
		if s.ID.DestinationPort != 0 || s.ID.SourcePort == 0 {
			continue // connected (harvested as a flow) or not bound
		}
		if d, ok := netip.AddrFromSlice(s.ID.Destination); ok && !d.Unmap().IsUnspecified() {
			continue
		}
		a, ok := netip.AddrFromSlice(s.ID.Source)
		if !ok {
			continue
		}
		if a = a.Unmap(); !a.IsUnspecified() && a != local {
			continue // loopback, an earlier IP, another address
		}
		if !slices.Contains(out, s.ID.SourcePort) {
			out = append(out, s.ID.SourcePort)
		}
	}
	slices.Sort(out)
	return out
}

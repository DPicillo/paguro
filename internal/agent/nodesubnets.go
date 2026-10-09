// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
)

// nodeSubnets lists the IPv4 subnets of the node's network devices – the
// interfaces backed by a device (an ENI, a virtual NIC), not veths, bridges,
// tunnels or dummies. With a VPC-native CNI (AWS VPC CNI, Azure CNI) the
// pods' addresses come from these subnets: on EKS, the node's ENIs are
// enp39s0 and enp40s0 in 192.168.64.0/19, the pods' veths eni*, and no
// Kubernetes object names the range.
func nodeSubnets(sysNet string) ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range links {
		name := l.Attrs().Name
		if _, err := os.Stat(filepath.Join(sysNet, name, "device")); err != nil {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if p := subnetOf(a.IPNet.String()); p != "" && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// subnetOf masks an address with its prefix length ("192.168.78.222/19" →
// "192.168.64.0/19"); "" for loopback, link-local and host routes.
func subnetOf(cidr string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Bits() == p.Addr().BitLen() {
		return ""
	}
	return p.Masked().String()
}

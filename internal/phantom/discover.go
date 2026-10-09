// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Node discovery for the agent: which addresses and devices this node has,
// where a pod's interfaces are, and which flows a local peer reaches through
// a kernel DNAT. Everything here runs in the caller's network namespace
// (the agent uses hostNetwork) unless a pod netns path is given.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// overlayDevices are devices CNIs route pod traffic through. Host-scope
// rules need programs on every one that exists (docs/PHANTOM-MODE.md 4.2).
var overlayDevices = []string{
	"cilium_host", "cilium_vxlan", "cilium_geneve", // Cilium
	"vxlan.calico", "vxlan-v6.calico", "tunl0", // Calico
	"flannel.1", "flannel-v6.1", // flannel
	"antrea-gw0", "ovn-k8s-mp0", // OVS CNIs: Antrea's and OVN-Kubernetes' host gateway port
}

// ovsTunnelDevices are the kernel devices of Open vSwitch tunnel ports
// (Antrea, OVN-Kubernetes, Kube-OVN). OVS picks the remote node in its own
// flow tables – for a Service connection after its own DNAT – and hands the
// inner packet to this device, so host-scope rules must run on its egress
// and rewrite the tunnel endpoint as well.
var ovsTunnelDevices = []string{"genev_sys_6081", "vxlan_sys_4789", "gre_sys", "stt_sys_7471"}

// tunnelDevices are collect_md overlay devices whose tunnel endpoint the CNI
// picks before tc egress runs (FlagTunnel).
var tunnelDevices = append([]string{"cilium_vxlan", "cilium_geneve"}, ovsTunnelDevices...)

func init() { overlayDevices = append(overlayDevices, ovsTunnelDevices...) }

// HostAddrs returns every address configured in this network namespace.
func HostAddrs() (map[netip.Addr]bool, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("phantom: list addresses: %w", err)
	}
	out := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out[ip.Unmap()] = true
		}
	}
	return out, nil
}

// HostDevices returns the devices that carry traffic to and from pods on
// this node: the output devices of the routes to dests (typically the old
// and new pod IP), the CNI's overlay devices and the devices of the default
// routes – in every routing table, not only the main one.
//
// Policy routing puts pod traffic on devices the main table never names.
// The AWS VPC CNI routes a pod whose address belongs to a secondary ENI out
// of that ENI (`from <pod> lookup <n>`, table n: default via the ENI), and
// replies arrive on it. Measured on EKS: with programs only on the primary
// ENI, every connection of a client pod on a secondary ENI that went
// through a ClusterIP (host scope) was lost on every migration – its
// packets left untranslated, to the old address, and the server's replies
// were not translated back; client pods on the primary ENI kept theirs.
func HostDevices(dests ...netip.Addr) ([]string, error) {
	var kernel []int
	for _, d := range dests {
		routes, err := netlink.RouteGet(net.IP(d.AsSlice()))
		if err != nil {
			continue // no route (e.g. unreachable from here): nothing to add
		}
		for _, r := range routes {
			if r.Type == unix.RTN_UNICAST {
				kernel = append(kernel, r.LinkIndex)
			}
		}
	}
	var all []netlink.Route
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Table RT_TABLE_UNSPEC with the table filter: every table.
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		if err == nil {
			all = append(all, routes...)
		}
	}
	links := map[int]netlink.Link{}
	if ls, err := netlink.LinkList(); err == nil {
		for _, l := range ls {
			links[l.Attrs().Index] = l
		}
	}
	out := pickHostDevices(dests, kernel, all, links)
	if len(out) == 0 {
		return nil, errors.New("phantom: no device carries pod traffic")
	}
	return out, nil
}

// pickHostDevices is the selection of HostDevices: the devices of kernel
// (the route lookups for dests), of every unicast route in any table but
// the local one that is a default route or covers one of dests (with
// multipath next hops), and every overlay device that exists. Loopback and
// the host side of pod interfaces never count.
func pickHostDevices(dests []netip.Addr, kernel []int, routes []netlink.Route, links map[int]netlink.Link) []string {
	set := map[string]bool{}
	add := func(idx int) {
		l, ok := links[idx]
		if idx <= 0 || !ok || l.Attrs().Name == "lo" || isPodInterface(l) {
			return
		}
		set[l.Attrs().Name] = true
	}
	for _, idx := range kernel {
		add(idx)
	}
	covers := func(n *net.IPNet) bool {
		if n == nil || isDefault(n) {
			return true
		}
		p, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			return false
		}
		ones, _ := n.Mask.Size()
		pfx := netip.PrefixFrom(p.Unmap(), ones)
		for _, d := range dests {
			if pfx.Contains(d) {
				return true
			}
		}
		return false
	}
	for _, r := range routes {
		if r.Table == unix.RT_TABLE_LOCAL || (r.Type != unix.RTN_UNICAST && r.Type != 0) || !covers(r.Dst) {
			continue
		}
		add(r.LinkIndex)
		for _, nh := range r.MultiPath { // ECMP
			add(nh.LinkIndex)
		}
	}
	for _, l := range links {
		if slices.Contains(overlayDevices, l.Attrs().Name) {
			set[l.Attrs().Name] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// isPodInterface reports whether l is the host side of a pod interface: a
// veth or netkit whose peer lives in another network namespace. (Cilium's
// cilium_host/cilium_net pair lives entirely in the host namespace.) The
// route to a local pod points at it; host-scope programs do not belong there.
func isPodInterface(l netlink.Link) bool {
	switch l.Type() {
	case "veth", "netkit":
		return l.Attrs().NetNsID >= 0
	}
	return false
}

func isDefault(n *net.IPNet) bool {
	ones, _ := n.Mask.Size()
	return ones == 0
}

// TunnelRewriteNeeded reports whether this node has a collect_md overlay
// device (Cilium tunnel mode, Open vSwitch tunnel ports).
func TunnelRewriteNeeded() bool {
	for _, name := range tunnelDevices {
		if _, err := netlink.LinkByName(name); err == nil {
			return true
		}
	}
	return false
}

// OnLinkIn reports whether a is on-link inside netnsPath: the route to it
// has no gateway and leaves through a real interface.
func OnLinkIn(netnsPath string, a netip.Addr) bool {
	onLink := false
	_ = inNetns(netnsPath, func() error {
		rs, err := netlink.RouteGet(net.IP(a.AsSlice()))
		if err == nil && len(rs) > 0 && rs[0].Gw == nil && rs[0].LinkIndex > 1 {
			onLink = rs[0].Type == unix.RTN_UNICAST || rs[0].Type == 0
		}
		return err
	})
	return onLink
}

// PodEndpointOf locates a pod interface: ifname inside netnsPath and its
// veth peer in this (host) namespace. The peer name stays empty for
// interfaces that are not veths (e.g. netkit, ipvlan).
func PodEndpointOf(netnsPath, ifname string) (PodEndpoint, error) {
	ep := PodEndpoint{Netns: netnsPath, Ifname: ifname}
	var peer int
	err := inNetns(netnsPath, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			return err
		}
		peer = l.Attrs().ParentIndex // IFLA_LINK: the peer's ifindex
		return nil
	})
	if err != nil {
		return ep, fmt.Errorf("phantom: %s in %s: %w", ifname, netnsPath, err)
	}
	if peer > 0 {
		if l, err := netlink.LinkByIndex(peer); err == nil {
			ep.HostIfname = l.Attrs().Name
		}
	}
	return ep, nil
}

// PodAddr returns the global address of the given family on ifname inside
// netnsPath (the replacement pod's new IP).
func PodAddr(netnsPath, ifname string, v4 bool) (netip.Addr, error) {
	var out netip.Addr
	err := inNetns(netnsPath, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			return err
		}
		fam := netlink.FAMILY_V6
		if v4 {
			fam = netlink.FAMILY_V4
		}
		addrs, err := netlink.AddrList(l, fam)
		if err != nil {
			return err
		}
		for _, a := range addrs {
			if a.Scope != unix.RT_SCOPE_UNIVERSE {
				continue
			}
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				out = ip.Unmap()
				return nil
			}
		}
		return errors.New("no global address")
	})
	if err != nil {
		return out, fmt.Errorf("phantom: address of %s in %s: %w", ifname, netnsPath, err)
	}
	return out, nil
}

// ViaNetfilter returns, from this node's conntrack table, which flows a
// local peer reaches through a kernel DNAT (kube-proxy ClusterIP/NodePort):
// the reply comes from the migrated pod's (old) local address while the
// original destination was something else. Those flows need host-scope rules. Nil
// means "none" (e.g. Cilium socket-LB, which leaves no DNAT state).
func ViaNetfilter(flows []Flow) (func(Flow) bool, error) {
	// The migrated pod's own addresses: usually one, more after chained
	// migrations (sockets bound to an earlier IP).
	olds := map[netip.Addr]bool{}
	for _, f := range flows {
		olds[f.Local.Addr()] = true
	}
	if len(olds) == 0 {
		return nil, nil
	}
	fam := netlink.InetFamily(unix.AF_INET)
	if !flows[0].Local.Addr().Is4() {
		fam = unix.AF_INET6
	}
	entries, err := netlink.ConntrackTableList(netlink.ConntrackTable, fam)
	if err != nil {
		return nil, fmt.Errorf("phantom: conntrack: %w", err)
	}
	type key struct {
		proto      Proto
		pod, local netip.AddrPort
	}
	dnat := map[key]bool{}
	for _, e := range entries {
		rs, ok1 := netip.AddrFromSlice(e.Reverse.SrcIP)
		rd, ok2 := netip.AddrFromSlice(e.Reverse.DstIP)
		od, ok3 := netip.AddrFromSlice(e.Forward.DstIP)
		if !ok1 || !ok2 || !ok3 || !olds[rs.Unmap()] {
			continue
		}
		replySrc := netip.AddrPortFrom(rs.Unmap(), e.Reverse.SrcPort)
		origDst := netip.AddrPortFrom(od.Unmap(), e.Forward.DstPort)
		if origDst == replySrc {
			continue // no DNAT
		}
		dnat[key{Proto(e.Forward.Protocol), replySrc, netip.AddrPortFrom(rd.Unmap(), e.Reverse.DstPort)}] = true
	}
	if len(dnat) == 0 {
		return nil, nil
	}
	return func(f Flow) bool {
		return dnat[key{f.Proto, f.Local, f.wire()}]
	}, nil
}

// KillFlows aborts the TCP sockets of flows inside netnsPath (SOCK_DESTROY):
// the application sees ECONNABORTED and reconnects at once instead of
// waiting for a timeout on a connection that cannot survive. An IPv4 flow
// may live on an AF_INET6 socket with v4-mapped addresses (dual-stack
// servers), so both families are tried. Returns the number of sockets
// destroyed.
func KillFlows(netnsPath string, flows []Flow) (int, error) {
	n := 0
	var errs []error
	err := inNetns(netnsPath, func() error {
		for _, f := range flows {
			if f.Proto != TCP {
				continue
			}
			fams := []uint8{unix.AF_INET6}
			if f.Local.Addr().Is4() {
				fams = []uint8{unix.AF_INET, unix.AF_INET6}
			}
			var last error
			for _, fam := range fams {
				if last = destroySocket(fam, f.Local, f.Remote); last == nil {
					n++
					break
				}
			}
			if last != nil {
				errs = append(errs, fmt.Errorf("%v: %w", f, last))
			}
		}
		return nil
	})
	return n, errors.Join(err, errors.Join(errs...))
}

// inetDiagReq is struct inet_diag_req_v2 (linux/inet_diag.h).
type inetDiagReq struct {
	family     uint8
	local, rem netip.AddrPort
}

func (r *inetDiagReq) Len() int { return 56 }

func (r *inetDiagReq) Serialize() []byte {
	b := make([]byte, r.Len())
	b[0] = r.family
	b[1] = unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(b[4:], 0xffffffff) // all states (host order)
	binary.BigEndian.PutUint16(b[8:], r.local.Port())
	binary.BigEndian.PutUint16(b[10:], r.rem.Port())
	put := func(off int, a netip.Addr) {
		if r.family == unix.AF_INET {
			v := a.As4()
			copy(b[off:], v[:])
		} else {
			v := a.As16() // v4-mapped for an IPv4 address
			copy(b[off:], v[:])
		}
	}
	put(12, r.local.Addr())
	put(28, r.rem.Addr())
	// interface 0 (any); cookie INET_DIAG_NOCOOKIE (host order)
	binary.NativeEndian.PutUint32(b[48:], 0xffffffff)
	binary.NativeEndian.PutUint32(b[52:], 0xffffffff)
	return b
}

// destroySocket sends one SOCK_DESTROY in the current network namespace.
func destroySocket(fam uint8, local, remote netip.AddrPort) error {
	req := nl.NewNetlinkRequest(nl.SOCK_DESTROY, unix.NLM_F_ACK)
	req.AddData(&inetDiagReq{family: fam, local: local, rem: remote})
	_, err := req.Execute(unix.NETLINK_INET_DIAG, 0)
	return err
}

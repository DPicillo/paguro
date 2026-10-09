// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Off-link routes for an old address.
//
// tc programs run on egress, i.e. after the kernel's routing decision and
// neighbour resolution. On the node a pod was migrated away from, its old
// address belongs to a local range: Flannel's bridge subnet (on-link, the
// kernel ARPs for it and the entry goes FAILED once the pod is gone) or
// Calico's IPAM block (a blackhole route once the pod's /32 is removed).
// Packets to the old address are then dropped before any tc program can
// translate them – measured with Flannel: a peer pod on the old node lost
// its connection, its neighbour entry for the old IP was FAILED.
//
// So wherever translation needs packets addressed to the old IP to leave
// (host scope on a node, and peer pods whose route to it is on-link), the
// old /32 is routed exactly like the new address – through the new
// address's gateway, or through the new address itself when that is
// on-link. The route carries Paguro's protocol number, so it can be removed
// reliably and is replaced (not kept) when the pod moves on.
//
// The route steers the translated connections only, never the address:
// it lives in a table of its own (SteerTable), which only the translated
// flows select – by their exact tuple (source and destination address and
// port, protocol), through a mark or a policy rule of their own
// (steer.go). A pod that receives the old address later (IP reuse) is
// reached through the CNI's routes as if Paguro were not there
// (docs/PHANTOM-MODE.md 3.1). The first version put the
// /32 into the main table; it beat the CNI's subnet route by prefix length,
// whatever its metric. Measured on EKS: the AWS VPC CNI gave the old
// address to another pod after its cooldown, and every connection from the
// peer node to that pod went to the migrated pod's node and was lost, as
// long as the migrated connections lived.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RouteProtocol marks Paguro's routes (rtnetlink protocol number).
const RouteProtocol netlink.RouteProtocol = 0x7a

// routeMetric: below any CNI route for the same prefix (the main table of
// earlier versions, where removal still looks).
const routeMetric = 4242

// SteerTable is the routing table of Paguro's routes for old addresses;
// SteerPriority is the priority of the per-flow policy rules that select it
// for local sockets (steer.go; the gate and the mark rule for forwarded
// flows sit right before and after it). Before the rules of CNIs that route
// pods by policy (the AWS VPC CNI: 512 and up, Cilium's ENI mode: 110), so
// that a flow is steered whatever the CNI's tables say about the old
// address – also when a pod on this node has received it.
const (
	SteerTable    = 4242
	SteerPriority = 80
)

// EnsureOffLinkRoute makes old routable like like (typically the new pod
// IP) inside netnsPath ("" = this namespace, the host's for the agent),
// unless a CNI route already takes old through a gateway – then Paguro's
// route is removed if present: a CNI route that came back (it was gone
// for a moment) must not stay shadowed by a more specific /32. Returns
// whether a route was installed.
func EnsureOffLinkRoute(netnsPath string, old, like netip.Addr) (bool, error) {
	return ensureOffLinkRoute(netnsPath, netnsPath == "", old, like)
}

// ensureOffLinkRoute: host tells whether netnsPath is a node's host
// namespace (see cniRoute).
func ensureOffLinkRoute(netnsPath string, host bool, old, like netip.Addr) (bool, error) {
	installed := false
	err := inNetns(netnsPath, func() error {
		// Decide on the CNI's own route: Paguro's may be there already,
		// from an earlier migration of this pod or from a moment the CNI
		// route was gone.
		cur, found, err := cniBest(old)
		if err != nil {
			return err
		}
		if old == like || (found && cniRoute(cur, host)) {
			// Back at the old address (a chain that returns to it), or the
			// CNI routes it: nothing to steer.
			return delOwnRoute(old)
		}
		if host {
			// NEW must be reachable through a route of its own; copying
			// the default route would send OLD out of the cluster (the
			// CNI's route to NEW may not be there yet – retried later).
			if lr, ok, err := cniBest(like); err != nil || !ok || lr.Dst == nil || isDefault(lr.Dst) {
				return fmt.Errorf("phantom: no cluster route to %s yet", like)
			}
		}
		ref, err := netlink.RouteGet(net.IP(like.AsSlice()))
		if err != nil || len(ref) == 0 {
			return fmt.Errorf("phantom: no route to %s: %w", like, err)
		}
		r := netlink.Route{
			Dst:       prefixOf(old),
			Gw:        ref[0].Gw,
			LinkIndex: ref[0].LinkIndex,
			Protocol:  RouteProtocol,
			Priority:  routeMetric,
			Table:     SteerTable,
			Flags:     int(netlink.FLAG_ONLINK),
		}
		if r.Gw == nil {
			// The new address is on-link here too (the pod came back to
			// this bridge): use it as the next hop. It answers ARP, the
			// frame reaches the new pod, and the tc program rewrites the
			// destination IP on the way. The kernel also reports no
			// gateway when the route's next hop is an address of this
			// host – Cilium's router IP on cilium_host, a NOARP device
			// where the next hop does not matter.
			r.Gw = net.IP(like.AsSlice())
		}
		if err := netlink.RouteReplace(&r); err != nil {
			return fmt.Errorf("phantom: route %s like %s: %w", old, like, err)
		}
		installed = true
		// An earlier version's route in the main table steered every
		// connection to the address.
		return delMainRoute(old)
	})
	return installed, err
}

// cniRoute reports whether r, the route old currently takes, is a CNI's
// route for a pod network: unicast through a gateway, and not Paguro's own
// (that one must follow the pod to its newest address). In the host
// namespace the default route does not count: it leads out of the cluster,
// and an old address ends up there once the route of its pod subnet is gone
// – the old node was deleted, or Cilium released a /32 pool. In a pod the
// default route is the CNI's way to everything.
func cniRoute(r netlink.Route, host bool) bool {
	if r.Protocol == RouteProtocol || !viaGateway(r) || r.Type != unix.RTN_UNICAST {
		return false
	}
	if !host {
		return true
	}
	if r.Dst == nil {
		return false
	}
	ones, _ := r.Dst.Mask.Size()
	return ones > 0
}

// viaGateway: the route has a gateway – or several (multipath, as with
// ECMP routes of BGP fabrics), all with a gateway.
func viaGateway(r netlink.Route) bool {
	if r.Gw != nil {
		return true
	}
	if len(r.MultiPath) == 0 {
		return false
	}
	for _, nh := range r.MultiPath {
		if nh.Gw == nil {
			return false
		}
	}
	return true
}

// RoutedIntoCluster reports whether a route of the main table other than
// Paguro's own and the default route covers old in this network namespace
// (the host's, for the agent): the CNI's route of its pod subnet, or a
// blackhole for a node's own block. False means old would leave the
// cluster. Where pod addresses are routed by the network itself (VPC CNIs:
// the default route) it is false from the start; callers look for the
// change from true to false.
func RoutedIntoCluster(old netip.Addr) (bool, error) {
	r, found, err := cniBest(old)
	if err != nil || !found || r.Dst == nil {
		return false, err
	}
	ones, _ := r.Dst.Mask.Size()
	return ones > 0, nil
}

// cniBest returns the most specific route of the main table for a that is
// not Paguro's own (the lowest metric among equally specific ones).
func cniBest(a netip.Addr) (netlink.Route, bool, error) {
	fam := netlink.FAMILY_V4
	if a.Is6() {
		fam = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return netlink.Route{}, false, err
	}
	var best netlink.Route
	bestLen := -1
	for _, r := range routes {
		if r.Protocol == RouteProtocol {
			continue
		}
		l := 0
		if r.Dst != nil {
			ones, _ := r.Dst.Mask.Size()
			p, ok := netip.AddrFromSlice(r.Dst.IP)
			if !ok || !netip.PrefixFrom(p.Unmap(), ones).Contains(a) {
				continue
			}
			l = ones
		}
		if l > bestLen || (l == bestLen && r.Priority < best.Priority) {
			best, bestLen = r, l
		}
	}
	return best, bestLen >= 0, nil
}

// RemoveOffLinkRoute removes Paguro's route for old (no error if gone).
func RemoveOffLinkRoute(netnsPath string, old netip.Addr) error {
	return inNetns(netnsPath, func() error { return delOwnRoute(old) })
}

// delOwnRoute removes Paguro's route for old in this namespace, if any –
// in its own table and in the main table (earlier versions).
func delOwnRoute(old netip.Addr) error {
	err := netlink.RouteDel(&netlink.Route{Dst: prefixOf(old), Protocol: RouteProtocol, Priority: routeMetric, Table: SteerTable})
	if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("phantom: removing route %s: %w", old, err)
	}
	return delMainRoute(old)
}

func delMainRoute(old netip.Addr) error {
	err := netlink.RouteDel(&netlink.Route{Dst: prefixOf(old), Protocol: RouteProtocol, Priority: routeMetric})
	if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("phantom: removing route %s: %w", old, err)
	}
	return nil
}

func prefixOf(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

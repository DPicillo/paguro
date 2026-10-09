// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"paguro.dev/paguro/internal/netadapter"
)

// Cilium's host routes for kept addresses. Every Cilium agent installs a
// route "<cidr> via <cilium_host> dev cilium_host" for each pod CIDR any
// node holds – Paguro's sticky pools are single /32s – and deletes it when
// a node gives the CIDR up. Cilium keys these routes by prefix only: while
// a kept address moves, two pool generations hold the same /32 on two
// nodes, and the first one released (the source's old generation after a
// migration, the prepared one after a rollback) deletes the route the other
// still needs – on every node, the pod's own included. Measured (Cilium
// 1.20, tunnel mode): back after 60–130 s. Pod and Service traffic does not
// notice (eBPF datapath), but everything the host sends to the pod does:
// kubelet's liveness and readiness probes failed, and kubelet would restart
// a just-migrated container or take it out of its Services.
//
// The route keeper restores the route at once: for every /32 of a Paguro
// pool that a CiliumNode still holds, a route like Cilium's (on the node
// that holds it without, elsewhere with the tunnel MTU of Cilium's other
// routes). It reacts to route deletions (netlink) within milliseconds and
// checks every routeKeeperInterval. It never deletes anything.

const routeKeeperInterval = 10 * time.Second

var ciliumNodeGVK = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNodeList"}

// RunRouteKeeper keeps the routes until ctx ends (Cilium only).
func (a *Agent) RunRouteKeeper(ctx context.Context) {
	if _, err := netlink.LinkByName("cilium_host"); err != nil {
		a.Log.Info("route keeper off: no cilium_host", "err", err)
		return
	}
	var mu sync.Mutex
	var want map[netip.Prefix]bool
	keep := func() {
		// Looked up each time: Cilium may re-create the device.
		link, err := netlink.LinkByName("cilium_host")
		if err != nil {
			a.Log.Warn("route keeper: cilium_host", "err", err)
			return
		}
		mu.Lock()
		w := want
		mu.Unlock()
		a.keepRoutes(link, w)
	}
	// The wanted routes come from the API (up to a second): listed
	// periodically and after a deletion, off the event loop – a slow
	// consumer overflows the netlink socket, which then ends the
	// subscription.
	refreshNow := make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(routeKeeperInterval)
		defer t.Stop()
		for {
			if w, err := a.stickyCIDRs(ctx); err == nil {
				mu.Lock()
				want = w
				mu.Unlock()
			} else if ctx.Err() == nil {
				a.Log.Warn("route keeper: listing CiliumNodes", "err", err)
			}
			keep()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-refreshNow:
			}
		}
	}()
	wanted := func(p netip.Prefix) bool {
		mu.Lock()
		defer mu.Unlock()
		_, ok := want[p]
		return ok
	}
	for ctx.Err() == nil {
		updates := make(chan netlink.RouteUpdate, 256)
		done := make(chan struct{}) // closing it ends the subscription
		stop := context.AfterFunc(ctx, func() { close(done) })
		err := netlink.RouteSubscribeWithOptions(updates, done, netlink.RouteSubscribeOptions{
			ReceiveBufferSize: routeEventBuffer,
			ErrorCallback:     func(err error) { a.Log.Warn("route keeper: route events", "err", err) },
		})
		if err != nil {
			a.Log.Warn("route keeper: no route events, checking periodically meanwhile", "err", err)
		} else {
			for u := range updates {
				if u.Type != unix.RTM_DELROUTE || u.Dst == nil {
					continue
				}
				if p, ok := netip.AddrFromSlice(u.Dst.IP); ok && wanted(netip.PrefixFrom(p.Unmap(), 32)) {
					// At once from what is known, then from a fresh list. A
					// route whose CIDR was just released everywhere stays –
					// like the stale routes Cilium leaves itself, harmless.
					keep()
					select {
					case refreshNow <- struct{}{}:
					default:
					}
				}
			}
			// The channel closes when the subscription ends (an overflow,
			// for instance, or ctx): subscribe again.
		}
		if stop() {
			close(done)
		}
		select {
		case <-ctx.Done():
		case <-time.After(routeResubscribe):
		}
	}
}

const (
	// routeEventBuffer is the netlink socket's receive buffer for route
	// events: a node with many pods changes routes in bursts.
	routeEventBuffer = 1 << 20
	// routeResubscribe: the pause before subscribing again.
	routeResubscribe = time.Second
)

// stickyCIDRs lists the /32s of Paguro pools that some CiliumNode holds;
// true marks those this node holds.
func (a *Agent) stickyCIDRs(ctx context.Context) (map[netip.Prefix]bool, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(ciliumNodeGVK)
	if err := a.APIReader.List(ctx, list); err != nil {
		return nil, err
	}
	return stickyCIDRsOf(list.Items, a.NodeName), nil
}

func stickyCIDRsOf(nodes []unstructured.Unstructured, local string) map[netip.Prefix]bool {
	out := map[netip.Prefix]bool{}
	for _, n := range nodes {
		pools, _, _ := unstructured.NestedSlice(n.Object, "spec", "ipam", "pools", "allocated")
		for _, p := range pools {
			m, _ := p.(map[string]any)
			name, _ := m["pool"].(string)
			if !netadapter.IsStickyPool(name) {
				continue
			}
			cidrs, _ := m["cidrs"].([]any)
			for _, c := range cidrs {
				s, _ := c.(string)
				pfx, err := netip.ParsePrefix(s)
				if err != nil || !pfx.Addr().Is4() || pfx.Bits() != 32 {
					continue
				}
				out[pfx] = out[pfx] || n.GetName() == local
			}
		}
	}
	return out
}

// keepRoutes adds the missing routes, shaped like Cilium's.
func (a *Agent) keepRoutes(link netlink.Link, want map[netip.Prefix]bool) {
	if len(want) == 0 {
		return
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: link.Attrs().Index}, netlink.RT_FILTER_OIF)
	if err != nil {
		a.Log.Warn("route keeper: listing routes", "err", err)
		return
	}
	have := map[netip.Prefix]bool{}
	mtu := 0
	for _, r := range routes {
		if r.MTU > 0 && mtu == 0 {
			mtu = r.MTU // Cilium's routes to other nodes carry the tunnel MTU
		}
		if r.Dst != nil {
			if p, ok := netip.AddrFromSlice(r.Dst.IP); ok {
				ones, _ := r.Dst.Mask.Size()
				have[netip.PrefixFrom(p.Unmap(), ones)] = true
			}
		}
	}
	gw := ciliumHostIP(link)
	if gw == nil {
		return
	}
	for pfx, local := range want {
		if have[pfx] {
			continue
		}
		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: pfx.Addr().AsSlice(), Mask: net.CIDRMask(32, 32)},
			Gw:        gw, Src: gw,
			Protocol: unix.RTPROT_KERNEL,
		}
		if !local {
			r.MTU = mtu
		}
		if err := netlink.RouteReplace(r); err != nil {
			a.Log.Warn("route keeper: restoring route", "cidr", pfx.String(), "err", err)
			continue
		}
		routeRepairs.Inc()
		a.Log.Info("restored Cilium's host route of a kept address", "cidr", pfx.String(), "local", local)
	}
}

func ciliumHostIP(link netlink.Link) net.IP {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if a.IP.IsGlobalUnicast() {
			return a.IP
		}
	}
	return nil
}

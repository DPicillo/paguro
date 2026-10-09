// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Phantom mode, part 3: routes of the old addresses to their new nodes, and
// reporting addresses no route can reach.

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/phantom"
)

// ensureRoutes makes the old addresses routable where this node translates
// them after routing (see phantom/route.go): in the host namespace when there
// are host-scope rules, and in peer pods (not the migrated pod itself).
func (pm *phantomManager) ensureRoutes(r *phantomRecord, mig phantom.Migration, flows []phantom.Flow, p phantom.PlanResult) {
	olds := []netip.Addr{}
	for _, f := range flows {
		if !slices.Contains(olds, f.Local.Addr()) {
			olds = append(olds, f.Local.Addr())
		}
	}
	nets := []string{}
	for _, a := range p.Attachments {
		if a.Kind == phantom.KindPod && a.Netns != r.Netns && !slices.Contains(nets, a.Netns) {
			nets = append(nets, a.Netns)
		}
	}
	for _, rule := range p.Rules {
		if rule.Scope == phantom.ScopeHost && !slices.Contains(nets, "") {
			nets = append(nets, "")
		}
	}
	for _, ns := range nets {
		for _, old := range olds {
			// Recorded even if nothing had to be installed: the route may
			// be one an earlier migration of this pod installed.
			if _, err := phantom.EnsureOffLinkRoute(ns, old, mig.NewIP); err != nil {
				// Recorded anyway: the host's routes are checked again on
				// every change (WatchRoutes).
				pm.log.Warn("phantom: route for the old address", "netns", ns, "addr", old, "err", err)
			}
			rt := phantomRoute{Netns: ns, Addr: old.String(), Like: mig.NewIP.String()}
			if ns == "" {
				rt.Routed, _ = phantom.RoutedIntoCluster(old)
			}
			r.Routes = append(r.Routes, rt)
		}
	}
}

// routeInUse reports whether a record other than except needs rt.
func (pm *phantomManager) routeInUse(rt phantomRoute, except types.UID) bool {
	for uid, o := range pm.records {
		if uid != except && slices.ContainsFunc(o.Routes, rt.same) {
			return true
		}
	}
	return false
}

// recheckRoutes ensures every host route need again, each like the newest
// record that needs it. A route that was fine when the record was
// programmed – the CNI's route of the old node's pod subnet – can vanish
// later: the node is deleted after a drain, Cilium releases a /32 pool.
// The old address would then follow the default route out of the cluster.
//
// It also returns the addresses that were routed into the cluster when
// they were programmed and are not any more (not reported before), with
// the newest migration that needs each: the controller drops them from
// the backend keeper (see phantomUnroutable). Caller holds pm.mu.
func (pm *phantomManager) recheckRoutes() []unroutable {
	type need struct {
		rt  phantomRoute
		rec *phantomRecord
	}
	newest := map[string]need{}
	for _, r := range pm.records {
		for _, rt := range r.Routes {
			if rt.Netns != "" || rt.Like == "" {
				continue
			}
			if n, ok := newest[rt.Addr]; !ok || r.Programmed.After(n.rec.Programmed) {
				newest[rt.Addr] = need{rt, r}
			}
		}
	}
	var lost []unroutable
	for _, n := range newest {
		old, err1 := netip.ParseAddr(n.rt.Addr)
		like, err2 := netip.ParseAddr(n.rt.Like)
		if err1 != nil || err2 != nil {
			continue
		}
		if ok, err := phantom.EnsureOffLinkRoute("", old, like); err != nil {
			pm.log.Warn("phantom: route for the old address", "addr", old, "err", err)
		} else if ok {
			pm.log.Info("phantom: old address routed like the new one", "addr", old, "like", like)
		}
		u := unroutable{UID: n.rec.UID, Namespace: n.rec.Namespace, Name: n.rec.Name, Addr: n.rt.Addr}
		if n.rt.Routed && !pm.unroutableSent[u] {
			if in, err := phantom.RoutedIntoCluster(old); err == nil && !in {
				lost = append(lost, u)
			}
		}
	}
	return lost
}

// patchByUID patches the status of the Migration u belongs to – and only
// that one: a Migration re-created under the same name must not receive
// the report (resourceVersion as precondition, retried on conflicts).
func (pm *phantomManager) patchByUID(ctx context.Context, u unroutable, status map[string]any) error {
	for i := 0; i < 5; i++ {
		cur := &v1.Migration{}
		if err := pm.a.APIReader.Get(ctx, types.NamespacedName{Namespace: u.Namespace, Name: u.Name}, cur); err != nil {
			return err
		}
		if cur.UID != u.UID {
			return apierrors.NewNotFound(v1.GroupVersion.WithResource("migrations").GroupResource(), u.Name)
		}
		b, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"resourceVersion": cur.ResourceVersion},
			"status":   status,
		})
		if err != nil {
			return err
		}
		if err = pm.a.Client.Status().Patch(ctx, cur, client.RawPatch(types.MergePatchType, b)); !apierrors.IsConflict(err) {
			return err
		}
	}
	return errors.New("status kept changing")
}

// unroutable: an old address of a migration that left the cluster's routes.
type unroutable struct {
	UID             types.UID
	Namespace, Name string
	Addr            string
}

// reportUnroutable publishes lost addresses (status.phantomUnroutable).
func (pm *phantomManager) reportUnroutable(ctx context.Context, lost []unroutable) {
	for _, u := range lost {
		err := pm.patchByUID(ctx, u, map[string]any{"phantomUnroutable": map[string]any{u.Addr: now()}})
		pm.log.Info("phantom: old address no longer routed into the cluster", "migration", u.Namespace+"/"+u.Name, "addr", u.Addr, "err", err)
		if err != nil && !apierrors.IsNotFound(err) {
			pm.mu.Lock()
			delete(pm.unroutableSent, u) // try again on the next check
			pm.mu.Unlock()
		}
	}
}

// WatchRoutes rechecks the routes of old addresses whenever the host's
// routes change, and every 30 s in case a notification was missed. Each
// check also covers devices that appeared since (coverHostDevices).
func (pm *phantomManager) WatchRoutes(ctx context.Context) {
	updates := make(chan netlink.RouteUpdate, 256)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.RouteSubscribeWithOptions(updates, done, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) { pm.log.Warn("phantom: route notifications", "err", err) },
	}); err != nil {
		pm.log.Warn("phantom: no route notifications, checking every 30 s", "err", err)
		updates = nil
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			// Added routes matter too: the CNI's route to a new address
			// may appear only after the programming. Paguro's own routes
			// would only echo the last check.
			if u.Protocol == phantom.RouteProtocol {
				continue
			}
			// A node's routes go in a burst: settle, then check once.
			time.Sleep(50 * time.Millisecond)
			for len(updates) > 0 {
				<-updates
			}
		case <-tick.C:
		}
		pm.mu.Lock()
		lost := pm.recheckRoutes()
		pm.coverHostDevices()
		pm.syncSteering()
		for _, u := range lost {
			pm.unroutableSent[u] = true // pending; reset if not confirmed
		}
		pm.mu.Unlock()
		if len(lost) > 0 {
			go pm.confirmUnroutable(ctx, lost)
		}
	}
}

// An old address must stay unrouted for unroutableGrace, checked every
// unroutableCheck, before it is reported. The report removes it from the
// backend keeper for good – connections through every node are reset – so
// a flap must not count: a restarting CNI agent (calico-node, cilium), a
// BGP session reset, a node that reboots. A deleted node's routes do not
// come back.
var (
	unroutableGrace = 60 * time.Second
	unroutableCheck = 10 * time.Second
)

func (pm *phantomManager) confirmUnroutable(ctx context.Context, lost []unroutable) {
	pending := lost
	for waited := time.Duration(0); waited < unroutableGrace && len(pending) > 0; waited += unroutableCheck {
		select {
		case <-ctx.Done():
			return
		case <-time.After(unroutableCheck):
		}
		still := pending[:0]
		for _, u := range pending {
			old, err := netip.ParseAddr(u.Addr)
			if in, rerr := phantom.RoutedIntoCluster(old); err == nil && rerr == nil && !in {
				still = append(still, u)
				continue
			}
			pm.mu.Lock()
			delete(pm.unroutableSent, u) // routed again: not lost
			pm.mu.Unlock()
		}
		pending = still
	}
	pm.reportUnroutable(ctx, pending)
}

// syncSteering makes the steering (phantom/steer.go) of every namespace
// match the live translated flows of all records: only those flows are
// routed like the new address, never other connections to an old address
// – a pod that received it (IP reuse) stays reachable. A flow is steered
// where its record routes its old address (ensureRoutes), by the tuple the
// kernel routes it by. Caller holds pm.mu.
//
// The host's flows are steered by the tuples conntrack maps them to. If
// conntrack cannot be read, the host's steering is only added to (Extend):
// replacing it would swap the right tuples of DNAT'ed and masqueraded flows
// for ones the kernel never routes by, and cut those connections off until
// the next check.
func (pm *phantomManager) syncSteering() {
	want := steeringWanted(pm.records)
	complete := true
	if host := want[""]; len(host) > 0 {
		want[""], complete = pm.routingTuples(host)
	}
	if pm.steerNets == nil {
		pm.steerNets = map[string]bool{}
	}
	nets := map[string]bool{"": true} // the host's: also what a previous process left
	for ns := range want {
		nets[ns] = true
	}
	for ns := range pm.steerNets {
		nets[ns] = true
	}
	st := pm.steering()
	for ns := range nets {
		sync := st.Sync
		if ns == "" && !complete {
			sync = st.Extend
		}
		err := sync(ns, ns == "", want[ns])
		switch {
		case err != nil && ns != "" && errors.Is(err, os.ErrNotExist):
			delete(pm.steerNets, ns) // the pod is gone, its rules with it
		case err != nil:
			pm.steerWarn(ns, err)
		case ns != "" && len(want[ns]) == 0:
			delete(pm.steerNets, ns)
		case ns != "":
			pm.steerNets[ns] = true
		}
		if err == nil {
			delete(pm.steerErr, ns)
		}
	}
}

// routingTuplesOf reads the conntrack mapping (a fake in tests).
var routingTuplesOf = phantom.RoutingTuples

// routingTuples returns the tuples the kernel routes the host's flows by
// (phantom.RoutingTuples). A connection keeps its NAT mapping for its life:
// conntrack is read only for flows not mapped before – a flow without an
// entry is asked again on the next sync. complete is false when conntrack
// could not be read; the flows it did not map are then given by their own
// tuples. Caller holds pm.mu.
func (pm *phantomManager) routingTuples(host []phantom.Tuple) (out []phantom.Tuple, complete bool) {
	if pm.routeOf == nil {
		pm.routeOf = map[phantom.Tuple]phantom.Tuple{}
	}
	wanted := make(map[phantom.Tuple]bool, len(host))
	var missing []phantom.Tuple
	for _, t := range host {
		wanted[t] = true
		if _, ok := pm.routeOf[t]; !ok {
			missing = append(missing, t)
		}
	}
	for t := range pm.routeOf {
		if !wanted[t] {
			delete(pm.routeOf, t)
		}
	}
	complete = true
	if len(missing) > 0 {
		found, err := routingTuplesOf(missing)
		for t, r := range found {
			pm.routeOf[t] = r
		}
		switch {
		case err == nil:
			pm.ctErr = ""
		case err.Error() != pm.ctErr: // once until it changes
			pm.ctErr = err.Error()
			pm.log.Warn("phantom: conntrack not readable – the host's steering is kept, new flows are added by their own tuples", "err", err)
		}
		complete = err == nil
	}
	out = make([]phantom.Tuple, len(host))
	for i, t := range host {
		out[i] = t
		if r, ok := pm.routeOf[t]; ok {
			out[i] = r
		}
	}
	return out, complete
}

// steering returns this node's steering, set up on first use: the packet
// mark of the agent's configuration, nft in the host's mount namespace.
func (pm *phantomManager) steering() *phantom.Steering {
	if pm.steer == nil {
		pm.steer = &phantom.Steering{}
		if pm.a != nil {
			pm.steer.Mark = pm.a.PhantomSteerMark
			if h := pm.a.Host; h != nil {
				pm.steer.Run = func(stdin, name string, args ...string) (string, error) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					return h.ShieldRunner(ctx)(stdin, name, args...)
				}
			}
		}
	}
	return pm.steer
}

// steerWarn logs a steering error once until it changes or goes away: the
// sync runs on every route change.
func (pm *phantomManager) steerWarn(ns string, err error) {
	if pm.steerErr == nil {
		pm.steerErr = map[string]string{}
	}
	if pm.steerErr[ns] == err.Error() {
		return
	}
	pm.steerErr[ns] = err.Error()
	pm.log.Warn("phantom: steering", "netns", ns, "err", err)
}

// steeringWanted returns, per namespace ("" = the host), the inside tuples
// of the live translated flows that leave towards an old address: the
// peer-side Out rules (host scope: the host; pod scope: the peer pod's
// namespace) whose old address the record routes in that namespace.
// Identity rules need no steering: the connection is on the wire as itself.
func steeringWanted(records map[types.UID]*phantomRecord) map[string][]phantom.Tuple {
	want := map[string][]phantom.Tuple{}
	for _, r := range records {
		routed := map[phantomRoute]bool{}
		for _, rt := range r.Routes {
			routed[phantomRoute{Netns: rt.Netns, Addr: rt.Addr}] = true
		}
		for i, p := range r.PerFlow {
			if slices.Contains(r.Dead, int32(i)) {
				continue
			}
			peerNs := ""
			for _, a := range p.Attachments {
				if a.Kind == phantom.KindPod && a.Netns != r.Netns {
					peerNs = a.Netns
				}
			}
			for _, rule := range p.Rules {
				if rule.Dir != phantom.Out || rule.Match == rule.Rewrite {
					continue
				}
				ns := ""
				if rule.Scope == phantom.ScopePod {
					if peerNs == "" {
						continue // the migrated pod's own side
					}
					ns = peerNs
				}
				if routed[phantomRoute{Netns: ns, Addr: rule.Match.Dst.Addr().String()}] {
					want[ns] = appendNew(want[ns], rule.Match)
				}
			}
		}
	}
	return want
}

// coverHostDevices attaches the host programs to devices that carry pod
// traffic and appeared after the records with host-scope rules were
// programmed: an ENI that the AWS VPC CNI's ipamd attaches as pods arrive
// (with a routing table of its own), a CNI device created later. A record
// gets the devices of its time (phantom.HostDevices); this keeps the set
// current while it lives. Attaching is idempotent, and every program only
// acts on exact hits. Caller holds pm.mu.
func (pm *phantomManager) coverHostDevices() {
	dests, have := hostScopeNeeds(pm.records)
	if len(dests) == 0 {
		return
	}
	devs, err := phantom.HostDevices(dests...)
	if err != nil {
		return
	}
	missing := slices.DeleteFunc(devs, func(d string) bool { return have[d] || pm.hostCovered[d] })
	if len(missing) == 0 {
		return
	}
	t, err := pm.tr()
	if err != nil {
		return
	}
	if pm.hostCovered == nil {
		pm.hostCovered = map[string]bool{}
	}
	for _, d := range missing {
		if err := t.Attach(phantom.Attachment{Ifname: d, Kind: phantom.KindHostDevice}); err != nil {
			pm.log.Warn("phantom: host programs not attached to a new device", "device", d, "err", err)
			continue
		}
		pm.hostCovered[d] = true
		pm.log.Info("phantom: host programs attached to a device that appeared after the programming", "device", d)
	}
}

// hostScopeNeeds returns the addresses the host-scope rules of records
// translate between (for the route lookups of phantom.HostDevices) and the
// host devices their plans attached to. No host-scope rule: no addresses.
func hostScopeNeeds(records map[types.UID]*phantomRecord) ([]netip.Addr, map[string]bool) {
	var dests []netip.Addr
	have := map[string]bool{}
	for _, r := range records {
		for i, p := range r.PerFlow {
			if slices.Contains(r.Dead, int32(i)) {
				continue
			}
			for _, a := range p.Attachments {
				if a.Kind == phantom.KindHostDevice {
					have[a.Ifname] = true
				}
			}
			for _, rule := range p.Rules {
				if rule.Scope == phantom.ScopeHost && rule.Dir == phantom.Out {
					dests = appendNew(dests, rule.Match.Dst.Addr(), rule.Rewrite.Dst.Addr())
				}
			}
		}
	}
	return dests, have
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Phantom mode, part 4: undoing a translation – ended connections, released
// migrations, port reservations – and the garbage collection of flows.

package agent

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/phantom"
)

// undo removes a partially applied record without marking the migration
// released.
func (pm *phantomManager) undo(r *phantomRecord) {
	pm.release(r, "programming failed")
	delete(pm.released, r.UID)
}

// dropDead removes the rules and reservations of flows that ended. A
// reservation stays while a live flow still needs it.
func (pm *phantomManager) dropDead(r *phantomRecord, dead []int32) {
	var fresh []int32
	for _, i := range dead {
		if int(i) < len(r.PerFlow) && !slices.Contains(r.Dead, i) {
			fresh = append(fresh, i)
		}
	}
	if len(fresh) == 0 {
		return
	}
	r.Dead = append(r.Dead, fresh...)
	var live, gone phantom.PlanResult
	for i, p := range r.PerFlow {
		if slices.Contains(r.Dead, int32(i)) {
			if slices.Contains(fresh, int32(i)) {
				gone.Rules = append(gone.Rules, p.Rules...)
				gone.Reservations = appendNew(gone.Reservations, p.Reservations...)
				gone.ConntrackReservations = appendNew(gone.ConntrackReservations, p.ConntrackReservations...)
			}
			continue
		}
		live.Reservations = appendNew(live.Reservations, p.Reservations...)
		live.ConntrackReservations = appendNew(live.ConntrackReservations, p.ConntrackReservations...)
	}
	other := pm.reservationsInUse(r.UID)
	live.Reservations = append(live.Reservations, other.Reservations...)
	live.ConntrackReservations = append(live.ConntrackReservations, other.ConntrackReservations...)
	gone.Reservations = slices.DeleteFunc(gone.Reservations, func(x phantom.Reservation) bool { return slices.Contains(live.Reservations, x) })
	gone.ConntrackReservations = slices.DeleteFunc(gone.ConntrackReservations, func(x phantom.Tuple) bool { return slices.Contains(live.ConntrackReservations, x) })
	t, err := pm.tr()
	if err == nil {
		// Only the rules this migration still owns: a later hop of the pod
		// may have taken over the same keys for a connection that this
		// hop's target saw end while the pod moved on (its sockets go away
		// with the source of the next hop).
		err = t.RevertOwned(r.ID, gone)
	}
	if err != nil {
		pm.log.Warn("phantom: removing rules of ended connections", "err", err)
	}
	_ = pm.save(r)
	pm.syncSteering()
}

// reservationsInUse returns the reservations the live flows of every other
// migration on this node need. A chained migration reserves the same wire
// tuples as the one before it; releasing the older one must not drop them.
func (pm *phantomManager) reservationsInUse(except types.UID) phantom.PlanResult {
	var in phantom.PlanResult
	for uid, o := range pm.records {
		if uid == except {
			continue
		}
		for i, p := range o.PerFlow {
			if !slices.Contains(o.Dead, int32(i)) {
				in.Reservations = appendNew(in.Reservations, p.Reservations...)
				in.ConntrackReservations = appendNew(in.ConntrackReservations, p.ConntrackReservations...)
			}
		}
	}
	return in
}

// release removes everything this node installed for a migration. Rules go
// by owner id – a rule a later (chained) migration re-installed for the
// same connection carries that migration's id and stays.
func (pm *phantomManager) release(r *phantomRecord, why string) {
	var all phantom.PlanResult
	for i, p := range r.PerFlow {
		if slices.Contains(r.Dead, int32(i)) {
			continue
		}
		all.Reservations = appendNew(all.Reservations, p.Reservations...)
		all.ConntrackReservations = appendNew(all.ConntrackReservations, p.ConntrackReservations...)
	}
	other := pm.reservationsInUse(r.UID)
	all.Reservations = slices.DeleteFunc(all.Reservations, func(x phantom.Reservation) bool { return slices.Contains(other.Reservations, x) })
	all.ConntrackReservations = slices.DeleteFunc(all.ConntrackReservations, func(x phantom.Tuple) bool { return slices.Contains(other.ConntrackReservations, x) })
	n := 0
	t, err := pm.tr()
	if err == nil {
		n, err = t.DeleteOwner(r.ID)
		err = errors.Join(err, t.Revert(all))
	}
	for _, rt := range r.Routes {
		if a, perr := netip.ParseAddr(rt.Addr); perr == nil && !pm.routeInUse(rt, r.UID) {
			// Removes only Paguro's own route (protocol and metric).
			err = errors.Join(err, phantom.RemoveOffLinkRoute(rt.Netns, a))
		}
	}
	pm.log.Info("phantom: released", "migration", r.Namespace+"/"+r.Name, "reason", why, "rules", n, "err", err)
	delete(pm.records, r.UID)
	delete(pm.gc, r.UID)
	delete(pm.gcWake, r.UID)
	pm.released[r.UID] = true
	_ = os.Remove(filepath.Join(phantomStateDir, string(r.UID)+".json"))
	pm.syncSteering()
	if len(pm.records) == 0 {
		pm.detachAll()
	}
}

// detachAll removes everything Phantom mode put into the datapath once no
// migration needs translation any more. The next migration starts over with
// fresh maps (tr re-creates the translator).
func (pm *phantomManager) detachAll() {
	pm.hostCovered = nil
	if pm.t != nil {
		_ = pm.t.Close()
		pm.t = nil
	}
	if err := phantom.Cleanup(phantom.DefaultPinPath); err != nil {
		pm.log.Warn("phantom: cleanup", "err", err)
		return
	}
	pm.log.Info("phantom: idle – programs detached, maps removed")
}

// phantomGCInterval is how often the target checks which migrated connections
// still exist.
const phantomGCInterval = 10 * time.Second

// gcLoop (target only) watches which migrated connections still exist and
// reports ended ones; when none is left or the pod is gone, it releases
// the migration on every node.
func (pm *phantomManager) gcLoop(m *v1.Migration, wake <-chan struct{}) {
	ctx := context.Background()
	log := pm.log.With("migration", m.Namespace+"/"+m.Name)
	flows, err := flowsFromAPI(m.Status.Source.Phantom.Flows)
	if err != nil {
		return
	}
	old, _ := netip.ParseAddr(m.Status.SourcePodIP)
	reported := map[int32]bool{}
	for _, i := range ptrDeref(m.Status.Target.Phantom).DeadFlows {
		reported[i] = true
	}
	tick := time.NewTicker(phantomGCInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
		case <-wake:
		}
		pm.mu.Lock()
		r := pm.records[m.UID]
		pm.mu.Unlock()
		if r == nil {
			return // released
		}
		var dead []int32
		live, ended, err := phantom.LiveFlows(r.Netns, old, flows)
		gone := err != nil && errors.Is(err, os.ErrNotExist)
		if err != nil && !gone {
			log.Warn("phantom: checking connections", "err", err)
			continue
		}
		for i, f := range flows {
			if (gone || slices.Contains(ended, f) || f.Class != phantom.ClassInCluster) && !reported[int32(i)] {
				dead = append(dead, int32(i))
				reported[int32(i)] = true
			}
		}
		if len(dead) == 0 && len(live) > 0 {
			continue
		}
		all := make([]int32, 0, len(reported))
		for i := range reported {
			all = append(all, i)
		}
		slices.Sort(all)
		patch := map[string]any{"deadFlows": all}
		if len(all) == len(flows) {
			patch["releasedAt"] = now()
		}
		// By UID: the loop runs as long as the connections live, and a
		// Migration re-created under the same name must not get the report.
		owner := unroutable{UID: m.UID, Namespace: m.Namespace, Name: m.Name}
		if err := pm.patchByUID(ctx, owner, map[string]any{"target": map[string]any{"phantom": patch}}); err != nil {
			if apierrors.IsNotFound(err) {
				return // the migration is gone
			}
			log.Warn("phantom: reporting ended connections", "err", err)
			continue
		}
		log.Info("phantom: connections ended", "ended", len(dead), "remaining", len(flows)-len(all))
		if len(all) == len(flows) {
			return
		}
	}
}

func ptrDeref(t *v1.TargetPhantom) v1.TargetPhantom {
	if t == nil {
		return v1.TargetPhantom{}
	}
	return *t
}

// coldStarted: a container of the replacement was started fresh after a
// failed restore – the migrated connections of the pod exist no more.
func coldStarted(m *v1.Migration) bool {
	for _, c := range m.Status.Target.Containers {
		if c.ColdStartReason != "" {
			return true
		}
	}
	return false
}

// strandedSocket is a socket on this node of a migrated connection whose
// other end is gone.
type strandedSocket struct {
	Netns string // "" = the host's
	// Local is the socket's own address, Remote its peer as it sees it (a
	// ClusterIP, if it connected to one).
	Local, Remote netip.AddrPort
}

// strandedSockets returns this node's sockets of the TCP flows dead (indexes
// into r.PerFlow and flows): the peers' ends – in a peer pod, a host socket,
// or a pod behind a kernel DNAT (host scope; its socket's own tuple from
// orig, the conntrack entry). Peers outside the cluster (a NodePort's
// clients) have no socket here. Flows aborted already are skipped.
func strandedSockets(r *phantomRecord, flows []phantom.Flow, dead []int32, orig map[phantom.Tuple]phantom.Tuple,
	hostIPs map[netip.Addr]bool, podNetns map[netip.Addr]string) []strandedSocket {
	var out []strandedSocket
	for _, i := range dead {
		if int(i) >= len(r.PerFlow) || int(i) >= len(flows) || slices.Contains(r.Aborted, i) || flows[i].Proto != phantom.TCP {
			continue
		}
		for _, rule := range r.PerFlow[i].Rules {
			// The peer's side: towards the migrated pod's own endpoint.
			if rule.Dir != phantom.Out || rule.Match.Dst != flows[i].Local {
				continue
			}
			s := strandedSocket{Local: rule.Match.Src, Remote: rule.Match.Dst}
			if rule.Scope == phantom.ScopeHost {
				if o, ok := orig[rule.Match]; ok {
					s.Local, s.Remote = o.Src, o.Dst
				}
			}
			a := s.Local.Addr().Unmap()
			switch ns, isPod := podNetns[a]; {
			case hostIPs[a]:
			case isPod:
				s.Netns = ns
			default:
				continue // outside the cluster
			}
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// abortStranded aborts this node's sockets of the connections a cold start
// of the replacement left without their other end (the replacement's
// target reports them dead). Without it a peer that waits for data – a
// clone in flight, a pooled connection – waits for its own timeout (one
// waited 7 min): nothing answers, and as long as it sends nothing, no RST
// comes either. Aborted, the application sees ECONNABORTED at once and
// reconnects. Caller holds pm.mu.
func (pm *phantomManager) abortStranded(ctx context.Context, r *phantomRecord, sph *v1.SourcePhantom, dead []int32) {
	if sph == nil || len(dead) == 0 {
		return
	}
	flows, err := flowsFromAPI(sph.Flows)
	if err != nil {
		return
	}
	var lookup []phantom.Tuple
	ips := map[netip.Addr]bool{}
	for _, i := range dead {
		if int(i) >= len(r.PerFlow) || slices.Contains(r.Aborted, i) {
			continue
		}
		for _, rule := range r.PerFlow[i].Rules {
			if rule.Dir == phantom.Out && rule.Scope == phantom.ScopeHost {
				lookup = append(lookup, rule.Match)
			}
			if rule.Dir == phantom.Out {
				ips[rule.Match.Src.Addr().Unmap()] = true
			}
		}
	}
	orig, err := phantom.OriginalTuples(lookup)
	if err != nil {
		pm.log.Warn("phantom: conntrack not readable – connections through a ClusterIP may not be aborted", "err", err)
	}
	for _, o := range orig {
		ips[o.Src.Addr().Unmap()] = true
	}
	hostIPs, err := phantom.HostAddrs()
	if err != nil {
		pm.log.Warn("phantom: host addresses", "err", err)
	}
	podNetns := map[netip.Addr]string{}
	if pods, err := pm.localPods(ctx, ips); err == nil {
		for a, ep := range pods {
			podNetns[a] = ep.Netns
		}
	}
	byNetns := map[string][]phantom.Flow{}
	for _, s := range strandedSockets(r, flows, dead, orig, hostIPs, podNetns) {
		byNetns[s.Netns] = append(byNetns[s.Netns], phantom.Flow{Proto: phantom.TCP, Local: s.Local, Remote: s.Remote})
	}
	total := 0
	for ns, fs := range byNetns {
		n, err := phantom.KillFlows(ns, fs)
		total += n
		if err != nil {
			pm.log.Info("phantom: aborting connections after the cold start", "netns", ns, "err", err)
		}
	}
	for _, i := range dead {
		if !slices.Contains(r.Aborted, i) {
			r.Aborted = append(r.Aborted, i)
		}
	}
	_ = pm.save(r)
	if total > 0 {
		pm.log.Info("phantom: the replacement was cold-started – aborted this node's ends of its connections",
			"migration", r.Namespace+"/"+r.Name, "sockets", total)
	}
}

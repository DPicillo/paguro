// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Phantom mode, part 2: programming a migration's translation on the target
// node and on every peer node.

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/phantom"
)

// reconcile brings this node in line with a Phantom migration's status. It
// re-reads the object under the lock: events are handled in goroutines, and
// acting on an older copy after a newer one could re-install released rules.
func (pm *phantomManager) reconcile(ctx context.Context, key types.NamespacedName) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	m := &v1.Migration{}
	if err := pm.a.Client.Get(ctx, key, m); err != nil || !isPhantom(m) {
		return
	}
	// Also once this node has released the migration's translation: the
	// attempts concern every node, also one without migrated flows.
	pm.handBackSYNs(m)
	if pm.released[m.UID] {
		return
	}
	r := pm.records[m.UID]
	tph := m.Status.Target.Phantom
	if r != nil && tph != nil && coldStarted(m) {
		// Before the release below: the target reports a cold start's
		// flows dead and released at once.
		pm.abortStranded(ctx, r, m.Status.Source.Phantom, tph.DeadFlows)
	}
	if tph != nil && tph.ReleasedAt != nil {
		if r != nil {
			pm.release(r, "connections ended")
		}
		pm.released[m.UID] = true
		return
	}
	sph := m.Status.Source.Phantom
	if sph == nil {
		return // not committed yet: nothing may be programmed
	}
	isTarget := m.Status.TargetNode == pm.a.NodeName
	fresh := r == nil
	if r == nil {
		var err error
		switch {
		case isTarget:
			r, err = pm.programTarget(ctx, m)
		case tph != nil && tph.ProgrammedAt != nil:
			r, err = pm.programPeer(ctx, m)
		default:
			return // peers wait for the target
		}
		if errors.Is(err, os.ErrNotExist) && isTarget {
			return // the replacement has no sandbox yet: retried on its report
		}
		if err != nil {
			pm.log.Error("phantom: programming failed", "migration", m.Namespace+"/"+m.Name, "target", isTarget, "err", err)
			return
		}
	}
	// A status report that failed after the datapath was programmed: report
	// again (peers only start once the target's report is there).
	if !fresh && !r.Reported {
		if isTarget {
			pm.reportTarget(ctx, m, r)
		} else {
			pm.reportPeer(ctx, m, r)
		}
	}
	if isTarget && !r.PendingCleared && m.Status.Target.RestoredAt != nil {
		pm.clearPending(r, sph)
	}
	if tph != nil {
		pm.dropDead(r, tph.DeadFlows)
	}
	if isTarget && !pm.gc[m.UID] {
		pm.gc[m.UID] = true
		if pm.gcWake == nil {
			pm.gcWake = map[types.UID]chan struct{}{}
		}
		pm.gcWake[m.UID] = make(chan struct{}, 1)
		go pm.gcLoop(m.DeepCopy(), pm.gcWake[m.UID])
	}
	if isTarget && coldStarted(m) {
		// The migrated connections are gone: report them now, not at the
		// next tick, so that the peers abort their side.
		select {
		case pm.gcWake[m.UID] <- struct{}{}:
		default:
		}
	}
}

// restoredNow is called by the target job the moment the wrapper reports
// the restore – saves a watch round trip before inbound traffic flows.
func (pm *phantomManager) restoredNow(uid types.UID, sph *v1.SourcePhantom) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if r := pm.records[uid]; r != nil && r.Target && !r.PendingCleared {
		pm.clearPending(r, sph)
	}
}

// nodeContext describes this node for the planner.
func (pm *phantomManager) nodeContext(ctx context.Context, m *v1.Migration, old, new netip.Addr, flows []phantom.Flow) (phantom.NodeContext, error) {
	nc := phantom.NodeContext{Remap: pm.remap(ctx, m.UID), OnLink: phantom.OnLinkIn}
	if cni, err := netadapter.DetectNodeCNI(pm.a.Host.Path("/etc/cni/net.d")); err == nil {
		nc.SourceVerify = cni.VerifiesSource()
	}
	var err error
	if nc.HostIPs, err = phantom.HostAddrs(); err != nil {
		return nc, err
	}
	// Only the pods this migration's flows talk to matter.
	peers := map[netip.Addr]bool{}
	for _, f := range flows {
		w := f.Remote
		if f.Wire.IsValid() {
			w = f.Wire
		}
		peers[w.Addr()] = true
		if nc.Remap != nil {
			if n, ok := nc.Remap(w.Addr()); ok {
				peers[n] = true
			}
		}
	}
	if nc.LocalPods, err = pm.localPods(ctx, peers); err != nil {
		return nc, err
	}
	dests := []netip.Addr{old, new}
	for _, f := range flows {
		if !slices.Contains(dests, f.Local.Addr()) {
			dests = append(dests, f.Local.Addr()) // chained migrations
		}
	}
	if nc.HostDevices, err = phantom.HostDevices(dests...); err != nil {
		return nc, err
	}
	if nc.ViaNetfilter, err = phantom.ViaNetfilter(flows); err != nil {
		pm.log.Warn("phantom: conntrack not readable – assuming no kernel DNAT", "err", err)
	}
	nc.TunnelRewrite = phantom.TunnelRewriteNeeded()
	return nc, nil
}

// localPods finds the pods on this node that own one of ips.
func (pm *phantomManager) localPods(ctx context.Context, ips map[netip.Addr]bool) (map[netip.Addr]phantom.PodEndpoint, error) {
	pods := &corev1.PodList{}
	if err := pm.a.Client.List(ctx, pods); err != nil {
		return nil, err
	}
	out := map[netip.Addr]phantom.PodEndpoint{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName != pm.a.NodeName || p.Spec.HostNetwork || p.Status.Phase != corev1.PodRunning {
			continue
		}
		var mine []netip.Addr
		for _, pip := range p.Status.PodIPs {
			if a, err := netip.ParseAddr(pip.IP); err == nil && ips[a] {
				mine = append(mine, a)
			}
		}
		if len(mine) == 0 {
			continue
		}
		netns, err := pm.podNetns(ctx, p)
		if err != nil {
			pm.log.Warn("phantom: peer pod without network namespace", "pod", p.Namespace+"/"+p.Name, "err", err)
			continue
		}
		ep, err := phantom.PodEndpointOf(netns, "eth0")
		if err != nil {
			pm.log.Warn("phantom: peer pod interface", "pod", p.Namespace+"/"+p.Name, "err", err)
			continue
		}
		for _, a := range mine {
			out[a] = ep
		}
	}
	return out, nil
}

// podNetns returns /proc/<pid>/ns/net of a running container of the pod
// (hostPID: valid in-process and on the host).
func (pm *phantomManager) podNetns(ctx context.Context, p *corev1.Pod) (string, error) {
	if ns := pm.a.runningNetns(ctx, p); ns != "" {
		return ns, nil
	}
	return "", errors.New("no running container")
}

// remap returns OLD->NEW of the other active Phantom migrations (a peer that
// was itself migrated is on the wire with its new address).
func (pm *phantomManager) remap(ctx context.Context, self types.UID) func(netip.Addr) (netip.Addr, bool) {
	list := &v1.MigrationList{}
	if err := pm.a.Client.List(ctx, list); err != nil {
		return nil
	}
	m := map[netip.Addr]netip.Addr{}
	for i := range list.Items {
		o := &list.Items[i]
		tph := o.Status.Target.Phantom
		if o.UID == self || !isPhantom(o) || tph == nil || tph.ProgrammedAt == nil || tph.ReleasedAt != nil {
			continue
		}
		old, err1 := netip.ParseAddr(o.Status.SourcePodIP)
		new, err2 := netip.ParseAddr(tph.NewIP)
		if err1 == nil && err2 == nil {
			m[old] = new
		}
	}
	if len(m) == 0 {
		return nil
	}
	return func(a netip.Addr) (netip.Addr, bool) { n, ok := m[a]; return n, ok }
}

// sandboxNetns returns the replacement's network namespace (written by the
// wrapper) as an in-process path and as the host's own path.
func (pm *phantomManager) sandboxNetns(uid types.UID) (inProc, onHost string, err error) {
	b, err := os.ReadFile(filepath.Join(layout.Root(string(uid)), v1.FileSandboxNetns))
	if err != nil {
		return "", "", err
	}
	onHost = strings.TrimSpace(string(b))
	if onHost == "" {
		return "", "", errors.New("sandbox has no network namespace path")
	}
	// /var/run is an absolute symlink to /run on the host; resolved through
	// the host root it would point into the agent's own filesystem.
	if rest, ok := strings.CutPrefix(onHost, "/var/run/"); ok {
		onHost = "/run/" + rest
	}
	return pm.a.Host.Path(onHost), onHost, nil
}

func (pm *phantomManager) programTarget(ctx context.Context, m *v1.Migration) (*phantomRecord, error) {
	start := time.Now()
	sph := m.Status.Source.Phantom
	flows, err := flowsFromAPI(sph.Flows)
	if err != nil {
		return nil, err
	}
	netns, hostNetns, err := pm.sandboxNetns(m.UID)
	if err != nil {
		return nil, fmt.Errorf("replacement sandbox: %w", err)
	}
	old, err := netip.ParseAddr(m.Status.SourcePodIP)
	if err != nil {
		return nil, fmt.Errorf("old IP: %w", err)
	}
	new, err := phantom.PodAddr(netns, "eth0", old.Is4())
	if err != nil {
		return nil, err
	}
	nodeIP, _, _ := net.SplitHostPort(pm.a.Endpoint)
	mig := phantom.Migration{ID: phantom.MigrationID(string(m.UID)), OldIP: old, NewIP: new}
	if a, err := netip.ParseAddr(nodeIP); err == nil {
		mig.NewNodeIP = a
	}
	nc, err := pm.nodeContext(ctx, m, old, new, flows)
	if err != nil {
		return nil, err
	}
	nc.IsTarget = true
	nc.Pending = m.Status.Target.RestoredAt == nil
	if nc.Migrated, err = phantom.PodEndpointOf(netns, "eth0"); err != nil {
		return nil, err
	}
	r := &phantomRecord{UID: m.UID, Namespace: m.Namespace, Name: m.Name, ID: mig.ID, Target: true,
		Netns: netns, OldIP: old.String(), PendingCleared: !nc.Pending}
	if err := pm.apply(r, mig, flows, nc); err != nil {
		return nil, err
	}
	// New connections to a listener bound to the old IP (self-IP fix-up).
	ports := make([]uint16, 0, len(sph.OldBoundListeners))
	for _, p := range sph.OldBoundListeners {
		ports = append(ports, uint16(p))
	}
	if err := phantom.InstallSelfIPFixup(pm.a.Host.ShieldRunner(ctx), hostNetns, old, new, ports); err != nil {
		pm.log.Warn("phantom: self-IP fix-up not installed", "err", err)
	}
	r.NewIP, r.NodeIP = new.String(), nodeIP
	_ = pm.save(r)
	pm.log.Info("phantom: target programmed", "migration", m.Namespace+"/"+m.Name, "old", old, "new", new,
		"flows", len(flows), "ms", ms(time.Since(start)))
	pm.reportTarget(ctx, m, r)
	return r, nil
}

// reportTarget publishes that the target node translates (peers wait for
// it). A failed report is retried on the next event.
func (pm *phantomManager) reportTarget(ctx context.Context, m *v1.Migration, r *phantomRecord) {
	pm.report(ctx, m, r, map[string]any{"target": map[string]any{"phantom": map[string]any{
		"newIP": r.NewIP, "nodeIP": r.NodeIP, "programmedAt": now(),
	}}})
}

// reportPeer records when this node programmed its side (status.phantomNodes).
func (pm *phantomManager) reportPeer(ctx context.Context, m *v1.Migration, r *phantomRecord) {
	pm.report(ctx, m, r, map[string]any{"phantomNodes": map[string]any{pm.a.NodeName: now()}})
}

func (pm *phantomManager) report(ctx context.Context, m *v1.Migration, r *phantomRecord, patch map[string]any) {
	if err := pm.a.patchStatus(ctx, m, patch); err != nil {
		pm.log.Warn("phantom: status report failed – will retry", "migration", m.Namespace+"/"+m.Name, "err", err)
		return
	}
	r.Reported = true
	_ = pm.save(r)
}

func (pm *phantomManager) programPeer(ctx context.Context, m *v1.Migration) (*phantomRecord, error) {
	start := time.Now()
	flows, err := flowsFromAPI(m.Status.Source.Phantom.Flows)
	if err != nil {
		return nil, err
	}
	tph := m.Status.Target.Phantom
	old, err1 := netip.ParseAddr(m.Status.SourcePodIP)
	new, err2 := netip.ParseAddr(tph.NewIP)
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	mig := phantom.Migration{ID: phantom.MigrationID(string(m.UID)), OldIP: old, NewIP: new}
	if a, err := netip.ParseAddr(tph.NodeIP); err == nil {
		mig.NewNodeIP = a
	}
	nc, err := pm.nodeContext(ctx, m, old, new, flows)
	if err != nil {
		return nil, err
	}
	r := &phantomRecord{UID: m.UID, Namespace: m.Namespace, Name: m.Name, ID: mig.ID}
	if err := pm.apply(r, mig, flows, nc); err != nil {
		return nil, err
	}
	rules := 0
	for _, p := range r.PerFlow {
		rules += len(p.Rules)
	}
	pm.log.Info("phantom: peer side programmed", "migration", m.Namespace+"/"+m.Name, "rules", rules, "ms", ms(time.Since(start)))
	pm.reportPeer(ctx, m, r)
	return r, nil
}

// apply plans every flow separately (so that each can be reverted alone),
// installs the union and persists the record before anything else can
// observe it.
func (pm *phantomManager) apply(r *phantomRecord, mig phantom.Migration, flows []phantom.Flow, nc phantom.NodeContext) error {
	// After chained migrations a flow's local address can be an earlier IP
	// of the pod: each flow is translated from its own to the new IP.
	plans, err := phantom.PlanFlows(mig, flows, nc)
	if err != nil {
		return err
	}
	var all phantom.PlanResult
	for _, p := range plans {
		r.PerFlow = append(r.PerFlow, p)
		all.Rules = append(all.Rules, p.Rules...)
		all.Attachments = appendNew(all.Attachments, p.Attachments...)
		all.Reservations = appendNew(all.Reservations, p.Reservations...)
		all.ConntrackReservations = appendNew(all.ConntrackReservations, p.ConntrackReservations...)
		all.Wire = append(all.Wire, p.Wire...)
	}
	t, err := pm.tr()
	if err != nil {
		return err
	}
	if r.Target {
		// Entries from an earlier stay of the pod on this node would make
		// every packet of a connection that is back at its old tuple
		// INVALID (see phantom/stalect.go). Before the placeholders: they
		// have the same shape.
		keep := pm.reservationsInUse(r.UID).ConntrackReservations
		if n, err := phantom.FlushStaleConntrack("", all.Wire, keep); err != nil {
			pm.log.Warn("phantom: stale conntrack entries", "migration", r.Namespace+"/"+r.Name, "err", err)
		} else if n > 0 {
			pm.log.Info("phantom: stale conntrack entries removed", "migration", r.Namespace+"/"+r.Name, "entries", n)
		}
	}
	r.Programmed = time.Now()
	if err := pm.save(r); err != nil {
		return err
	}
	pm.records[r.UID] = r
	if err := t.Apply(all); err != nil {
		// Remove what was installed so far and forget the record (no
		// tombstone): the next status event programs from scratch.
		pm.undo(r)
		return err
	}
	pm.ensureRoutes(r, mig, flows, all)
	pm.syncSteering()
	return pm.save(r)
}

// clearPending opens the migrated pod's inbound rules once the restored
// sockets exist, and aborts connections Phantom mode cannot keep (external
// peers) so that the application reconnects at once.
func (pm *phantomManager) clearPending(r *phantomRecord, sph *v1.SourcePhantom) {
	var pending []phantom.Rule
	for _, p := range r.PerFlow {
		pending = append(pending, p.PendingRules()...)
	}
	t, err := pm.tr()
	if err == nil {
		err = t.SetFlags(0, phantom.FlagPending, pending...)
	}
	if err != nil {
		pm.log.Error("phantom: clearing pending rules failed", "err", err)
		return
	}
	r.PendingCleared = true
	_ = pm.save(r)
	if sph == nil || sph.Unsupported == 0 {
		return
	}
	flows, err := flowsFromAPI(sph.Flows)
	if err != nil {
		return
	}
	var kill []phantom.Flow
	for _, f := range flows {
		if f.Class != phantom.ClassInCluster {
			kill = append(kill, f)
		}
	}
	n, err := phantom.KillFlows(r.Netns, kill)
	pm.log.Info("phantom: aborted connections to peers outside the cluster", "count", n, "err", err)
}

func appendNew[T comparable](dst []T, src ...T) []T {
	for _, v := range src {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

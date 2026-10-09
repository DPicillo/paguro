// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

// Phantom mode, UDP servers: the NAT bindings of their clients move to the new
// IP on every node (docs/PHANTOM-MODE.md, "UDP servers"; internal/ctguard,
// rebind.go).
//
// An unconnected UDP socket (game server, QUIC, DNS) has no peer to
// harvest, and its server knows each client by the address its datagrams
// come from – through a NodePort or LoadBalancer, the entry node's
// masquerade address and port. kube-proxy deletes the clients' entries
// to the old IP once the old endpoint stops serving; the next datagram is
// NATed afresh, and with MASQUERADE --random-fully (kube-proxy's default
// wherever iptables supports it) from another port: the server sees a
// stranger (measured on EKS: every player through the NLB timed out 30 s
// after a migration).
//
// So at the commit the source publishes the ports of the pod's unconnected
// UDP sockets (status.source.phantom.udpServerPorts). Every node then records
// its entries of clients that reached such a port through a Service –
// kube-proxy deletes them only seconds later, when the old endpoint stops
// serving. As soon as the target reports the new IP (status.target.phantom),
// the node replaces each of them with the same binding to the new IP: same
// client tuple, same masquerade port. The restored server's first datagram
// from such a client comes from the address it knows. Until 30 s after the
// restore the node keeps the moved bindings in place – against kube-proxy's
// clean-up, should it run before it counts the new address as serving, and
// against a datagram NATed afresh in between – with conntrack events and
// polling.
//
// Nothing to undo: before the commit nothing is touched (a rollback finds
// the old bindings as they were), and a moved binding is an ordinary NAT
// entry to the serving endpoint that ends with its flow. A rollback after
// the commit starts no move and ends a running guard.

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/ctguard"
	"paguro.dev/paguro/internal/phantom"
)

const (
	// udpRebindAfterRestore: how long after the restore a node keeps the
	// moved bindings in place (as long as the restored server's hold).
	udpRebindAfterRestore = 30 * time.Second
	// udpRebindAfterEnd: a migration that ended without a restore (cold
	// start, failure) is guarded this much longer.
	udpRebindAfterEnd = 5 * time.Second
	// udpRebindMax bounds the wait for the new IP and the guard.
	udpRebindMax = 3 * time.Minute
	// udpRebindPoll: conntrack events repair at once; the poll catches
	// what they miss (a full table dump each time) – events lost to a full
	// socket buffer when kube-proxy's clean-up deletes many entries at once.
	// Every 250 ms until 5 s after the restore (kube-proxy's clean-up of the
	// old endpoint: 2.5 s after the restore on EKS), then every second.
	udpRebindPoll     = 250 * time.Millisecond
	udpRebindPollLate = time.Second
	udpRebindPollFast = 5 * time.Second
	// udpRebindWait: how often the agent's cache is asked for the new IP.
	udpRebindWait = 50 * time.Millisecond
)

// harvestUDPServerPorts lists the frozen pod's UDP server ports for
// status.source.phantom (source, during the freeze). Best effort: without them
// those servers' clients are NATed afresh as before.
func harvestUDPServerPorts(netns, oldIP string, log *slog.Logger) []int32 {
	old, err := netip.ParseAddr(oldIP)
	if err != nil {
		return nil
	}
	ports, err := phantom.UDPServerPorts(netns, old)
	if err != nil {
		log.Warn("phantom: listing the pod's UDP servers failed – their clients through a NodePort or LoadBalancer may lose the session", "err", err)
		return nil
	}
	out := make([]int32, len(ports))
	for i, p := range ports {
		out[i] = int32(p)
	}
	return out
}

// udpRebindSpec is what a node needs to move the bindings, known from the
// commit on.
type udpRebindSpec struct {
	old   netip.Addr
	ports []uint16
	// translated: pod side and peer of the harvested UDP flows (connected
	// sockets) – Phantom mode translates those itself, their entries stay.
	translated map[[2]netip.AddrPort]bool
}

func (s udpRebindSpec) skip(e ctguard.Entry) bool {
	return s.translated[[2]netip.AddrPort{e.ReplySrc, e.ReplyDst}]
}

// udpRebindSpecOf returns the spec of a committed Phantom migration whose pod
// has UDP servers; ok is false when there is nothing to move.
func udpRebindSpecOf(m *v1.Migration) (udpRebindSpec, bool) {
	sph := m.Status.Source.Phantom
	if !isPhantom(m) || m.Status.IPPreserved || sph == nil || len(sph.UDPServerPorts) == 0 {
		return udpRebindSpec{}, false
	}
	old, err := netip.ParseAddr(m.Status.SourcePodIP)
	if err != nil {
		return udpRebindSpec{}, false
	}
	s := udpRebindSpec{old: old.Unmap(), translated: map[[2]netip.AddrPort]bool{}}
	for _, p := range sph.UDPServerPorts {
		if p > 0 && p <= 0xffff {
			s.ports = append(s.ports, uint16(p))
		}
	}
	if len(s.ports) == 0 {
		return udpRebindSpec{}, false
	}
	unmap := func(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }
	for _, f := range sph.Flows {
		if f.Proto != "udp" {
			continue
		}
		local, err := netip.ParseAddrPort(f.Local)
		if err != nil {
			continue
		}
		for _, peer := range []string{f.Remote, f.Wire} {
			if r, err := netip.ParseAddrPort(peer); err == nil {
				s.translated[[2]netip.AddrPort{unmap(local), unmap(r)}] = true
			}
		}
	}
	return s, true
}

// udpRebindNewIP returns the replacement's address once the target has
// programmed its side (the address every node translates to).
func udpRebindNewIP(m *v1.Migration, old netip.Addr) (netip.Addr, bool) {
	tph := m.Status.Target.Phantom
	if tph == nil || tph.ProgrammedAt == nil {
		return netip.Addr{}, false
	}
	n, err := netip.ParseAddr(tph.NewIP)
	if err != nil {
		return netip.Addr{}, false
	}
	n = n.Unmap()
	if n == old || n.Is4() != old.Is4() {
		return netip.Addr{}, false
	}
	return n, true
}

// udpConntrack is what the move needs from the kernel (fakes in tests).
type udpConntrack interface {
	Snapshot(old netip.Addr, ports []uint16, skip func(ctguard.Entry) bool) ([]ctguard.Entry, error)
	Ensure(want []ctguard.Entry) ([]ctguard.Entry, error)
	Watch(ctx context.Context, set *ctguard.Set, repaired func(ctguard.Entry, error)) error
}

// kernelConntrack is this node's conntrack table (host network namespace).
type kernelConntrack struct{}

// udpRebindConntrack is what rebindUDPServers works on (a fake in tests).
var udpRebindConntrack udpConntrack = kernelConntrack{}

func (kernelConntrack) Snapshot(old netip.Addr, ports []uint16, skip func(ctguard.Entry) bool) ([]ctguard.Entry, error) {
	return ctguard.SnapshotRebind(old, ports, skip)
}

func (kernelConntrack) Ensure(want []ctguard.Entry) ([]ctguard.Entry, error) {
	return ctguard.EnsureRetargeted(want)
}

func (kernelConntrack) Watch(ctx context.Context, set *ctguard.Set, repaired func(ctguard.Entry, error)) error {
	return ctguard.Watch(ctx, set, repaired)
}

// rebindRegistry holds this node's running guards by the address they
// moved the bindings to. A migration of the same pod that commits within
// the guard's window takes over: its bindings move on from that address,
// and two guards must not pull them in opposite directions.
type rebindRegistry struct {
	mu sync.Mutex
	m  map[netip.Addr]*rebindHold
}

type rebindHold struct{ cancel context.CancelFunc }

var udpRebinds = &rebindRegistry{}

// takeOver stops the guard that holds bindings at addr, if any.
func (r *rebindRegistry) takeOver(addr netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.m[addr]
	if ok {
		h.cancel()
		delete(r.m, addr)
	}
	return ok
}

// hold registers a guard of bindings at addr (stopping an earlier one);
// release unregisters it.
func (r *rebindRegistry) hold(addr netip.Addr, cancel context.CancelFunc) (release func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[netip.Addr]*rebindHold{}
	}
	if prev, ok := r.m[addr]; ok {
		prev.cancel()
	}
	h := &rebindHold{cancel: cancel}
	r.m[addr] = h
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.m[addr] == h {
			delete(r.m, addr)
		}
	}
}

// udpRebinder moves and guards one migration's bindings on this node.
type udpRebinder struct {
	ct  udpConntrack
	reg *rebindRegistry
	// get returns the migration's current state; nil, nil once it is gone.
	get   func(context.Context) (*v1.Migration, error)
	now   func() time.Time
	sleep func(context.Context, time.Duration) bool
	log   *slog.Logger
}

// run returns the number of bindings it moved.
func (r *udpRebinder) run(ctx context.Context, spec udpRebindSpec) int {
	if r.reg.takeOver(spec.old) {
		r.log.Info("phantom: a guard of the pod's previous migration held the UDP bindings – taking over")
	}
	clients, err := r.ct.Snapshot(spec.old, spec.ports, spec.skip)
	if err != nil {
		r.log.Warn("phantom: conntrack not readable – NAT bindings of the pod's UDP clients on this node are not moved", "err", err)
		return 0
	}
	if len(clients) == 0 {
		return 0 // no client of the pod's UDP servers enters the cluster here
	}
	r.log.Info("phantom: clients of the pod's UDP servers enter here – their NAT bindings move to the new IP",
		"clients", len(clients), "ports", spec.ports, "first", clients[0].String())
	started := r.now()
	var new netip.Addr
	for {
		m, err := r.get(ctx)
		if err == nil {
			if m == nil || rollingBack(m) {
				return 0
			}
			n, ok := udpRebindNewIP(m, spec.old)
			if ok {
				new = n
				break
			}
			if m.Status.Phase.Terminal() {
				return 0
			}
		}
		if r.now().Sub(started) >= udpRebindMax {
			r.log.Warn("phantom: the target never reported the new IP – the UDP clients' NAT bindings stay", "waited", udpRebindMax)
			return 0
		}
		if !r.sleep(ctx, udpRebindWait) {
			return 0
		}
	}
	want := ctguard.Retarget(clients, new)
	if len(want) == 0 {
		return 0
	}
	set := ctguard.RetargetedSet(want)
	gctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer r.reg.hold(new, cancel)()
	go func() {
		err := r.ct.Watch(gctx, set, func(e ctguard.Entry, err error) {
			if err != nil {
				r.log.Warn("phantom: keeping a moved UDP NAT binding", "entry", e.String(), "err", err)
				return
			}
			r.log.Info("phantom: moved UDP NAT binding re-installed at once", "entry", e.String())
		})
		if err != nil {
			r.log.Warn("phantom: watching conntrack events – the moved UDP NAT bindings are kept by polling only", "err", err)
		}
	}()
	return r.guard(gctx, set, new, len(want), started)
}

// guard installs the moved bindings and keeps them until the migration
// no longer needs them (udpRebindOver).
func (r *udpRebinder) guard(ctx context.Context, set *ctguard.Set, new netip.Addr, n int, started time.Time) int {
	var restoredSeen, endedSeen time.Time
	lastErr := ""
	for first := true; ; first = false {
		fixed, err := r.ct.Ensure(set.All())
		switch {
		case err != nil && err.Error() != lastErr:
			lastErr = err.Error()
			r.log.Warn("phantom: moving UDP NAT bindings", "err", err)
		case first:
			r.log.Info("phantom: UDP NAT bindings moved to the new IP", "bindings", n, "new", new)
		case len(fixed) > 0:
			r.log.Info("phantom: moved UDP NAT bindings re-installed", "entries", len(fixed), "first", fixed[0].String())
		}
		m, err := r.get(ctx)
		if err == nil {
			now := r.now()
			if m != nil && rollingBack(m) {
				// The source serves at the old address again: nothing to
				// keep at the new one.
				r.log.Info("phantom: the migration rolls back – the moved UDP NAT bindings are no longer kept")
				return n
			}
			if m != nil && m.Status.Target.RestoredAt != nil && restoredSeen.IsZero() {
				restoredSeen = now
			}
			if m != nil && m.Status.Phase.Terminal() && endedSeen.IsZero() {
				endedSeen = now
			}
			if udpRebindOver(m == nil, now, started, restoredSeen, endedSeen) {
				return n
			}
		}
		if r.now().Sub(started) >= udpRebindMax {
			return n // also while the migration cannot be read
		}
		poll := udpRebindPoll
		if !restoredSeen.IsZero() && r.now().Sub(restoredSeen) >= udpRebindPollFast {
			poll = udpRebindPollLate
		}
		if !r.sleep(ctx, poll) {
			return n // a later migration of the pod took over
		}
	}
}

// rollingBack: the migration is aborted after the commit (Frozen allows it:
// a warm target that never appears) – the source thaws at the old address.
func rollingBack(m *v1.Migration) bool {
	return m.Status.Phase == v1.PhaseAborting || m.Status.Phase == v1.PhaseRolledBack
}

// udpRebindOver: the moved bindings need no more guarding – the migration
// is gone, its restore (as this node saw it) is udpRebindAfterRestore past,
// it ended without a restore udpRebindAfterEnd ago, or the guard ran for
// udpRebindMax.
func udpRebindOver(gone bool, now, started, restoredSeen, endedSeen time.Time) bool {
	switch {
	case gone, now.Sub(started) >= udpRebindMax:
		return true
	case !restoredSeen.IsZero():
		return now.Sub(restoredSeen) >= udpRebindAfterRestore
	case !endedSeen.IsZero():
		return now.Sub(endedSeen) >= udpRebindAfterEnd
	}
	return false
}

// udpRebindDue reports whether this node starts the move for m: a
// committed migration that has not ended – or one that succeeded less than
// udpRebindAfterRestore after its restore. An agent that restarted during
// the migration, or whose events coalesced, may see it first as Succeeded
// (the commit and the end can be seconds apart), and its node's clients
// still need their bindings moved: kube-proxy's clean-up comes later, and
// entries it removed already are skipped.
func udpRebindDue(m *v1.Migration, now time.Time) bool {
	switch st := &m.Status; {
	case !st.Phase.Terminal():
		return true
	case st.Phase == v1.PhaseSucceeded:
		return st.Target.RestoredAt != nil && now.Sub(st.Target.RestoredAt.Time) < udpRebindAfterRestore
	}
	return false
}

// rebindUDPServers starts this node's move of the UDP servers' NAT
// bindings for a committed Phantom migration – once per migration and node.
func (a *Agent) rebindUDPServers(m *v1.Migration, log *slog.Logger) {
	spec, ok := udpRebindSpecOf(m)
	if !ok || !udpRebindDue(m, time.Now()) {
		return
	}
	a.mu.Lock()
	st := a.stateOf(m)
	started := st.udpRebind
	st.udpRebind = true
	a.mu.Unlock()
	if started {
		return
	}
	key, uid := client.ObjectKeyFromObject(m), m.UID
	r := &udpRebinder{ct: udpRebindConntrack, reg: udpRebinds, now: time.Now, sleep: sleepCtx,
		log: log.With("role", "udp-rebind"),
		get: func(ctx context.Context) (*v1.Migration, error) {
			cur := &v1.Migration{}
			if err := a.Client.Get(ctx, key, cur); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, nil
				}
				return nil, err
			}
			if cur.UID != uid {
				return nil, nil
			}
			return cur, nil
		}}
	go r.run(context.Background(), spec)
}

// sleepCtx sleeps for d; false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

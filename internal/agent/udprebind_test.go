// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/ctguard"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/netadapter"
)

// The Xonotic migration on EKS: OLD 192.168.90.1, the server on :26000.
func udpMigration() *v1.Migration {
	return &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "xonotic", UID: "mig-uid"},
		Status: v1.MigrationStatus{Phase: v1.PhaseRestoring, NetworkAdapter: netadapter.NamePhantom,
			SourceNode: "node-b", TargetNode: "node-t", SourcePodIP: "192.168.90.1",
			Source: v1.SourceStatus{Phantom: &v1.SourcePhantom{UDPServerPorts: []int32{26000},
				Flows: []v1.PhantomFlow{
					// A connected UDP socket of the pod: Phantom mode
					// translates it.
					{Proto: "udp", Local: "192.168.90.1:26000", Remote: "192.168.78.222:2004", Class: "in-cluster", Server: true},
					{Proto: "tcp", Local: "192.168.90.1:8080", Remote: "192.168.78.222:2005", Class: "in-cluster", Server: true},
				}}}}}
}

func programmed(m *v1.Migration, newIP string) {
	m.Status.Target.Phantom = &v1.TargetPhantom{NewIP: newIP, NodeIP: "192.168.70.5", ProgrammedAt: &metav1.MicroTime{Time: time.Now()}}
}

func TestUDPRebindSpecOf(t *testing.T) {
	s, ok := udpRebindSpecOf(udpMigration())
	if !ok || s.old != netip.MustParseAddr("192.168.90.1") || !slices.Equal(s.ports, []uint16{26000}) {
		t.Fatalf("spec %+v %v", s, ok)
	}
	translated := ctguard.Entry{ReplySrc: netip.MustParseAddrPort("192.168.90.1:26000"), ReplyDst: netip.MustParseAddrPort("192.168.78.222:2004")}
	player := ctguard.Entry{ReplySrc: netip.MustParseAddrPort("192.168.90.1:26000"), ReplyDst: netip.MustParseAddrPort("192.168.78.222:63723")}
	if !s.skip(translated) || s.skip(player) {
		t.Errorf("skip: translated flow %v, player %v", s.skip(translated), s.skip(player))
	}
	for name, mod := range map[string]func(*v1.Migration){
		"kept IP":       func(m *v1.Migration) { m.Status.IPPreserved = true },
		"not phantom":   func(m *v1.Migration) { m.Status.NetworkAdapter = netadapter.NameCalico },
		"not committed": func(m *v1.Migration) { m.Status.Source.Phantom = nil },
		"no UDP server": func(m *v1.Migration) { m.Status.Source.Phantom.UDPServerPorts = nil },
		"bad port":      func(m *v1.Migration) { m.Status.Source.Phantom.UDPServerPorts = []int32{0, 70000} },
		"bad old IP":    func(m *v1.Migration) { m.Status.SourcePodIP = "" },
	} {
		m := udpMigration()
		mod(m)
		if _, ok := udpRebindSpecOf(m); ok {
			t.Errorf("%s: spec returned", name)
		}
	}
}

func TestUDPRebindNewIP(t *testing.T) {
	old := netip.MustParseAddr("192.168.90.1")
	m := udpMigration()
	if _, ok := udpRebindNewIP(m, old); ok {
		t.Error("new IP before the target programmed")
	}
	m.Status.Target.Phantom = &v1.TargetPhantom{NewIP: "192.168.93.7"}
	if _, ok := udpRebindNewIP(m, old); ok {
		t.Error("new IP without programmedAt")
	}
	for ip, want := range map[string]bool{"192.168.93.7": true, "192.168.90.1": false, "fd00::7": false, "": false} {
		programmed(m, ip)
		if n, ok := udpRebindNewIP(m, old); ok != want || (ok && n.String() != ip) {
			t.Errorf("%q: %v %v", ip, n, ok)
		}
	}
}

func TestUDPRebindOver(t *testing.T) {
	t0 := time.Unix(1000, 0)
	var zero time.Time
	for _, c := range []struct {
		name                 string
		gone                 bool
		now, restored, ended time.Time
		over                 bool
	}{
		{"running", false, t0.Add(10 * time.Second), zero, zero, false},
		{"gone", true, t0, zero, zero, true},
		{"restored 29 s ago", false, t0.Add(31 * time.Second), t0.Add(2 * time.Second), zero, false},
		{"restored 30 s ago", false, t0.Add(32 * time.Second), t0.Add(2 * time.Second), zero, true},
		{"succeeded right after the restore", false, t0.Add(10 * time.Second), t0.Add(2 * time.Second), t0.Add(3 * time.Second), false},
		{"ended without restore", false, t0.Add(9 * time.Second), zero, t0.Add(3 * time.Second), true},
		{"limit", false, t0.Add(udpRebindMax), zero, zero, true},
	} {
		if got := udpRebindOver(c.gone, c.now, t0, c.restored, c.ended); got != c.over {
			t.Errorf("%s: over = %v", c.name, got)
		}
	}
}

// fakeConntrack records the calls in order.
type fakeConntrack struct {
	mu       sync.Mutex
	clients  []ctguard.Entry
	calls    []string
	ensured  [][]ctguard.Entry
	watching chan *ctguard.Set
}

func (f *fakeConntrack) Snapshot(old netip.Addr, ports []uint16, skip func(ctguard.Entry) bool) ([]ctguard.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "snapshot")
	var out []ctguard.Entry
	for _, e := range f.clients {
		if e.ReplySrc.Addr() == old && slices.Contains(ports, e.ReplySrc.Port()) && !skip(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeConntrack) Ensure(want []ctguard.Entry) ([]ctguard.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "ensure")
	f.ensured = append(f.ensured, want)
	return nil, nil
}

func (f *fakeConntrack) Watch(ctx context.Context, set *ctguard.Set, _ func(ctguard.Entry, error)) error {
	f.watching <- set
	<-ctx.Done()
	return nil
}

func (f *fakeConntrack) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// fakeClock: sleep advances the time; script changes the migration at given times.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) bool {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return ctx.Err() == nil
}

var (
	nlbPlayer = ctguard.Entry{Proto: 17,
		OrigSrc: netip.MustParseAddrPort("3.67.9.3:46683"), OrigDst: netip.MustParseAddrPort("192.168.78.222:31716"),
		ReplySrc: netip.MustParseAddrPort("192.168.90.1:26000"), ReplyDst: netip.MustParseAddrPort("192.168.78.222:63723")}
	translatedFlow = ctguard.Entry{Proto: 17,
		OrigSrc: netip.MustParseAddrPort("3.67.9.3:46684"), OrigDst: netip.MustParseAddrPort("192.168.78.222:31716"),
		ReplySrc: netip.MustParseAddrPort("192.168.90.1:26000"), ReplyDst: netip.MustParseAddrPort("192.168.78.222:2004")}
)

// The order on a node: snapshot at the commit, nothing touched until the
// target reports the new IP, then the moved bindings, kept until 30 s after
// the restore.
func TestUDPRebinderOrder(t *testing.T) {
	ct := &fakeConntrack{clients: []ctguard.Entry{nlbPlayer, translatedFlow}, watching: make(chan *ctguard.Set, 1)}
	clock := &fakeClock{now: time.Unix(1000, 0)}
	start := clock.Now()
	m := udpMigration()
	ensuresBeforeNewIP := -1
	get := func(context.Context) (*v1.Migration, error) {
		cur := m.DeepCopy()
		el := clock.Now().Sub(start)
		if el >= 400*time.Millisecond {
			programmed(cur, "192.168.93.7")
		} else {
			ensuresBeforeNewIP = len(ct.ensured)
		}
		if el >= 2*time.Second {
			cur.Status.Target.RestoredAt = &metav1.MicroTime{Time: start.Add(2 * time.Second)}
		}
		if el >= 3*time.Second {
			cur.Status.Phase = v1.PhaseSucceeded
		}
		return cur, nil
	}
	reg := &rebindRegistry{}
	r := &udpRebinder{ct: ct, reg: reg, get: get, now: clock.Now, sleep: clock.Sleep, log: slog.New(slog.DiscardHandler)}
	spec, _ := udpRebindSpecOf(m)
	if n := r.run(context.Background(), spec); n != 1 {
		t.Fatalf("moved %d bindings, want 1 (the translated flow stays)", n)
	}
	calls := ct.callLog()
	snapshots := 0
	for _, c := range calls {
		if c == "snapshot" {
			snapshots++
		}
	}
	if calls[0] != "snapshot" || snapshots != 1 {
		t.Fatalf("calls %v: one snapshot, first", calls)
	}
	if ensuresBeforeNewIP != 0 {
		t.Fatalf("%d installs before the target reported the new IP", ensuresBeforeNewIP)
	}
	want := []ctguard.Entry{nlbPlayer}
	want[0].ReplySrc = netip.MustParseAddrPort("192.168.93.7:26000")
	if !slices.Equal(ct.ensured[0], want) {
		t.Fatalf("first install %v, want %v (same client tuple and masquerade port)", ct.ensured[0], want)
	}
	// Restored at 2 s (seen by the node at its next poll), kept 30 s.
	elapsed := clock.Now().Sub(start)
	if elapsed < 32*time.Second || elapsed > 33*time.Second {
		t.Errorf("guard ended %s after the commit, want 30 s after the restore at 2 s", elapsed)
	}
	// 250 ms polls until 5 s after the restore, then one a second.
	if n := len(ct.ensured); n < 45 || n > 60 {
		t.Errorf("%d installs, want one per %s until 5 s after the restore, then one per %s", n, udpRebindPoll, udpRebindPollLate)
	}
	select {
	case set := <-ct.watching:
		if all := set.All(); len(all) != 1 || all[0] != want[0] {
			t.Errorf("watched %v", all)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no conntrack watch")
	}
	if len(reg.m) != 0 {
		t.Error("guard still registered after its end")
	}
}

func TestUDPRebinderNothingToMove(t *testing.T) {
	ct := &fakeConntrack{watching: make(chan *ctguard.Set, 1)}
	clock := &fakeClock{now: time.Unix(1000, 0)}
	gets := 0
	r := &udpRebinder{ct: ct, reg: &rebindRegistry{}, now: clock.Now, sleep: clock.Sleep, log: slog.New(slog.DiscardHandler),
		get: func(context.Context) (*v1.Migration, error) { gets++; return udpMigration(), nil }}
	spec, _ := udpRebindSpecOf(udpMigration())
	if n := r.run(context.Background(), spec); n != 0 || gets != 0 || !slices.Equal(ct.callLog(), []string{"snapshot"}) {
		t.Fatalf("no client here: moved %d, %d reads, calls %v", n, gets, ct.callLog())
	}
	// The migration goes away before the target reports the new IP.
	ct = &fakeConntrack{clients: []ctguard.Entry{nlbPlayer}, watching: make(chan *ctguard.Set, 1)}
	r.ct = ct
	r.get = func(context.Context) (*v1.Migration, error) {
		if clock.Now().Sub(time.Unix(1000, 0)) > time.Second {
			return nil, nil
		}
		return udpMigration(), nil
	}
	if n := r.run(context.Background(), spec); n != 0 || slices.Contains(ct.callLog(), "ensure") {
		t.Fatalf("migration gone: moved %d, calls %v", n, ct.callLog())
	}
}

// A chained migration of the same pod takes over the guard of the one
// before it on this node: its bindings move on from that address.
func TestRebindRegistryTakeOver(t *testing.T) {
	reg := &rebindRegistry{}
	addr := netip.MustParseAddr("192.168.93.7")
	ctx1, cancel1 := context.WithCancel(context.Background())
	release1 := reg.hold(addr, cancel1)
	if !reg.takeOver(addr) || ctx1.Err() == nil {
		t.Fatal("first guard not stopped")
	}
	_, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	reg.hold(addr, cancel2)
	release1() // the first guard ends late: must not unregister the second
	if _, ok := reg.m[addr]; !ok {
		t.Fatal("a late release removed the newer guard")
	}
	if reg.takeOver(netip.MustParseAddr("192.168.90.1")) {
		t.Fatal("took over a guard that does not exist")
	}
}

// Every node starts the move once per migration, and only for a committed
// Phantom migration with UDP servers.
func TestReconcileStartsUDPRebindOnce(t *testing.T) {
	layout.StateDir = t.TempDir()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	ct := &fakeConntrack{watching: make(chan *ctguard.Set, 1)}
	prev := udpRebindConntrack
	udpRebindConntrack = ct
	defer func() { udpRebindConntrack = prev }()
	mig := udpMigration()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.Migration{}).WithObjects(mig).Build()
	a := &Agent{Client: cl, APIReader: cl, NodeName: "node-c", Log: slog.New(slog.DiscardHandler)}
	a.init()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(mig)}
	for range 3 {
		if _, err := a.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(ct.callLog()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if calls := ct.callLog(); !slices.Equal(calls, []string{"snapshot"}) {
		t.Fatalf("calls %v, want one snapshot for three events", calls)
	}
	if !a.states[mig.UID].udpRebind {
		t.Fatal("state not recorded")
	}
}

// The move starts for a migration that has not ended, and for one this
// node sees first as Succeeded shortly after the restore (an agent that
// restarted meanwhile) – not later, and not after any other end.
func TestUDPRebindDue(t *testing.T) {
	now := time.Unix(10000, 0)
	at := func(d time.Duration) *metav1.MicroTime { return &metav1.MicroTime{Time: now.Add(-d)} }
	for _, c := range []struct {
		name     string
		phase    v1.Phase
		restored *metav1.MicroTime
		due      bool
	}{
		{"restoring", v1.PhaseRestoring, nil, true},
		{"cutting over", v1.PhaseCuttingOver, nil, true},
		{"succeeded just now", v1.PhaseSucceeded, at(3 * time.Second), true},
		{"succeeded long ago", v1.PhaseSucceeded, at(udpRebindAfterRestore), false},
		{"succeeded by a cold start", v1.PhaseSucceeded, nil, false},
		{"failed", v1.PhaseFailed, at(time.Second), false},
		{"rolled back", v1.PhaseRolledBack, nil, false},
	} {
		m := udpMigration()
		m.Status.Phase, m.Status.Target.RestoredAt = c.phase, c.restored
		if got := udpRebindDue(m, now); got != c.due {
			t.Errorf("%s: due %v, want %v", c.name, got, c.due)
		}
	}
}

// An agent that first sees the migration as Succeeded, right after the
// restore, still moves its clients' bindings.
func TestReconcileStartsUDPRebindAfterTheEnd(t *testing.T) {
	layout.StateDir = t.TempDir()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	ct := &fakeConntrack{watching: make(chan *ctguard.Set, 1)}
	prev := udpRebindConntrack
	udpRebindConntrack = ct
	defer func() { udpRebindConntrack = prev }()
	mig := udpMigration()
	mig.Status.Phase = v1.PhaseSucceeded
	mig.Status.Target.RestoredAt = &metav1.MicroTime{Time: time.Now().Add(-2 * time.Second)}
	programmed(mig, "192.168.93.7")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.Migration{}).WithObjects(mig).Build()
	a := &Agent{Client: cl, APIReader: cl, NodeName: "node-c", Log: slog.New(slog.DiscardHandler)}
	a.init()
	if _, err := a.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(mig)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(ct.callLog()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls := ct.callLog(); len(calls) == 0 || calls[0] != "snapshot" {
		t.Fatalf("calls %v: the move did not start", calls)
	}
}

// A rollback after the commit: no move once the migration aborts, and a
// guard that runs stops keeping the bindings at the new address.
func TestUDPRebinderRollback(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	start := clock.Now()
	spec, _ := udpRebindSpecOf(udpMigration())
	// Aborting while the target had reported its address.
	ct := &fakeConntrack{clients: []ctguard.Entry{nlbPlayer}, watching: make(chan *ctguard.Set, 1)}
	r := &udpRebinder{ct: ct, reg: &rebindRegistry{}, now: clock.Now, sleep: clock.Sleep, log: slog.New(slog.DiscardHandler),
		get: func(context.Context) (*v1.Migration, error) {
			m := udpMigration()
			m.Status.Phase = v1.PhaseAborting
			programmed(m, "192.168.93.7")
			return m, nil
		}}
	if n := r.run(context.Background(), spec); n != 0 || slices.Contains(ct.callLog(), "ensure") {
		t.Fatalf("aborting: moved %d, calls %v", n, ct.callLog())
	}
	// Moved, then aborted: the guard ends at once, long before 30 s.
	ct = &fakeConntrack{clients: []ctguard.Entry{nlbPlayer}, watching: make(chan *ctguard.Set, 1)}
	r.ct = ct
	start = clock.Now()
	r.get = func(context.Context) (*v1.Migration, error) {
		m := udpMigration()
		programmed(m, "192.168.93.7")
		if clock.Now().Sub(start) >= time.Second {
			m.Status.Phase = v1.PhaseAborting
		}
		return m, nil
	}
	if n := r.run(context.Background(), spec); n != 1 {
		t.Fatalf("moved %d", n)
	}
	if el := clock.Now().Sub(start); el > 2*time.Second {
		t.Errorf("guarded %s after the rollback began", el)
	}
}

// The guard ends after udpRebindMax also when the migration cannot be read.
func TestUDPRebinderGuardBoundedWithoutReads(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	start := clock.Now()
	spec, _ := udpRebindSpecOf(udpMigration())
	ct := &fakeConntrack{clients: []ctguard.Entry{nlbPlayer}, watching: make(chan *ctguard.Set, 1)}
	r := &udpRebinder{ct: ct, reg: &rebindRegistry{}, now: clock.Now, sleep: clock.Sleep, log: slog.New(slog.DiscardHandler),
		get: func(context.Context) (*v1.Migration, error) {
			if clock.Now().Sub(start) < time.Second {
				m := udpMigration()
				programmed(m, "192.168.93.7")
				return m, nil
			}
			return nil, errors.New("the cache is gone")
		}}
	if n := r.run(context.Background(), spec); n != 1 {
		t.Fatalf("moved %d", n)
	}
	if el := clock.Now().Sub(start); el < udpRebindMax || el > udpRebindMax+2*time.Second {
		t.Errorf("guard ended after %s, want %s", el, udpRebindMax)
	}
}

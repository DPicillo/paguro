// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/pkg/names"
)

func gateEnv(t *testing.T, phase v1.Phase) (*commitGate, client.Client, *v1.Migration, *resourceapi.ResourceClaim) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	mig := &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "ns", UID: "mig-uid"},
		Status: v1.MigrationStatus{Phase: phase}}
	claim := &resourceapi.ResourceClaim{ObjectMeta: metav1.ObjectMeta{Name: "paguro-gate-migui", Namespace: "ns", UID: "claim-uid",
		Labels: map[string]string{names.LabelMigrationUID: "mig-uid"}}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.Migration{}).WithObjects(mig, claim).Build()
	a := &Agent{Client: cl, APIReader: cl, Log: slog.New(slog.DiscardHandler)}
	return &commitGate{a: a, log: a.Log}, cl, mig, claim
}

// Held until the commit: reported as staged (the source freezes on that),
// released when the migration is committed.
func TestCommitGateHoldsUntilCommit(t *testing.T) {
	g, cl, mig, claim := gateEnv(t, v1.PhasePreCopy)
	done := make(chan error, 1)
	go func() { done <- g.hold(context.Background(), claim) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cur := &v1.Migration{}
		_ = cl.Get(context.Background(), client.ObjectKeyFromObject(mig), cur)
		if cur.Status.Target.SandboxStagedAt != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not reported as staged")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("released before the commit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cur := &v1.Migration{}
	_ = cl.Get(context.Background(), client.ObjectKeyFromObject(mig), cur)
	cur.Status.Phase = v1.PhaseFrozen
	if err := cl.Status().Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("not released after the commit")
	}
}

// After the migration – kubelet prepares again after its own restart – and
// for a rolled-back one the gate does not hold.
func TestCommitGateAfterTheMigration(t *testing.T) {
	g, _, _, claim := gateEnv(t, v1.PhaseSucceeded)
	if err := g.hold(context.Background(), claim); err != nil {
		t.Fatalf("succeeded: %v", err)
	}
	g, _, _, claim = gateEnv(t, v1.PhaseRolledBack)
	if err := g.hold(context.Background(), claim); err == nil {
		t.Fatal("rolled back: the replacement must not start")
	}
	// Failed after the commit: the replacement is the only copy, it must start.
	g, cl, mig, claim := gateEnv(t, v1.PhaseFailed)
	cur := &v1.Migration{}
	_ = cl.Get(context.Background(), client.ObjectKeyFromObject(mig), cur)
	cur.Status.Cutover.SourceDeletedAt = &metav1.MicroTime{Time: time.Now()}
	_ = cl.Status().Update(context.Background(), cur)
	if err := g.hold(context.Background(), claim); err != nil {
		t.Fatalf("failed after the commit: %v", err)
	}
	g, cl, mig, claim = gateEnv(t, v1.PhasePreCopy)
	_ = cl.Delete(context.Background(), mig)
	if err := g.hold(context.Background(), claim); err != nil {
		t.Fatalf("migration gone: %v", err)
	}
}

// Early hand-over: released as soon as the source reports the pause; an
// abort releases the hold with an error at once.
func TestCommitGateEarlyHandOver(t *testing.T) {
	layout.StateDir = t.TempDir()
	g, cl, mig, claim := gateEnv(t, v1.PhasePreCopy)
	cur := &v1.Migration{}
	_ = cl.Get(context.Background(), client.ObjectKeyFromObject(mig), cur)
	cur.Status.Network.EarlyHandOver = true
	if err := cl.Status().Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.hold(context.Background(), claim) }()
	select {
	case err := <-done:
		t.Fatalf("released before the hand-over: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	srv := httptest.NewServer((&Server{Token: "t"}).Handler())
	defer srv.Close()
	c, _ := NewClient(strings.TrimPrefix(srv.URL, "http://"), "t", nil, "")
	if err := c.HandOver(context.Background(), "mig-uid"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("not released on the hand-over")
	}

	g, cl, mig, claim = gateEnv(t, v1.PhasePreCopy)
	go func() { done <- g.hold(context.Background(), claim) }()
	time.Sleep(50 * time.Millisecond)
	_ = cl.Get(context.Background(), client.ObjectKeyFromObject(mig), cur)
	cur.Status.Phase = v1.PhaseAborting
	_ = cl.Status().Update(context.Background(), cur)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("aborting: the replacement must not start")
		}
	case <-time.After(time.Second):
		t.Fatal("an abort must end the hold at once")
	}
}

func TestMarkAborted(t *testing.T) {
	layout.StateDir = t.TempDir()
	at := &metav1.MicroTime{Time: time.Now()}
	for _, c := range []struct {
		phase   v1.Phase
		deleted *metav1.MicroTime
		want    bool
	}{
		{v1.PhaseAborting, nil, true},
		{v1.PhaseRolledBack, nil, true},
		{v1.PhaseFailed, nil, true},
		{v1.PhaseFailed, at, false}, // after the commit: the replacement is the only copy
		{v1.PhaseRestoring, at, false},
		{v1.PhasePreCopy, nil, false},
	} {
		m := &v1.Migration{Status: v1.MigrationStatus{Phase: c.phase}}
		m.Status.Cutover.SourceDeletedAt = c.deleted
		if got := abortedBeforeCommit(m); got != c.want {
			t.Errorf("%s (source deleted %v): %v, want %v", c.phase, c.deleted != nil, got, c.want)
		}
	}
	if err := markAborted("u1"); err != nil {
		t.Fatal(err)
	}
	if !layout.Exists(filepath.Join(layout.Root("u1"), v1.FileAborted)) {
		t.Fatal("marker missing")
	}
}

// Calico: after the commit the gate holds until the source's sandbox is gone
// (hand-over), at most handOverWait.
func TestCommitGateWaitsForSourceStop(t *testing.T) {
	layout.StateDir = t.TempDir()
	g, cl, mig, claim := gateEnv(t, v1.PhaseFrozen)
	src := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "ns", UID: "src-uid"}}
	if err := cl.Create(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	cur := &v1.Migration{}
	_ = cl.Get(context.Background(), client.ObjectKeyFromObject(mig), cur)
	cur.Spec.PodName = "web-1"
	if err := cl.Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	cur.Status.Network.HandOverAfterSourceStop = true
	cur.Status.Source.FrozenAt = &metav1.MicroTime{Time: time.Now()}
	cur.Status.SourcePodUID = "src-uid"
	if err := cl.Status().Update(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.hold(context.Background(), claim) }()
	select {
	case err := <-done:
		t.Fatalf("released before the source's sandbox was gone: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	srv := httptest.NewServer((&Server{Token: "t"}).Handler())
	defer srv.Close()
	c, _ := NewClient(strings.TrimPrefix(srv.URL, "http://"), "t", nil, "")
	if err := c.HandOver(context.Background(), "mig-uid"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("not released on the hand-over")
	}

	// No hand-over (its message lost): released once the source pod is gone.
	layout.StateDir = t.TempDir()
	go func() { done <- g.hold(context.Background(), claim) }()
	select {
	case err := <-done:
		t.Fatalf("released while the source pod exists: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	if err := cl.Delete(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("not released when the source pod was gone")
	}

	// No hand-over (source agent gone): released after handOverWait.
	m := cur.DeepCopy()
	m.Status.Source.FrozenAt = &metav1.MicroTime{Time: time.Now().Add(-handOverWait - time.Second)}
	if !handOverOverdue(m) {
		t.Fatal("overdue hand-over not detected")
	}
}

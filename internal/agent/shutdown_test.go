// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// Drain marks the node, waits for the migrations this node takes part in
// (not for others) and withdraws the endpoint at the end.
func TestDrainWaitsForThisNodesMigrations(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	mig := func(name, source, target string, phase v1.Phase) *v1.Migration {
		return &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name)},
			Status: v1.MigrationStatus{Phase: phase, SourceNode: source, TargetNode: target}}
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1",
		Annotations: map[string]string{v1.AnnotationNodeAgent: "10.0.0.1:9555", "other": "kept"}}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node,
		mig("mine", "n0", "n1", v1.PhasePreCopy),
		mig("others", "n2", "n3", v1.PhasePreCopy),
		mig("ended", "n1", "n2", v1.PhaseSucceeded)).Build()
	a := &Agent{Client: cl, APIReader: cl, NodeName: "n1", Version: "v2", Host: &Host{Root: t.TempDir()},
		Log: slog.New(slog.DiscardHandler)}
	a.transferUp.Store(true)
	a.Endpoint = "10.0.0.1:9555"

	draining := make(chan string, 1)
	go func() {
		// The node is marked while the migration runs; then it ends.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			n := &corev1.Node{}
			_ = cl.Get(context.Background(), client.ObjectKey{Name: "n1"}, n)
			if v := n.Annotations[v1.AnnotationNodeAgentDraining]; v != "" {
				draining <- v
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		close(draining)
		m := &v1.Migration{}
		_ = cl.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "mine"}, m)
		m.Status.Phase = v1.PhaseSucceeded
		_ = cl.Update(context.Background(), m)
	}()

	start := time.Now()
	a.Drain(context.Background(), 10*time.Second)
	if since := <-draining; since == "" {
		t.Fatal("the node was never marked as draining")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("drain took %s: it waited for another node's migration", d)
	}
	n := &corev1.Node{}
	_ = cl.Get(context.Background(), client.ObjectKey{Name: "n1"}, n)
	if _, ok := n.Annotations[v1.AnnotationNodeAgent]; ok {
		t.Error("the endpoint must be withdrawn after the drain")
	}
	if _, ok := n.Annotations[v1.AnnotationNodeAgentDraining]; ok {
		t.Error("the draining mark must go with the agent")
	}
	if n.Annotations["other"] != "kept" || n.Annotations[v1.AnnotationNodeAgentVersion] != "v2" {
		t.Errorf("other annotations must stay: %v", n.Annotations)
	}
	// A late periodic annotation must not bring the endpoint back.
	_ = a.AnnotateNode(context.Background())
	_ = cl.Get(context.Background(), client.ObjectKey{Name: "n1"}, n)
	if _, ok := n.Annotations[v1.AnnotationNodeAgent]; ok {
		t.Error("AnnotateNode after the drain re-published the endpoint")
	}
}

// The drain gives up at its timeout and still withdraws the endpoint.
func TestDrainTimeout(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", Annotations: map[string]string{v1.AnnotationNodeAgent: "x"}}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node, &v1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "stuck", Namespace: "ns"},
		Status:     v1.MigrationStatus{Phase: v1.PhaseRestoring, TargetNode: "n1"}}).Build()
	a := &Agent{Client: cl, NodeName: "n1", Host: &Host{Root: t.TempDir()}, Log: slog.New(slog.DiscardHandler)}
	start := time.Now()
	a.Drain(context.Background(), 1500*time.Millisecond)
	if d := time.Since(start); d < time.Second || d > 4*time.Second {
		t.Fatalf("drain returned after %s, want ~1.5 s", d)
	}
	n := &corev1.Node{}
	_ = cl.Get(context.Background(), client.ObjectKey{Name: "n1"}, n)
	if _, ok := n.Annotations[v1.AnnotationNodeAgent]; ok {
		t.Error("the endpoint must be withdrawn after a drain timeout")
	}
}

// A cache that never started blocks every List until its context ends; the
// drain gives up after drainListTimeout, not after its own timeout.
func TestDrainWithoutCache(t *testing.T) {
	oldTimeout, oldAttempt := drainListTimeout, drainListAttempt
	drainListTimeout, drainListAttempt = 300*time.Millisecond, 100*time.Millisecond
	defer func() { drainListTimeout, drainListAttempt = oldTimeout, oldAttempt }()
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	cl := interceptor.NewClient(fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build(), interceptor.Funcs{
		List: func(ctx context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			<-ctx.Done()
			return ctx.Err()
		}})
	a := &Agent{Client: cl, NodeName: "n1", Host: &Host{Root: t.TempDir()}, Log: slog.New(slog.DiscardHandler)}
	start := time.Now()
	a.Drain(context.Background(), 10*time.Minute)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("drain returned after %s, want well under its 10 min timeout", d)
	}
}

// Old failures are rescued only while their replacement still waits here;
// recent ones always (the replacement may not exist yet).
func TestRescueNeeded(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	waiting := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns",
		Annotations: map[string]string{v1.AnnotationRestoreID: "waits"}}, Spec: corev1.PodSpec{NodeName: "n1"},
		Status: corev1.PodStatus{Phase: corev1.PodPending}}
	running := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns",
		Annotations: map[string]string{v1.AnnotationRestoreID: "runs"}}, Spec: corev1.PodSpec{NodeName: "n1"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waiting, running).Build()
	a := &Agent{Client: cl, NodeName: "n1"}
	failed := func(uid string, ago time.Duration) *v1.Migration {
		at := metav1.NewMicroTime(time.Now().Add(-ago))
		return &v1.Migration{ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid)},
			Status: v1.MigrationStatus{Phase: v1.PhaseFailed, PhaseChangedAt: &at}}
	}
	for _, c := range []struct {
		m    *v1.Migration
		want bool
	}{
		{failed("gone", time.Minute), true},
		{failed("gone", 3*24*time.Hour), false},
		{failed("runs", 3*24*time.Hour), false},
		{failed("waits", 3*24*time.Hour), true},
	} {
		if got := a.rescueNeeded(context.Background(), c.m); got != c.want {
			t.Errorf("%s failed %s ago: rescue %v, want %v", c.m.UID, time.Since(c.m.Status.PhaseChangedAt.Time).Round(time.Minute), got, c.want)
		}
	}
}

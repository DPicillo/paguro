// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"paguro.dev/paguro/api/v1alpha1"
)

// With PerNode migrations under way from the pod's node, a new one stays
// Pending with the reason and starts once one of them has ended.
func TestQueuePerNode(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	running := func(name string, phase v1alpha1.Phase, node string) *v1alpha1.Migration {
		return &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(name)},
			Spec:   v1alpha1.MigrationSpec{PodName: "pod-" + name},
			Status: v1alpha1.MigrationStatus{Phase: phase, SourceNode: node}}
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "game", Namespace: ns}, Spec: corev1.PodSpec{NodeName: "node-a"}}
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: ns, UID: "new"},
		Spec: v1alpha1.MigrationSpec{PodName: "game"}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.Migration{}).WithObjects(
		pod, mig,
		running("a", v1alpha1.PhasePreCopy, "node-a"),
		running("b", v1alpha1.PhaseRestoring, "node-a"),
		running("c", v1alpha1.PhasePreflight, "node-a"),
		running("d", v1alpha1.PhaseSucceeded, "node-a"), // ended
		running("e", v1alpha1.PhasePreCopy, "node-b"),   // another node
		running("f", v1alpha1.PhasePending, "node-a"),   // queued itself
	).Build()
	r := &MigrationReconciler{Client: cl, APIReader: cl, Clock: clocktesting.NewFakeClock(time.Now()), PerNode: 3}

	if _, err := r.start(ctx, mig); err != nil {
		t.Fatal(err)
	}
	got := &v1alpha1.Migration{}
	_ = cl.Get(ctx, client.ObjectKeyFromObject(mig), got)
	if got.Status.Phase != v1alpha1.PhasePending || !strings.Contains(got.Status.Message, "3 migrations from node node-a") {
		t.Fatalf("want queued, got %s: %q", got.Status.Phase, got.Status.Message)
	}

	done := running("a", v1alpha1.PhaseSucceeded, "node-a")
	cur := &v1alpha1.Migration{}
	_ = cl.Get(ctx, client.ObjectKeyFromObject(done), cur)
	cur.Status.Phase = v1alpha1.PhaseSucceeded
	if err := cl.Status().Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if _, err := r.start(ctx, got); err != nil {
		t.Fatal(err)
	}
	_ = cl.Get(ctx, client.ObjectKeyFromObject(mig), got)
	if got.Status.Phase != v1alpha1.PhasePreflight || got.Status.SourceNode != "node-a" || got.Status.StartedAt == nil {
		t.Fatalf("want Preflight from node-a, got %s %q", got.Status.Phase, got.Status.SourceNode)
	}
}

// Without a bound, or for a pod that does not exist (the preflight
// reports it), nothing waits.
func TestQueueUnbounded(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns}, Spec: v1alpha1.MigrationSpec{PodName: "missing"}}
	lists := 0
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mig).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, l client.ObjectList, o ...client.ListOption) error {
			lists++
			return c.List(ctx, l, o...)
		}}).Build()
	r := &MigrationReconciler{Client: cl, APIReader: cl, PerNode: 3}
	if node, wait, err := r.queued(ctx, mig); err != nil || wait != "" || node != "" {
		t.Fatalf("missing pod: node %q wait %q err %v", node, wait, err)
	}
	r.PerNode = 0
	if _, wait, _ := r.queued(ctx, mig); wait != "" || lists != 0 {
		t.Fatalf("no bound: wait %q, %d lists", wait, lists)
	}
}

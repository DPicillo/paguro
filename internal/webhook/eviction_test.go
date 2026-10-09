// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"context"
	"net/http"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"paguro.dev/paguro/api/v1alpha1"
)

func evictionSetup(t *testing.T, objs ...client.Object) (*EvictionHandler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(&v1alpha1.Migration{}).Build()
	return &EvictionHandler{Client: cl, Reader: cl}, cl
}

func evictionRequest(pod string, dryRun bool) admission.Request {
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create, SubResource: "eviction", Namespace: "games", Name: pod, DryRun: &dryRun,
	}}
}

func runningPod(name string, migratable bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games", UID: types.UID("1f2e3d4c-0000-0000-0000-000000000000")},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if migratable {
		p.Labels = map[string]string{v1alpha1.LabelMigratable: "true"}
	}
	return p
}

func isRetry(r admission.Response) bool {
	return !r.Allowed && r.Result != nil && r.Result.Code == http.StatusTooManyRequests
}

// The first eviction of a migratable pod starts one migration and asks the
// evicter to retry; retries while it runs get the same answer.
func TestEvictionStartsMigration(t *testing.T) {
	ctx := context.Background()
	h, cl := evictionSetup(t, runningPod("server-0", true))
	r := h.Handle(ctx, evictionRequest("server-0", false))
	if !isRetry(r) {
		t.Fatalf("first eviction: want 429, got %+v", r.Result)
	}
	var list v1alpha1.MigrationList
	if err := cl.List(ctx, &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("want one migration, got %d (%v)", len(list.Items), err)
	}
	m := list.Items[0]
	if m.Spec.PodName != "server-0" || m.Labels[LabelTrigger] != TriggerEviction || m.Name != "server-0-evict-1f2e3d4c" {
		t.Fatalf("migration: %+v", m.ObjectMeta)
	}
	if r := h.Handle(ctx, evictionRequest("server-0", false)); !isRetry(r) || !strings.Contains(r.Result.Message, "in progress") {
		t.Fatalf("retry while migrating: %+v", r.Result)
	}
	if err := cl.List(ctx, &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("a retry must not start a second migration: %d", len(list.Items))
	}
}

// After the migration: success lets the eviction of the (going) source
// through; failure and rollback fall back to a normal eviction.
func TestEvictionAfterMigration(t *testing.T) {
	for _, phase := range []v1alpha1.Phase{v1alpha1.PhaseSucceeded, v1alpha1.PhaseFailed, v1alpha1.PhaseRolledBack} {
		pod := runningPod("server-0", true)
		m := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: evictionMigrationName(pod), Namespace: "games"},
			Spec: v1alpha1.MigrationSpec{PodName: "server-0"}, Status: v1alpha1.MigrationStatus{Phase: phase}}
		h, cl := evictionSetup(t, pod, m)
		if r := h.Handle(context.Background(), evictionRequest("server-0", false)); !r.Allowed {
			t.Errorf("%s: want the eviction allowed, got %+v", phase, r.Result)
		}
		var list v1alpha1.MigrationList
		_ = cl.List(context.Background(), &list)
		if len(list.Items) != 1 {
			t.Errorf("%s: no new migration after the first one ended, got %d", phase, len(list.Items))
		}
	}
}

// A migration someone else started holds the eviction back as well.
func TestEvictionWaitsForOtherMigration(t *testing.T) {
	m := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "manual", Namespace: "games"},
		Spec: v1alpha1.MigrationSpec{PodName: "server-0"}, Status: v1alpha1.MigrationStatus{Phase: v1alpha1.PhasePreCopy}}
	h, _ := evictionSetup(t, runningPod("server-0", true), m)
	if r := h.Handle(context.Background(), evictionRequest("server-0", false)); !isRetry(r) || !strings.Contains(r.Result.Message, "manual") {
		t.Fatalf("want 429 naming the running migration, got %+v", r.Result)
	}
}

// Pods that are not migratable, dry runs and unknown pods are evicted as
// usual, and nothing is created.
func TestEvictionPassesThrough(t *testing.T) {
	h, cl := evictionSetup(t, runningPod("plain", false), runningPod("server-0", true))
	for _, tt := range []struct {
		pod    string
		dryRun bool
	}{{"plain", false}, {"server-0", true}, {"missing", false}} {
		if r := h.Handle(context.Background(), evictionRequest(tt.pod, tt.dryRun)); !r.Allowed {
			t.Errorf("%s (dry run %v): want allowed, got %+v", tt.pod, tt.dryRun, r.Result)
		}
	}
	var list v1alpha1.MigrationList
	_ = cl.List(context.Background(), &list)
	if len(list.Items) != 0 {
		t.Fatalf("nothing may be created, got %d migrations", len(list.Items))
	}
}

func TestEvictionMigrationNameFitsALabel(t *testing.T) {
	p := runningPod(strings.Repeat("a", 60)+"-x", true)
	if n := evictionMigrationName(p); len(n) > 63 || !strings.HasSuffix(n, "-evict-1f2e3d4c") {
		t.Fatalf("name %q (%d)", n, len(n))
	}
}

// A replacement under the source's name (StatefulSet): the evicter's retry
// for the pod that left is answered 404 – unless the replacement's own node
// is being drained, which is an eviction of its own.
func TestEvictionRetryAfterSameNameMigration(t *testing.T) {
	ctx := context.Background()
	done := metav1.NowMicro()
	mig := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "server-0-evict-aaaaaaaa", Namespace: "games", UID: "mig-1",
			Labels: map[string]string{LabelTrigger: TriggerEviction}},
		Spec:   v1alpha1.MigrationSpec{PodName: "server-0"},
		Status: v1alpha1.MigrationStatus{Phase: v1alpha1.PhaseSucceeded, SourceNode: "node-a", TargetNode: "node-b", CompletedAt: &done},
	}
	replacement := runningPod("server-0", true)
	replacement.Annotations = map[string]string{v1alpha1.AnnotationRestoreID: "mig-1"}
	replacement.Spec.NodeName = "node-b"
	for _, tt := range []struct {
		cordoned bool
		want     int32
	}{{false, http.StatusNotFound}, {true, http.StatusTooManyRequests}} {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}, Spec: corev1.NodeSpec{Unschedulable: tt.cordoned}}
		h, _ := evictionSetup(t, mig.DeepCopy(), replacement.DeepCopy(), node)
		r := h.Handle(ctx, evictionRequest("server-0", false))
		if r.Allowed || r.Result == nil || r.Result.Code != tt.want {
			t.Errorf("target node cordoned=%v: want %d, got %+v", tt.cordoned, tt.want, r.Result)
		}
	}
}

// An eviction whose UID precondition names another pod (Karpenter sets it)
// is meant for a pod that is gone.
func TestEvictionUIDPrecondition(t *testing.T) {
	h, _ := evictionSetup(t, runningPod("server-0", true))
	req := evictionRequest("server-0", false)
	req.Object.Raw = []byte(`{"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":"server-0","namespace":"games"},` +
		`"deleteOptions":{"preconditions":{"uid":"00000000-old0-0000-0000-000000000000"}}}`)
	if r := h.Handle(context.Background(), req); r.Allowed || r.Result.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %+v", r.Result)
	}
}

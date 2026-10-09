// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// The second hop of a chain: the source pod was restored by the first hop
// and still carries that restore's annotations. Its shield belongs to the
// running migration and must stay up, whatever runc reports.
func TestShieldJanitorSparesMigrationSources(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mc-p497c1", Namespace: "mc", UID: "pod-uid",
		Annotations: map[string]string{v1.AnnotationRestoreID: "hop-1-uid"}}}
	hop := func(name string, phase v1.Phase, podUID string) *v1.Migration {
		return &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "mc", UID: types.UID("uid-" + name)},
			Spec:   v1.MigrationSpec{PodName: pod.Name},
			Status: v1.MigrationStatus{Phase: phase, SourcePodUID: podUID, SourceNode: "node-b"}}
	}
	cases := []struct {
		name string
		objs []client.Object
		want bool
	}{
		{"no migration: a leftover", nil, false},
		{"hop 1 ended", []client.Object{hop("hop-1", v1.PhaseSucceeded, "first-pod-uid")}, false},
		{"hop 2 freezing", []client.Object{hop("hop-1", v1.PhaseSucceeded, "first-pod-uid"), hop("hop-2", v1.PhaseFrozen, "pod-uid")}, true},
		{"hop 2 before the source UID is known", []client.Object{hop("hop-2", v1.PhasePreCopy, "")}, true},
		{"another pod's migration", []client.Object{hop("other", v1.PhasePreCopy, "other-pod-uid")}, false},
		{"hop 2 rolled back", []client.Object{hop("hop-2", v1.PhaseRolledBack, "pod-uid")}, false},
	}
	for _, c := range cases {
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(c.objs...).Build()
		a := &Agent{Client: cl, APIReader: cl, NodeName: "node-b", Log: slog.New(slog.DiscardHandler)}
		a.init()
		if got := a.shieldInUse(context.Background(), pod); got != c.want {
			t.Errorf("%s: shieldInUse = %v, want %v", c.name, got, c.want)
		}
	}

	// The source job in memory counts even before the cache has the
	// Migration.
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	a := &Agent{Client: cl, APIReader: cl, NodeName: "node-b", Log: slog.New(slog.DiscardHandler)}
	a.init()
	m := hop("hop-2", v1.PhasePreCopy, "pod-uid")
	a.states[m.UID] = &migState{key: client.ObjectKeyFromObject(m), source: &sourceJob{m: m}}
	if !a.shieldInUse(context.Background(), pod) {
		t.Error("a running source job does not protect its shield")
	}

	// Migrations not listable: keep the shield.
	failing := interceptor.NewClient(fake.NewClientBuilder().WithScheme(scheme).Build(), interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("cache not synced")
		}})
	a = &Agent{Client: failing, APIReader: failing, NodeName: "node-b", Log: slog.New(slog.DiscardHandler)}
	a.init()
	if !a.shieldInUse(context.Background(), pod) {
		t.Error("a list error lowers the shield")
	}
}

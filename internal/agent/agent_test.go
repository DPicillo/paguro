// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
)

// A target agent restarted after the commit watches the restore again:
// only a target job reports it, and without the report the controller
// declares a restored migration failed.
func TestTargetResumesAfterRestart(t *testing.T) {
	layout.StateDir = t.TempDir()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	for _, phase := range []v1.Phase{v1.PhaseFrozen, v1.PhaseCuttingOver, v1.PhaseRestoring} {
		mig := &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "ns", UID: "mig-uid"},
			Status: v1.MigrationStatus{Phase: phase, SourceNode: "node-a", TargetNode: "node-b"}}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.Migration{}).WithObjects(mig).Build()
		a := &Agent{Client: cl, APIReader: cl, NodeName: "node-b", Log: slog.New(slog.DiscardHandler)}
		a.init()
		if _, err := a.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(mig)}); err != nil {
			t.Fatal(err)
		}
		st := a.states[mig.UID]
		if st == nil || st.cancelTarget == nil {
			t.Fatalf("%s: no target job after a restart", phase)
		}
		first := st.cancelTarget
		// A second event must not start another one.
		_, _ = a.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(mig)})
		if st := a.states[mig.UID]; fmt.Sprintf("%p", st.cancelTarget) != fmt.Sprintf("%p", first) {
			t.Fatalf("%s: second job started", phase)
		}
		first()
	}
}

// What the agent remembers about a migration goes with the Migration.
func TestStateDroppedWithMigration(t *testing.T) {
	layout.StateDir = t.TempDir()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	mig := &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "ns", UID: "mig-uid"},
		Status: v1.MigrationStatus{Phase: v1.PhaseRolledBack, SourceNode: "node-a", TargetNode: "node-b"}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.Migration{}).WithObjects(mig).Build()
	a := &Agent{Client: cl, APIReader: cl, NodeName: "node-b", Log: slog.New(slog.DiscardHandler)}
	a.init()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(mig)}
	if _, err := a.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(a.states) != 1 {
		t.Fatalf("states: %d", len(a.states))
	}
	if err := cl.Delete(context.Background(), mig); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(a.states) != 0 {
		t.Fatal("state of a deleted migration kept")
	}
}

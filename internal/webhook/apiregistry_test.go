// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
)

func apiRegistry(t *testing.T, objs ...client.Object) (*APIRegistry, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.Migration{}).
		WithIndex(&v1alpha1.Migration{}, OwnerIndex, func(o client.Object) []string {
			if u := o.(*v1alpha1.Migration).Status.Cutover.ReplacementOwnerUID; u != "" {
				return []string{u}
			}
			return nil
		}).Build()
	return &APIRegistry{Client: cl, Reader: cl}, cl
}

func cutoverMigration(phase v1alpha1.Phase) *v1alpha1.Migration {
	m := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "shop", UID: "mig-uid"}}
	m.Status.Phase = phase
	m.Status.Cutover.ReplacementOwnerUID = string(ownerUID)
	return m
}

func TestAPIRegistryExactlyOnce(t *testing.T) {
	ctx := context.Background()
	reg, cl := apiRegistry(t, cutoverMigration(v1alpha1.PhasePreCopy))
	mig := &v1alpha1.Migration{}
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "shop", Name: "m"}, mig); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Pending(ctx, ownerUID); ok {
		t.Fatal("not armed yet, nothing may be pending")
	}
	if err := reg.Register(ctx, mig, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Pending(ctx, ownerUID); !ok {
		t.Fatal("armed migration not pending")
	}
	if _, ok := reg.Pending(ctx, "other-owner"); ok {
		t.Fatal("pending for a foreign owner")
	}

	// Two webhook replicas: the first claim wins, the second finds nothing.
	calls := 0
	mutate := func(*v1alpha1.Migration) error { calls++; return nil }
	if _, found, err := reg.Consume(ctx, ownerUID, "web-abc", mutate); !found || err != nil {
		t.Fatalf("first claim: found=%v err=%v", found, err)
	}
	other := &APIRegistry{Client: cl, Reader: cl}
	if _, found, err := other.Consume(ctx, ownerUID, "web-def", mutate); found || err != nil {
		t.Fatalf("second claim must find nothing: found=%v err=%v", found, err)
	}
	if calls != 1 {
		t.Fatalf("mutate ran %d times", calls)
	}
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "shop", Name: "m"}, mig); err != nil {
		t.Fatal(err)
	}
	if at, ok := reg.ConsumedAt(mig); !ok || at.IsZero() || mig.Status.Cutover.InterceptedPod != "web-abc" {
		t.Fatalf("claim not recorded: %+v", mig.Status.Cutover)
	}

	// Without force a consumed migration stays consumed; with force (the
	// mutated pod never appeared) it is armed again.
	if err := reg.Register(ctx, mig, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Pending(ctx, ownerUID); ok {
		t.Fatal("re-armed without force")
	}
	if err := reg.Register(ctx, mig, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Pending(ctx, ownerUID); !ok {
		t.Fatal("force did not re-arm")
	}
}

func TestAPIRegistryNotInterceptable(t *testing.T) {
	ctx := context.Background()
	for _, phase := range []v1alpha1.Phase{v1alpha1.PhaseAborting, v1alpha1.PhaseRolledBack, v1alpha1.PhaseRestoring, v1alpha1.PhaseSucceeded} {
		m := cutoverMigration(phase)
		now := metav1.NowMicro()
		m.Status.Cutover.InterceptArmedAt = &now
		reg, _ := apiRegistry(t, m)
		if _, ok := reg.Pending(ctx, ownerUID); ok {
			t.Errorf("phase %s must not intercept", phase)
		}
	}
}

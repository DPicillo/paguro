// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
)

func TestActiveCollector(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	mig := func(name string, phase v1alpha1.Phase, age time.Duration) *v1alpha1.Migration {
		return &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns",
			CreationTimestamp: metav1.NewTime(now.Add(-age))}, Status: v1alpha1.MigrationStatus{Phase: phase}}
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		mig("a", v1alpha1.PhasePreCopy, time.Minute), mig("b", v1alpha1.PhasePreCopy, 40*time.Minute),
		mig("c", v1alpha1.PhaseRestoring, 2*time.Minute), mig("d", v1alpha1.PhaseSucceeded, 5*time.Hour)).Build()
	c := &ActiveCollector{Reader: cl, Now: func() time.Time { return now }}
	want := `
# HELP paguro_migration_oldest_active_seconds Age of the oldest migration not yet finished (0 when there is none).
# TYPE paguro_migration_oldest_active_seconds gauge
paguro_migration_oldest_active_seconds 2400
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "paguro_migration_oldest_active_seconds"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "paguro_migrations_active"); n != 7 {
		t.Fatalf("%d phase series", n)
	}
}

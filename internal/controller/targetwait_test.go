// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
)

// targetWaitEnv: the only other node is cordoned; the migration was started
// by an eviction if evicted is set.
func targetWaitEnv(t *testing.T, evicted bool) *env {
	t.Helper()
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{})
	e.r.EvictionTargetWait = 2 * time.Minute
	if evicted {
		e.markEvicted()
	}
	e.setUnschedulable("node-b", true)
	return e
}

// markEvicted labels the migration as started by an eviction.
func (e *env) markEvicted() {
	e.t.Helper()
	m := e.mig()
	m.Labels = map[string]string{webhook.LabelTrigger: webhook.TriggerEviction}
	if err := e.c.Update(context.Background(), m); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) setUnschedulable(name string, on bool) {
	e.t.Helper()
	n := &corev1.Node{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, n); err != nil {
		e.t.Fatal(err)
	}
	n.Spec.Unschedulable = on
	if err := e.c.Update(context.Background(), n); err != nil {
		e.t.Fatal(err)
	}
}

// An eviction's migration waits in Preflight while no node can take the
// pod, and goes on once one can.
func TestEvictionMigrationWaitsForTarget(t *testing.T) {
	e := targetWaitEnv(t, true)
	e.reconcile() // finalizer, Preflight
	for range 3 {
		if res := e.reconcile(); res.RequeueAfter != targetPoll {
			t.Fatalf("want a requeue after %s, got %+v", targetPoll, res)
		}
	}
	m := e.mig()
	if m.Status.Phase != v1alpha1.PhasePreflight || !strings.Contains(m.Status.Message, "waiting until 2026-10-01T12:02:00Z for a target node") {
		t.Fatalf("want waiting in Preflight, got %s: %q", m.Status.Phase, m.Status.Message)
	}
	if !e.sourceExists() {
		t.Fatal("a waiting migration must not touch the pod")
	}
	e.clock.Step(50 * time.Second)
	e.setUnschedulable("node-b", false) // the new node is ready
	if m := e.reconcileUntil(v1alpha1.PhasePreCopy); m.Status.TargetNode != "node-b" {
		t.Fatalf("target %q", m.Status.TargetNode)
	}
}

// After the wait the migration fails (and the eviction goes through); a
// migration that no eviction started fails at once.
func TestTargetWaitEnds(t *testing.T) {
	e := targetWaitEnv(t, true)
	e.reconcile()
	e.reconcile()
	e.clock.Step(2 * time.Minute)
	m := e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "waited 2m0s for a node") {
		t.Fatalf("message %q", m.Status.Message)
	}

	e = targetWaitEnv(t, false)
	if m := e.reconcileUntil(v1alpha1.PhaseFailed); strings.Contains(m.Status.Message, "waited") {
		t.Fatalf("a manual migration must not wait: %q", m.Status.Message)
	}
}

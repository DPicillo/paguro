// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

func withMemoryLimit(q string) podOpt {
	return func(p *corev1.Pod) {
		p.Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(q)}
	}
}

// terminates gives node-a (the source) a known end, d from the test clock.
func (e *env) terminates(d time.Duration) {
	e.t.Helper()
	n := &corev1.Node{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "node-a"}, n); err != nil {
		e.t.Fatal(err)
	}
	n.Annotations[v1alpha1.AnnotationNodeTerminatesAt] = e.clock.Now().Add(d).UTC().Format(time.RFC3339)
	if err := e.c.Update(context.Background(), n); err != nil {
		e.t.Fatal(err)
	}
}

func withMemoryRequest(q string) podOpt {
	return func(p *corev1.Pod) {
		p.Spec.Containers[0].Resources.Requests = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(q)}
	}
}

func TestCopyEstimate(t *testing.T) {
	for _, tt := range []struct {
		pod  *corev1.Pod
		want time.Duration
	}{
		{testPod(), 15 * time.Second},                                                   // nothing: 512 MiB
		{testPod(withMemoryLimit("1536Mi")), 26 * time.Second},                          // 10 s + 1.5 GiB at 96 MiB/s
		{testPod(withMemoryLimit("2Gi"), withMemoryRequest("768Mi")), 18 * time.Second}, // the request counts
	} {
		if got := copyEstimate(tt.pod).Round(time.Second); got != tt.want {
			t.Errorf("estimate %s, want %s", got, tt.want)
		}
	}
}

// An eviction's migration off a node that goes before the pod could have
// moved is refused at once: the eviction restarts the pod sooner.
func TestDeadlineRefusesEvictionMigration(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(withMemoryLimit("1Gi")), v1alpha1.MigrationSpec{})
	e.r.EvictionTargetWait = 2 * time.Minute
	e.markEvicted()
	e.terminates(15 * time.Second) // the pod needs about 21 s
	m := e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "goes at 2026-10-01T12:00:15Z") || !strings.Contains(m.Status.Message, "evicting it instead") {
		t.Fatalf("message %q", m.Status.Message)
	}
	if !e.sourceExists() {
		t.Fatal("a refused migration must not touch the pod")
	}
}

// Waiting for a target ends when the migration could just still finish.
func TestDeadlineShortensTargetWait(t *testing.T) {
	e := targetWaitEnv(t, true)
	e.terminates(2 * time.Minute) // nothing set: 512 MiB, about 15.3 s
	e.reconcile()
	e.reconcile()
	m := e.mig()
	if m.Status.Phase != v1alpha1.PhasePreflight || !strings.Contains(m.Status.Message, "waiting until 2026-10-01T12:01:44Z") {
		t.Fatalf("want waiting until two minutes minus the estimate, got %s: %q", m.Status.Phase, m.Status.Message)
	}
	e.clock.Step(105 * time.Second)
	m = e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "evicting it instead") {
		t.Fatalf("message %q", m.Status.Message)
	}
}

// A migration that someone started by hand goes ahead, with a warning.
func TestDeadlineWarnsManualMigration(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{})
	e.terminates(10 * time.Second)
	m := e.reconcileUntil(v1alpha1.PhasePreCopy)
	if !strings.Contains(strings.Join(m.Status.Warnings, " "), "node-a goes at") {
		t.Fatalf("warnings %v", m.Status.Warnings)
	}
}

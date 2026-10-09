// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"paguro.dev/paguro/internal/netadapter"
)

// The replacement continues serving processes: its readiness probe starts at
// once (EKS: a 30 s delay refused new connections for 19 s), its startup
// probe too, with the delay added to its failure budget; liveness stays.
func TestRestoreTargetProbesStartAtOnce(t *testing.T) {
	exec := corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"mc-health"}}}
	pod := replacement()
	pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: exec, InitialDelaySeconds: 30, PeriodSeconds: 2, FailureThreshold: 3}
	pod.Spec.Containers[0].StartupProbe = &corev1.Probe{ProbeHandler: exec, InitialDelaySeconds: 30, PeriodSeconds: 10, FailureThreshold: 6}
	pod.Spec.Containers[0].LivenessProbe = &corev1.Probe{ProbeHandler: exec, InitialDelaySeconds: 60}
	// A startup probe with the API's defaults (period 10 s, 3 failures).
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "side",
		StartupProbe: &corev1.Probe{ProbeHandler: exec, InitialDelaySeconds: 25}})
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{Name: "proxy", RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
		ReadinessProbe: &corev1.Probe{ProbeHandler: exec, InitialDelaySeconds: 5}})
	if err := MutateIntoRestoreTarget(pod, migration(netadapter.NamePhantom, false), netadapter.Generic{}); err != nil {
		t.Fatal(err)
	}
	c := pod.Spec.Containers[0]
	if r := c.ReadinessProbe; r.InitialDelaySeconds != 0 || r.PeriodSeconds != 2 || r.FailureThreshold != 3 {
		t.Errorf("readiness %+v", r)
	}
	if s := c.StartupProbe; s.InitialDelaySeconds != 0 || s.PeriodSeconds != 10 || s.FailureThreshold != 9 {
		t.Errorf("startup %+v: want no delay, 6+3 failures of 10 s", s)
	}
	if c.LivenessProbe.InitialDelaySeconds != 60 {
		t.Errorf("liveness changed: %+v", c.LivenessProbe)
	}
	if s := pod.Spec.Containers[1].StartupProbe; s.InitialDelaySeconds != 0 || s.PeriodSeconds != 10 || s.FailureThreshold != 6 {
		t.Errorf("startup with defaults %+v: want 3+3 failures of 10 s", s)
	}
	for _, ic := range pod.Spec.InitContainers {
		if ic.Name == "proxy" && ic.ReadinessProbe.InitialDelaySeconds != 0 {
			t.Errorf("sidecar readiness %+v", ic.ReadinessProbe)
		}
	}
}

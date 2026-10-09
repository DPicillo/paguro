// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/webhook"
)

// A node may go at a known time whatever runs on it – a spot instance two
// minutes after AWS's warning. Its agent publishes the time
// (paguro.dev/terminates-at, agent/interruption.go). A migration that
// cannot finish before it only delays the pod's restart: the instance
// takes the pod with it, and the eviction it held back would have let the
// pod start on another node at once. So a migration that an eviction
// started moves only if the time left covers an estimate of its own
// duration, and waits for a target node only as long as that holds.

// The estimate: a fixed part (preflight, the target's sandbox, the freeze
// and the restore – 4–5 s measured on EKS) and the pod's memory at the
// network baseline of a small EC2 instance (0.78 Gbit/s for an
// m7i-flex.large; most move faster). Memory: the containers' requests –
// what the pod is expected to use; limits overstate it, and an estimate
// too high restarts a pod that could have moved – else their limits,
// else deadlineDefaultMemory. Measured on EKS: Bedrock (requests 768 MiB)
// moved in 7–8 s, estimated 18 s.
const (
	deadlineBase          = 10 * time.Second
	deadlineRate          = 96 << 20 // bytes per second
	deadlineDefaultMemory = 512 << 20
)

// copyEstimate is how long moving the pod is expected to take.
func copyEstimate(pod *corev1.Pod) time.Duration {
	var limits, requests int64
	for _, c := range pod.Spec.Containers {
		limits += c.Resources.Limits.Memory().Value()
		requests += c.Resources.Requests.Memory().Value()
	}
	mem := requests
	if mem == 0 {
		mem = limits
	}
	if mem == 0 {
		mem = deadlineDefaultMemory
	}
	return deadlineBase + time.Duration(float64(mem)/deadlineRate*float64(time.Second))
}

// terminatesAt returns the time the node goes (paguro.dev/terminates-at).
func terminatesAt(node *corev1.Node) (time.Time, bool) {
	if node == nil {
		return time.Time{}, false
	}
	v := node.Annotations[v1alpha1.AnnotationNodeTerminatesAt]
	if v == "" {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, v)
	return at, err == nil
}

// latestStart is the last moment a migration of the pod off a terminating
// node can begin and still finish; zero if the node has no known end.
func latestStart(pod *corev1.Pod, src *corev1.Node) time.Time {
	end, ok := terminatesAt(src)
	if !ok {
		return time.Time{}
	}
	return end.Add(-copyEstimate(pod))
}

// checkDeadline: a migration that an eviction started is refused when its
// source node goes before it could finish – the eviction then restarts the
// pod elsewhere at once. Others only get a warning: whoever started them
// asked for this one.
func (r *MigrationReconciler) checkDeadline(mig *v1alpha1.Migration, pod *corev1.Pod, src *corev1.Node, res *preflightResult) error {
	start := latestStart(pod, src)
	if start.IsZero() || r.now().Time.Before(start) {
		return nil
	}
	end, _ := terminatesAt(src)
	why := fmt.Sprintf("node %s goes at %s, in %s; moving the pod takes about %s",
		src.Name, end.UTC().Format(time.RFC3339), end.Sub(r.now().Time).Round(time.Second), copyEstimate(pod).Round(time.Second))
	if mig.Labels[webhook.LabelTrigger] == webhook.TriggerEviction {
		return reject("%s – evicting it instead restarts it sooner", why)
	}
	res.warnings = append(res.warnings, why)
	return nil
}

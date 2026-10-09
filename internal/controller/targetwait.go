// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/webhook"
)

// targetPoll is how often a migration that waits for a target node looks
// again.
const targetPoll = 3 * time.Second

// awaitingTarget: no node can take the pod yet, and the migration may wait
// for one.
type awaitingTarget struct{ msg string }

func (a *awaitingTarget) Error() string { return a.msg }

// targetWait returns until when a migration without a target node may wait
// for one (zero: it fails at once).
//
// Only migrations that an eviction started wait, and only for
// EvictionTargetWait from their start. Whoever evicts often brings the
// target along: Karpenter launches a node for the pods of a node it
// deletes or that gets a spot interruption warning, and drains the old one
// at the same time; the new node is ready after about 50 s on EC2. Failing
// the migration then would let the eviction through and restart the pod on
// that very node a few seconds later. Meanwhile the pod runs on, and the
// evicter's retries are answered 429. A manual migration without a target
// fails at once: its user wants to know. On a node that goes at a known
// time the wait ends early enough for the migration to finish
// (deadline.go).
func (r *MigrationReconciler) targetWait(mig *v1alpha1.Migration, pod *corev1.Pod, src *corev1.Node) time.Time {
	if r.EvictionTargetWait <= 0 || mig.Labels[webhook.LabelTrigger] != webhook.TriggerEviction ||
		mig.Spec.TargetNode != "" || mig.Status.StartedAt == nil {
		return time.Time{}
	}
	until := mig.Status.StartedAt.Add(r.EvictionTargetWait)
	if start := latestStart(pod, src); !start.IsZero() && start.Before(until) {
		until = start
	}
	return until
}

// noTarget is the preflight's answer when no node can take the pod: wait if
// the migration may (targetWait), else reject.
func (r *MigrationReconciler) noTarget(mig *v1alpha1.Migration, pod *corev1.Pod, src *corev1.Node, why string) error {
	until := r.targetWait(mig, pod, src)
	if until.IsZero() {
		return reject("%s", why)
	}
	// Past a terminating node's latest start, checkDeadline has refused
	// already; what ends here is the wait itself.
	if !r.now().Time.Before(until) {
		return reject("%s (waited %s for a node)", why, r.EvictionTargetWait)
	}
	return &awaitingTarget{msg: fmt.Sprintf("waiting until %s for a target node: %s",
		until.UTC().Format(time.RFC3339), why)}
}

// reportAwaitingTarget shows why the migration waits (phase Preflight,
// message); the message changes only when the reason does.
func (r *MigrationReconciler) reportAwaitingTarget(ctx context.Context, mig *v1alpha1.Migration, msg string) error {
	if mig.Status.Message == msg {
		return nil
	}
	return r.patchStatus(ctx, mig, func(st *v1alpha1.MigrationStatus) { st.Message = msg })
}

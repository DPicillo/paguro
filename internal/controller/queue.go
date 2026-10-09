// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

// queuePoll is how often a queued migration checks for room.
const queuePoll = 2 * time.Second

// queued returns the node the migration's pod runs on and, if that node
// already has PerNode migrations under way, why the migration waits.
//
// Migrations that leave a node at the same time freeze and are restored
// together: a drain of eleven pods froze each of them for up to 21 s (kubelet
// and the CNI work through the target's new sandboxes in turn), where one at
// a time took 0.7 s. A queued migration has not touched its pod: the pod
// runs on until it is its turn. The count reads the API server, not the
// cache, and runs under startMu with the transition it permits (the
// controller is the leader), so two workers cannot both take the last
// place.
func (r *MigrationReconciler) queued(ctx context.Context, mig *v1alpha1.Migration) (node, wait string, err error) {
	pod := &corev1.Pod{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: mig.Spec.PodName}, pod); err != nil {
		return "", "", client.IgnoreNotFound(err) // the preflight reports a missing pod
	}
	node = pod.Spec.NodeName
	if r.PerNode <= 0 || node == "" {
		return node, "", nil
	}
	var list v1alpha1.MigrationList
	if err := r.APIReader.List(ctx, &list); err != nil {
		return "", "", err
	}
	n := 0
	for _, m := range list.Items {
		if m.UID != mig.UID && m.Status.SourceNode == node && underWay(m.Status.Phase) {
			n++
		}
	}
	if n >= r.PerNode {
		return node, fmt.Sprintf("queued: %d migrations from node %s are under way (at most %d at a time); the pod runs on meanwhile",
			n, node, r.PerNode), nil
	}
	return node, "", nil
}

// underWay: started and not ended.
func underWay(p v1alpha1.Phase) bool {
	return p != "" && p != v1alpha1.PhasePending && !p.Terminal()
}

// reportQueued shows why the migration waits (phase Pending, message).
func (r *MigrationReconciler) reportQueued(ctx context.Context, mig *v1alpha1.Migration, why string) error {
	if mig.Status.Phase == v1alpha1.PhasePending && mig.Status.Message == why {
		return nil
	}
	return r.transition(ctx, mig, v1alpha1.PhasePending, why, nil)
}

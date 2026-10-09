// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	"paguro.dev/paguro/api/v1alpha1"
)

// reannounceMax bounds the wait for the replacement's endpoint to go: a
// stale one (its node's Cilium agent down) must not keep the source's
// address on the fallback route for good.
const reannounceMax = 2 * time.Minute

// reannounce gives the address back to the source after a rollback with an
// early hand-over: the replacement's sandbox may have claimed the address
// while the source was paused, and Cilium leaves the address without its
// endpoint entry once the replacement's endpoint is deleted
// (PoolRotator.Reannounce). Waits for that deletion, then announces the
// source's endpoint once (network.reannouncedAt). Reports whether the
// migration is done with it.
func (r *MigrationReconciler) reannounce(ctx context.Context, mig *v1alpha1.Migration) (bool, ctrl.Result, error) {
	st := &mig.Status
	if !st.Network.EarlyHandOver || st.Network.ReannouncedAt != nil || st.Cutover.SourceDeletedAt != nil ||
		st.TargetPodName == "" || r.Pools == nil {
		return true, ctrl.Result{}, nil
	}
	replacement := st.TargetPodName
	if st.PhaseChangedAt != nil && r.Clock.Since(st.PhaseChangedAt.Time) > reannounceMax {
		r.emitTyped(mig, corev1.EventTypeWarning, "Reannounce",
			"the replacement's endpoint "+replacement+" is still there; announcing the source anyway")
		replacement = ""
	}
	done, err := r.Pools.Reannounce(ctx, mig.Namespace, mig.Spec.PodName, replacement)
	if err != nil {
		r.emitTyped(mig, corev1.EventTypeWarning, "Reannounce", "announcing the source's endpoint again: "+err.Error())
		if !done {
			return false, ctrl.Result{RequeueAfter: pollInterval}, nil
		}
	}
	if !done {
		return false, ctrl.Result{RequeueAfter: fastRequeue}, nil
	}
	now := r.now()
	return true, ctrl.Result{}, r.patchStatusUnlocked(ctx, mig, func(s *v1alpha1.MigrationStatus) {
		s.Network.ReannouncedAt = &now
	})
}

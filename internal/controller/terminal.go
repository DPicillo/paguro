// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"paguro.dev/paguro/api/v1alpha1"
)

// cleanupTerminal is everything after a migration ended, in this order:
//
//  1. releaseSource – once (status.releasedAt): the steps that touch the
//     source pod or its owner. Recorded, so that a new leader does not
//     repeat them on a pod a later migration has taken over meanwhile.
//  2. a replacement that failed after the commit gets through its commit
//     gate (every reconcile, until it runs).
//  3. endpoint bridge and backend keeper go when they are due (time-based).
//  4. the finalizer goes.
func (r *MigrationReconciler) cleanupTerminal(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	if mig.Status.ReleasedAt == nil {
		done, res, err := r.releaseSource(ctx, mig)
		if err != nil || !done {
			return res, err
		}
		if err := r.patchStatusUnlocked(ctx, mig, func(s *v1alpha1.MigrationStatus) {
			now := r.now()
			s.ReleasedAt = &now
		}); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Failed after the commit: the replacement is the only copy and must
	// get through its commit gate (the agent's rescue keeps it alive).
	st := &mig.Status
	if st.Phase == v1alpha1.PhaseFailed && st.Network.CommitGate && st.Cutover.SourceDeletedAt != nil {
		target, err := r.findTargetPod(ctx, mig)
		if err != nil {
			logf.FromContext(ctx).Error(err, "looking up the replacement for its commit gate")
		} else if target != nil {
			if err := r.ensureGateClaim(ctx, mig, target); err != nil {
				r.emitTyped(mig, corev1.EventTypeWarning, "CommitGate", err.Error())
			}
		}
	}

	var res ctrl.Result
	if due, after := r.bridgeDue(ctx, mig); due {
		if err := r.deleteEndpointBridge(ctx, mig); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		res.RequeueAfter = after
	}
	if due, after := r.keeperDue(mig); due {
		if err := r.deleteBackendKeeper(ctx, mig); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := r.pruneKeeper(ctx, mig); err != nil {
			return ctrl.Result{}, err
		}
		if after > 0 && (res.RequeueAfter == 0 || after < res.RequeueAfter) {
			res.RequeueAfter = after
		}
	}
	return res, r.removeFinalizer(ctx, mig)
}

// releaseSource undoes or finishes what the migration did to the source pod
// and its owner; idempotent. Reports whether it is done.
func (r *MigrationReconciler) releaseSource(ctx context.Context, mig *v1alpha1.Migration) (bool, ctrl.Result, error) {
	if err := r.Registry.Forget(ctx, mig); err != nil {
		return false, ctrl.Result{}, err
	}
	// Aborted before the cutover: remove the warm replacement, hand the
	// source back to the ReplicaSet.
	if done, err := r.undoEarlyReplacement(ctx, mig); err != nil || !done {
		return false, ctrl.Result{RequeueAfter: fastRequeue}, err
	}
	// Rolled back after an early hand-over: the address back to the source.
	if done, res, err := r.reannounce(ctx, mig); err != nil || !done {
		return false, res, err
	}
	// After the commit the source must be gone, whatever the outcome.
	if _, err := r.ensureSourceDeleted(ctx, mig); err != nil {
		return false, ctrl.Result{}, err
	}
	// A held GameServer follows its replacement, or – none was created –
	// is handed back to Agones' judgement.
	if gameServerOf(mig) {
		target, err := r.findTargetPod(ctx, mig)
		if err == nil && target != nil {
			err = r.releaseGameServer(ctx, mig, target)
		} else if err == nil {
			err = r.forgetGameServer(ctx, mig)
		}
		if err != nil {
			return false, ctrl.Result{}, err
		}
	}
	return true, ctrl.Result{}, nil
}

// releaseWaitMax bounds how long a new migration of a pod waits for an
// ended one to release it (a clean-up that keeps failing must not block
// the pod for good; the longest regular step, the re-announce, gives up
// after reannounceMax).
const releaseWaitMax = 3 * reannounceMax / 2

// unreleasedMigration names an ended migration of pod that has not
// released it yet ("" if none).
func (r *MigrationReconciler) unreleasedMigration(ctx context.Context, mig *v1alpha1.Migration, pod types.UID) (string, error) {
	var list v1alpha1.MigrationList
	if err := r.List(ctx, &list, client.InNamespace(mig.Namespace)); err != nil {
		return "", err
	}
	for i := range list.Items {
		o := &list.Items[i]
		if o.UID == mig.UID || !o.Status.Phase.Terminal() || o.Status.ReleasedAt != nil ||
			o.Status.SourcePodUID != string(pod) {
			continue
		}
		if o.Status.PhaseChangedAt != nil && r.Clock.Since(o.Status.PhaseChangedAt.Time) > releaseWaitMax {
			continue
		}
		return o.Name, nil
	}
	return "", nil
}

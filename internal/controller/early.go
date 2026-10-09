// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

// Early replacement pod ("warm target"): the replacement is created during
// pre-copy instead of only after the source has been deleted. Admission,
// volume setup in the kubelet and creation by the ReplicaSet are therefore no
// longer part of the freeze time. The pod stays in ContainerCreating until
// the cutover (the source still holds the sticky IP and RWO volumes) – this
// is intended.
//
// Deployment pods: the source gets a different pod-template-hash; the
// ReplicaSet releases it (ownerRef removed) and immediately creates a
// replacement, which the webhook turns into the restore target as usual.
// Services usually select by app labels, so the source keeps receiving
// traffic.
// Bare pods: the controller creates the target pod under a new name.

import (
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
	"paguro.dev/paguro/pkg/names"
)

const (
	labelPodTemplateHash = appsv1.DefaultDeploymentUniqueLabelKey // "pod-template-hash"
	// On the source pod: original pod-template-hash (for rollback).
	AnnotationOriginalHash = "paguro.dev/original-pod-template-hash"
)

// selectsOnTemplateHash: the ReplicaSet's selector contains pod-template-hash
// (managed by Deployments). Only then does a label change detach the source.
func selectsOnTemplateHash(rs *appsv1.ReplicaSet) bool {
	if rs.Spec.Selector == nil {
		return false
	}
	if _, ok := rs.Spec.Selector.MatchLabels[labelPodTemplateHash]; ok {
		return true
	}
	for _, e := range rs.Spec.Selector.MatchExpressions {
		if e.Key == labelPodTemplateHash {
			return true
		}
	}
	return false
}

// detachedHash: value that makes the source drop out of the ReplicaSet.
func detachedHash(orig string, uid types.UID) string {
	return orig + "-paguro-" + names.UIDSuffix(string(uid))
}

func isEarly(mig *v1alpha1.Migration) bool { return mig.Status.Cutover.Mode == v1alpha1.CutoverEarly }

// expectedTargetName: deterministic name of the early replacement pod.
func expectedTargetName(mig *v1alpha1.Migration) (string, error) {
	if mig.Status.Cutover.ReplacementOwnerUID == "" {
		return names.ReplacementName(mig.Spec.PodName+"-", string(mig.UID)), nil
	}
	// ReplicaSets name pods via generateName "<rs>-"; the webhook turns that
	// into ReplacementName(generateName, uid).
	src, err := webhook.SourcePodOf(mig)
	if err != nil {
		return "", err
	}
	owner := metav1.GetControllerOf(src)
	if owner == nil {
		return "", fmt.Errorf("source pod snapshot has no controller owner")
	}
	return names.ReplacementName(owner.Name+"-", string(mig.UID)), nil
}

// ensureEarlyReplacement makes sure during pre-copy that the warm replacement
// pod exists. Returns a requeue interval (0 = pod is in place).
// Errors that require a rollback lead directly to Aborting.
func (r *MigrationReconciler) ensureEarlyReplacement(ctx context.Context, mig *v1alpha1.Migration, source *corev1.Pod) (ctrl.Result, error) {
	st := &mig.Status
	target, err := r.findTargetPod(ctx, mig)
	if err != nil {
		return ctrl.Result{}, err
	}
	if target != nil {
		if target.Status.Phase == corev1.PodFailed {
			return ctrl.Result{}, r.abort(ctx, mig, fmt.Sprintf("warm target pod %s failed (%s: %s)",
				target.Name, target.Status.Reason, target.Status.Message))
		}
		if string(target.UID) != st.TargetPodUID || st.TargetPodName != target.Name {
			created := r.now()
			if at, ok := r.Registry.ConsumedAt(mig); ok {
				created = metav1.NewMicroTime(at)
			}
			if err := r.patchStatus(ctx, mig, func(s *v1alpha1.MigrationStatus) {
				s.TargetPodName, s.TargetPodUID = target.Name, string(target.UID)
				s.Cutover.TargetPodCreatedAt = &created
			}); err != nil {
				return ctrl.Result{}, err
			}
			msg := fmt.Sprintf("warm target pod %s created on %s during pre-copy", target.Name, st.TargetNode)
			if st.Cutover.ReplacementRequestedAt != nil {
				msg += fmt.Sprintf(" (%d ms after request)", created.Sub(st.Cutover.ReplacementRequestedAt.Time).Milliseconds())
			}
			r.emitTyped(mig, corev1.EventTypeNormal, "WarmTarget", msg)
		}
		return ctrl.Result{}, nil
	}

	// No target pod yet: record the request (basis for the timeout).
	if st.Cutover.ReplacementRequestedAt == nil {
		name, err := expectedTargetName(mig)
		if err != nil {
			return ctrl.Result{}, r.abort(ctx, mig, "cannot determine replacement name: "+err.Error())
		}
		now := r.now()
		if err := r.patchStatus(ctx, mig, func(s *v1alpha1.MigrationStatus) {
			s.Cutover.ReplacementRequestedAt = &now
			s.TargetPodName = name
		}); err != nil {
			return ctrl.Result{}, err
		}
		r.emitTyped(mig, corev1.EventTypeNormal, "EarlyReplacement",
			fmt.Sprintf("cutover mode early: requesting warm target pod %s on %s during pre-copy", name, st.TargetNode))
	}

	if r.Clock.Since(st.Cutover.ReplacementRequestedAt.Time) > TargetPodTimeout {
		return ctrl.Result{}, r.abort(ctx, mig, fmt.Sprintf("warm target pod did not appear within %s", TargetPodTimeout))
	}

	if st.Cutover.ReplacementOwnerUID == "" {
		return r.createEarlyBareTarget(ctx, mig)
	}

	// Owner case: arm the webhook, then detach the source from the ReplicaSet.
	if escaped, err := r.findEscapedReplacement(ctx, mig, st.Cutover.ReplacementRequestedAt); err != nil {
		return ctrl.Result{}, err
	} else if escaped != "" {
		return ctrl.Result{}, r.abort(ctx, mig, fmt.Sprintf(
			"replacement pod %s was created without restore (webhook did not intercept it)", escaped))
	}
	at, ok := r.Registry.ConsumedAt(mig)
	force := ok && r.Clock.Since(at) > ReRegisterAfter
	if force {
		// Re-arming lets a second pod become the restore target: only if
		// the API server, not just the cache, has no target pod.
		if live, err := r.findTargetPodLive(ctx, mig); err != nil {
			return ctrl.Result{}, err
		} else if live != nil {
			return ctrl.Result{RequeueAfter: fastRequeue}, nil
		}
	}
	if err := r.registerReplacement(ctx, mig, force); err != nil {
		return ctrl.Result{}, err
	}
	want := detachedHash(st.Cutover.OriginalPodTemplateHash, mig.UID)
	if source.Labels[labelPodTemplateHash] != want {
		if err := r.patchPodMeta(ctx, source,
			map[string]any{labelPodTemplateHash: want},
			map[string]any{AnnotationOriginalHash: st.Cutover.OriginalPodTemplateHash}); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: fastRequeue}, nil
}

func (r *MigrationReconciler) createEarlyBareTarget(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	pod, err := webhook.BareReplacement(mig, netadapter.ForName(mig.Status.NetworkAdapter))
	if err != nil {
		return ctrl.Result{}, r.abort(ctx, mig, "cannot build target pod: "+err.Error())
	}
	pod.Name = mig.Status.TargetPodName
	err = r.Create(ctx, pod)
	switch {
	case err == nil, apierrors.IsAlreadyExists(err):
		return ctrl.Result{RequeueAfter: fastRequeue}, nil
	case apierrors.IsInvalid(err) || apierrors.IsForbidden(err):
		return ctrl.Result{}, r.abort(ctx, mig, "creating target pod rejected: "+err.Error())
	default:
		return ctrl.Result{}, err
	}
}

// patchPodMeta sets labels/annotations via merge patch (nil value = delete).
func (r *MigrationReconciler) patchPodMeta(ctx context.Context, pod *corev1.Pod, labels, annotations map[string]any) error {
	meta := map[string]any{}
	if labels != nil {
		meta["labels"] = labels
	}
	if annotations != nil {
		meta["annotations"] = annotations
	}
	body, err := json.Marshal(map[string]any{"metadata": meta})
	if err != nil {
		return err
	}
	return client.IgnoreNotFound(r.Patch(ctx, pod, client.RawPatch(types.MergePatchType, body)))
}

// undoEarlyReplacement reverts the early replacement (only before the source
// is deleted): first delete the warm target pod, then reset the
// pod-template-hash – the ReplicaSet adopts the source again. Idempotent;
// returns true when nothing is left to do.
func (r *MigrationReconciler) undoEarlyReplacement(ctx context.Context, mig *v1alpha1.Migration) (bool, error) {
	st := &mig.Status
	if !isEarly(mig) || st.Cutover.SourceDeletedAt != nil {
		return true, nil
	}
	if err := r.Registry.Forget(ctx, mig); err != nil {
		return false, err
	}
	done := true

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(mig.Namespace)); err != nil {
		return false, err
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Annotations[v1alpha1.AnnotationRestoreID] != string(mig.UID) || string(p.UID) == st.SourcePodUID {
			continue
		}
		done = false
		if !p.DeletionTimestamp.IsZero() {
			continue
		}
		uid := p.UID
		if err := r.Delete(ctx, p, client.GracePeriodSeconds(0), client.Preconditions{UID: &uid}); client.IgnoreNotFound(err) != nil {
			return false, err
		}
		r.emitTyped(mig, corev1.EventTypeNormal, "WarmTargetDeleted", "rollback: deleted warm target pod "+p.Name)
	}

	if st.Cutover.OriginalPodTemplateHash != "" {
		source, err := r.sourcePod(ctx, mig)
		if err != nil {
			return false, err
		}
		// Only the label this migration set: after a rollback the pod lives
		// on, and a later migration of it detaches it again under its own
		// hash. Measured: a new leader re-ran the clean-up of an earlier
		// rolled-back migration (helm upgrade during a migration), handed the
		// source back to the ReplicaSet, which deleted the running
		// migration's warm target and created a pod without restore.
		// The check reads the pod live and the patch carries its
		// resourceVersion: a new leader's cache may not have seen the later
		// migration's detach yet.
		if source != nil && source.Labels[labelPodTemplateHash] == detachedHash(st.Cutover.OriginalPodTemplateHash, mig.UID) {
			readopted, err := r.readoptSource(ctx, mig, source)
			if err != nil {
				return false, err
			}
			if readopted {
				r.emitTyped(mig, corev1.EventTypeNormal, "SourceReadopted",
					"rollback: restored pod-template-hash "+st.Cutover.OriginalPodTemplateHash+", ReplicaSet adopts the source again")
			}
		}
	}
	return done, nil
}

// readoptSource hands the source back to its ReplicaSet: the original
// pod-template-hash again, if the live pod still carries this migration's
// detached hash. A conflict is returned (the reconcile retries).
func (r *MigrationReconciler) readoptSource(ctx context.Context, mig *v1alpha1.Migration, cached *corev1.Pod) (bool, error) {
	live := &corev1.Pod{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(cached), live); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	orig := mig.Status.Cutover.OriginalPodTemplateHash
	if live.UID != cached.UID || live.Labels[labelPodTemplateHash] != detachedHash(orig, mig.UID) {
		return false, nil
	}
	base := live.DeepCopy()
	live.Labels[labelPodTemplateHash] = orig
	delete(live.Annotations, AnnotationOriginalHash)
	if err := r.Patch(ctx, live, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return true, nil
}

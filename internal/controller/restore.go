// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

// watchRestore: wait until the wrapper has restored and the pod is running.
func (r *MigrationReconciler) watchRestore(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	st := &mig.Status
	r.rotatePool(ctx, mig) // retry if it failed during cutover
	// Never Succeeded while the frozen source is still there.
	if gone, err := r.ensureSourceDeleted(ctx, mig); err != nil || !gone {
		return ctrl.Result{RequeueAfter: fastRequeue}, err
	}
	var pod corev1.Pod
	err := r.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: st.TargetPodName}, &pod)
	if apierrors.IsNotFound(err) || (err == nil && string(pod.UID) != st.TargetPodUID) {
		return ctrl.Result{}, r.fail(ctx, mig, fmt.Sprintf(
			"target pod %s disappeared during restore; the source is gone, no rollback possible", st.TargetPodName))
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if pod.Status.Phase == corev1.PodFailed {
		return ctrl.Result{}, r.fail(ctx, mig, fmt.Sprintf(
			"target pod %s failed (%s: %s); the source is gone, no rollback possible",
			pod.Name, pod.Status.Reason, pod.Status.Message))
	}
	if err := r.releaseGameServer(ctx, mig, &pod); err != nil {
		return ctrl.Result{RequeueAfter: fastRequeue}, err
	}

	// A replacement that got its address only now (new IP, owner recreates
	// it after the source's deletion).
	r.bridgeLate(ctx, mig)
	if st.Network.CommitGate {
		if err := r.ensureGateClaim(ctx, mig, &pod); err != nil {
			r.emitTyped(mig, corev1.EventTypeWarning, "CommitGate", err.Error())
		}
	}
	volumes, err := r.trackVolumes(ctx, mig)
	if err != nil {
		return ctrl.Result{}, err
	}

	coldStarts := coldStartedContainers(st.Target.Containers)
	reported := allContainersReported(st.Target.Containers, len(pod.Spec.Containers))
	running := pod.Status.Phase == corev1.PodRunning
	done := running && (st.Target.RestoredAt != nil || (reported && len(coldStarts) > 0))

	if !done {
		if st.Cutover.SourceDeletedAt != nil && r.Clock.Since(st.Cutover.SourceDeletedAt.Time) > RestoreTimeout {
			return ctrl.Result{}, r.fail(ctx, mig, fmt.Sprintf(
				"restore did not complete within %s (target agent: %q); the source is gone, no rollback possible",
				RestoreTimeout, st.Target.Error+st.Target.Message))
		}
		return ctrl.Result{RequeueAfter: pollInterval}, r.patchProgress(ctx, mig, &pod, volumes)
	}

	var warnings []string
	if hasReadinessProbe(&pod) && !podReady(&pod) {
		ref := st.PhaseChangedAt
		if st.Target.RestoredAt != nil {
			ref = st.Target.RestoredAt
		}
		if ref != nil && r.Clock.Since(ref.Time) < ReadyWait {
			return ctrl.Result{RequeueAfter: pollInterval}, r.patchProgress(ctx, mig, &pod, volumes)
		}
		warnings = append(warnings, fmt.Sprintf("target pod restored and running but not Ready within %s", ReadyWait))
	}
	return ctrl.Result{}, r.succeed(ctx, mig, &pod, volumes, coldStarts, warnings)
}

// patchProgress writes the target IP and volume timestamps once known.
func (r *MigrationReconciler) patchProgress(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod, volumes []v1alpha1.VolumeStatus) error {
	if mig.Status.TargetPodIP == pod.Status.PodIP && volumesEqual(mig.Status.Volumes, volumes) {
		return nil
	}
	return r.patchStatus(ctx, mig, func(st *v1alpha1.MigrationStatus) {
		st.TargetPodIP = pod.Status.PodIP
		st.Volumes = volumes
	})
}

func (r *MigrationReconciler) succeed(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod,
	volumes []v1alpha1.VolumeStatus, coldStarts []string, warnings []string) error {
	now := r.now()
	st := &mig.Status
	end := now
	if st.Target.RestoredAt != nil {
		end = *st.Target.RestoredAt
	}

	msg := fmt.Sprintf("restored on %s, freeze %d ms", st.TargetNode, msSince(st.Source.FrozenAt, end.Time))
	if st.IPPreserved {
		msg += ", IP " + st.SourcePodIP + " preserved"
	}
	if len(coldStarts) > 0 {
		msg = fmt.Sprintf("running on %s but cold-started (memory state lost): %s", st.TargetNode, strings.Join(coldStarts, "; "))
	}

	err := r.transition(ctx, mig, v1alpha1.PhaseSucceeded, msg, func(s *v1alpha1.MigrationStatus) {
		s.TargetPodIP = pod.Status.PodIP
		s.Volumes = volumes
		s.Warnings = append(s.Warnings, warnings...)
		s.Timings.FreezeMs = msSince(s.Source.FrozenAt, end.Time)
		s.Timings.RestoreMs = restoreMs(s)
		s.Timings.VolumeMoveMs = volumeMoveMs(s)
		if len(coldStarts) > 0 {
			setCondition(s, mig.Generation, metav1.ConditionFalse, ReasonColdStart, strings.Join(coldStarts, "; "))
		} else {
			setCondition(s, mig.Generation, metav1.ConditionTrue, ReasonRestored, "memory state restored")
		}
	})
	if err != nil {
		return err
	}
	if len(coldStarts) > 0 {
		r.emitTyped(mig, corev1.EventTypeWarning, ReasonColdStart,
			"workload is up but was cold-started, in-memory state is lost: "+strings.Join(coldStarts, "; "))
	}
	for _, w := range warnings {
		r.emitTyped(mig, corev1.EventTypeWarning, "NotReady", w)
	}
	return nil
}

func restoreMs(st *v1alpha1.MigrationStatus) int64 {
	if st.Target.RestoredAt != nil && st.Cutover.TargetPodCreatedAt != nil {
		return st.Target.RestoredAt.Sub(st.Cutover.TargetPodCreatedAt.Time).Milliseconds()
	}
	var maxMs int64
	for _, c := range st.Target.Containers {
		maxMs = max(maxMs, c.RestoreMs)
	}
	return maxMs
}

// volumeMoveMs: from source deletion until the last volume is usable on
// the target – attached there and detached from the source. With pre-attach
// the attach comes first and the detach is what the target waits for
// (measured: attached 0.25 s, detached 11.6 s after the source deletion).
func volumeMoveMs(st *v1alpha1.MigrationStatus) int64 {
	if st.Cutover.SourceDeletedAt == nil {
		return 0
	}
	var last *metav1.MicroTime
	for i := range st.Volumes {
		for _, t := range []*metav1.MicroTime{st.Volumes[i].AttachedAt, st.Volumes[i].DetachedAt} {
			if st.Volumes[i].AttachedAt != nil && t != nil && (last == nil || t.After(last.Time)) {
				last = t
			}
		}
	}
	if last == nil {
		return 0
	}
	return last.Sub(st.Cutover.SourceDeletedAt.Time).Milliseconds()
}

func coldStartedContainers(cs []v1alpha1.TargetContainerStatus) []string {
	var out []string
	for _, c := range cs {
		if c.ColdStartReason != "" {
			out = append(out, c.Name+": "+c.ColdStartReason)
		}
	}
	return out
}

func allContainersReported(cs []v1alpha1.TargetContainerStatus, want int) bool {
	n := 0
	for _, c := range cs {
		if c.Restored || c.ColdStartReason != "" {
			n++
		}
	}
	return want > 0 && n >= want
}

func hasReadinessProbe(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.ReadinessProbe != nil {
			return true
		}
	}
	return false
}

func podReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// trackVolumes derives detachedAt/attachedAt of the RWO volumes from the
// VolumeAttachments (a watch on VolumeAttachment triggers the reconcile, so
// the timestamps are accurate to a few milliseconds).
func (r *MigrationReconciler) trackVolumes(ctx context.Context, mig *v1alpha1.Migration) ([]v1alpha1.VolumeStatus, error) {
	out := make([]v1alpha1.VolumeStatus, len(mig.Status.Volumes))
	for i := range mig.Status.Volumes {
		mig.Status.Volumes[i].DeepCopyInto(&out[i])
	}
	if !hasRWO(mig) {
		return out, nil
	}
	var vas storagev1.VolumeAttachmentList
	if err := r.List(ctx, &vas); err != nil {
		return nil, err
	}
	now := r.now()
	for i := range out {
		v := &out[i]
		if v.Kind != VolumePVCRWO || (v.DetachedAt != nil && v.AttachedAt != nil) {
			continue
		}
		var pvc corev1.PersistentVolumeClaim
		if err := r.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: v.ClaimName}, &pvc); err != nil {
			return nil, client.IgnoreNotFound(err)
		}
		onSource, onTarget := false, false
		for j := range vas.Items {
			va := &vas.Items[j]
			if va.Spec.Source.PersistentVolumeName == nil || *va.Spec.Source.PersistentVolumeName != pvc.Spec.VolumeName {
				continue
			}
			switch va.Spec.NodeName {
			case mig.Status.SourceNode:
				onSource = onSource || va.Status.Attached
			case mig.Status.TargetNode:
				onTarget = onTarget || va.Status.Attached
			}
		}
		if v.DetachedAt == nil && !onSource {
			v.DetachedAt = &now
		}
		if v.AttachedAt == nil && onTarget {
			v.AttachedAt = &now
		}
	}
	return out, nil
}

func volumesEqual(a, b []v1alpha1.VolumeStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i].DetachedAt == nil) != (b[i].DetachedAt == nil) || (a[i].AttachedAt == nil) != (b[i].AttachedAt == nil) {
			return false
		}
	}
	return true
}

// watchAbort: wait for the source to thaw.
func (r *MigrationReconciler) watchAbort(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	st := &mig.Status
	reason := st.Message
	// Clean up the warm replacement immediately (independent of the source thaw).
	r.discardPreparedPool(ctx, mig)
	if _, err := r.undoEarlyReplacement(ctx, mig); err != nil {
		return ctrl.Result{}, err
	}
	if st.Source.ThawedAt != nil {
		msg := "workload continues on " + st.SourceNode + "; abort reason: " + reason
		// Usually the abort reason is the source agent's error already.
		if st.Source.Error != "" && !strings.Contains(reason, st.Source.Error) {
			msg += " (source agent: " + st.Source.Error + ")"
		}
		return ctrl.Result{}, r.transition(ctx, mig, v1alpha1.PhaseRolledBack, msg,
			func(s *v1alpha1.MigrationStatus) {
				setCondition(s, mig.Generation, metav1.ConditionFalse, ReasonRolledBack, reason)
			})
	}
	var waited time.Duration
	if st.PhaseChangedAt != nil {
		waited = r.Clock.Since(st.PhaseChangedAt.Time)
	}
	if waited < AbortTimeout {
		return ctrl.Result{RequeueAfter: AbortTimeout - waited}, nil
	}
	if !st.Source.Accepted && st.Source.FrozenAt == nil {
		return ctrl.Result{}, r.transition(ctx, mig, v1alpha1.PhaseRolledBack,
			"source agent never picked up the migration, nothing was frozen; abort reason: "+reason,
			func(s *v1alpha1.MigrationStatus) {
				setCondition(s, mig.Generation, metav1.ConditionFalse, ReasonRolledBack, reason)
			})
	}
	msg := fmt.Sprintf("source agent did not confirm thaw within %s – source may still be frozen; "+
		"check pod %s on node %s (abort reason: %s)", AbortTimeout, mig.Spec.PodName, st.SourceNode, reason)
	if err := r.fail(ctx, mig, msg); err != nil {
		return ctrl.Result{}, err
	}
	r.emitTyped(mig, corev1.EventTypeWarning, "SourceMayBeFrozen", msg)
	return ctrl.Result{}, nil
}

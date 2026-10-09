// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"paguro.dev/paguro/api/v1alpha1"
)

// Condition types and reasons.
const (
	ConditionRestored = "Restored"

	ReasonRestored   = "Restored"
	ReasonColdStart  = "ColdStart"
	ReasonFailed     = "Failed"
	ReasonRolledBack = "RolledBack"

	eventAction = "Migrate"
)

func (r *MigrationReconciler) now() metav1.MicroTime {
	return metav1.NewMicroTime(r.Clock.Now())
}

// Status writes. The controller writes its own fields of status, the agents
// theirs (merge patches touch only what changed):
//
//   - transition: a phase change (optimistic lock), with events and metrics.
//   - patchStatus: controller fields that must not race another controller
//     replica's decision (optimistic lock: a conflict is retried by the
//     reconcile).
//   - patchStatusUnlocked: controller fields only it writes, whose write
//     must not fail because an agent patched meanwhile.
//
// On error both restore mig, so that the caller sees what is stored.

// patchStatus applies mutate to the status and sends only the difference
// as a merge patch with resourceVersion.
func (r *MigrationReconciler) patchStatus(ctx context.Context, mig *v1alpha1.Migration, mutate func(*v1alpha1.MigrationStatus)) error {
	base := mig.DeepCopy()
	mutate(&mig.Status)
	err := r.Status().Patch(ctx, mig, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	if err != nil {
		*mig = *base
	}
	return err
}

// patchStatusUnlocked is patchStatus without the optimistic lock.
func (r *MigrationReconciler) patchStatusUnlocked(ctx context.Context, mig *v1alpha1.Migration, mutate func(*v1alpha1.MigrationStatus)) error {
	base := mig.DeepCopy()
	mutate(&mig.Status)
	err := r.Status().Patch(ctx, mig, client.MergeFrom(base))
	if err != nil {
		*mig = *base
	}
	return err
}

// transition changes the phase (optimistic lock), sets message, timestamps
// and – for terminal states – completedAt/totalMs, emits events on the
// migration and pod, and updates the metrics. A conflict is returned
// unchanged (→ requeue); in that case nothing has happened.
func (r *MigrationReconciler) transition(ctx context.Context, mig *v1alpha1.Migration, to v1alpha1.Phase, msg string,
	mutate func(*v1alpha1.MigrationStatus)) error {
	before := mig.DeepCopy()
	now := r.now()
	err := r.patchStatus(ctx, mig, func(st *v1alpha1.MigrationStatus) {
		st.Phase = to
		st.Message = msg
		st.PhaseChangedAt = &now
		if mutate != nil {
			mutate(st)
		}
		if to.Terminal() {
			st.CompletedAt = &now
			if st.StartedAt != nil {
				st.Timings.TotalMs = now.Sub(st.StartedAt.Time).Milliseconds()
			}
		}
	})
	if err != nil {
		*mig = *before
		return err
	}
	logf.FromContext(ctx).Info("phase transition", "from", before.Status.Phase, "to", to, "message", msg)
	r.observePhases(before, now.Time)
	r.emit(mig, to, msg)
	if to.Terminal() {
		r.observeResult(mig)
	}
	return nil
}

// fail: terminal state Failed.
func (r *MigrationReconciler) fail(ctx context.Context, mig *v1alpha1.Migration, msg string) error {
	return r.transition(ctx, mig, v1alpha1.PhaseFailed, msg, func(st *v1alpha1.MigrationStatus) {
		setCondition(st, mig.Generation, metav1.ConditionFalse, ReasonFailed, msg)
	})
}

// abort: request a rollback (only allowed before CuttingOver).
func (r *MigrationReconciler) abort(ctx context.Context, mig *v1alpha1.Migration, msg string) error {
	switch mig.Status.Phase {
	case v1alpha1.PhasePreCopy, v1alpha1.PhaseFrozen:
	default:
		return fmt.Errorf("abort not allowed in phase %s", mig.Status.Phase)
	}
	return r.transition(ctx, mig, v1alpha1.PhaseAborting, msg, nil)
}

func setCondition(st *v1alpha1.MigrationStatus, gen int64, status metav1.ConditionStatus, reason, msg string) {
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	meta.SetStatusCondition(&st.Conditions, metav1.Condition{
		Type: ConditionRestored, Status: status, Reason: reason, Message: msg, ObservedGeneration: gen,
	})
}

// emit emits an event on the migration and one on the affected pod
// (the source until cutover, the replacement pod afterwards).
func (r *MigrationReconciler) emit(mig *v1alpha1.Migration, phase v1alpha1.Phase, msg string) {
	if r.Recorder == nil {
		return
	}
	typ := corev1.EventTypeNormal
	if phase == v1alpha1.PhaseFailed || phase == v1alpha1.PhaseAborting || phase == v1alpha1.PhaseRolledBack {
		typ = corev1.EventTypeWarning
	}
	r.emitTyped(mig, typ, string(phase), msg)
}

func (r *MigrationReconciler) emitTyped(mig *v1alpha1.Migration, typ, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	pod := eventPod(mig)
	msg = truncateNote(msg, maxEventNote-len(mig.Name)-2)
	// A nil *Pod in the runtime.Object parameter is not a nil interface:
	// the recorder would call GetObjectKind on it and panic (measured: a
	// panic per phase transition before a pod was known – each one a
	// failed reconcile with backoff).
	var related runtime.Object
	if pod != nil {
		related = pod
	}
	r.Recorder.Eventf(mig, related, typ, reason, eventAction, "%s", msg)
	if pod != nil {
		r.Recorder.Eventf(pod, mig, typ, "Migration"+reason, eventAction, "%s: %s", mig.Name, msg)
	}
}

// maxEventNote is the API server's limit for an event's note
// (events.k8s.io/v1); longer events are rejected, not shortened.
const maxEventNote = 1024

// truncateNote shortens s to at most n bytes, on a rune boundary.
func truncateNote(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ell = "…"
	cut := n - len(ell)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ell
}

// eventPod builds a reference to the currently relevant pod.
func eventPod(mig *v1alpha1.Migration) *corev1.Pod {
	name, uid := mig.Spec.PodName, mig.Status.SourcePodUID
	if mig.Status.TargetPodName != "" {
		name, uid = mig.Status.TargetPodName, mig.Status.TargetPodUID
	}
	if uid == "" {
		return nil
	}
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: mig.Namespace, UID: types.UID(uid)},
	}
}

// observePhases measures the time spent in the phase(s) being left. The agent
// sets Frozen without phaseChangedAt; source.frozenAt covers that.
func (r *MigrationReconciler) observePhases(before *v1alpha1.Migration, now time.Time) {
	if r.Metrics == nil {
		return
	}
	st := &before.Status
	since := st.PhaseChangedAt
	if st.Phase == v1alpha1.PhaseFrozen && st.Source.FrozenAt != nil {
		if since != nil {
			r.Metrics.Phase.WithLabelValues(string(v1alpha1.PhasePreCopy)).Observe(st.Source.FrozenAt.Sub(since.Time).Seconds())
		}
		since = st.Source.FrozenAt
	}
	if since != nil && st.Phase != "" {
		r.Metrics.Phase.WithLabelValues(string(st.Phase)).Observe(now.Sub(since.Time).Seconds())
	}
}

func (r *MigrationReconciler) observeResult(mig *v1alpha1.Migration) {
	if r.Metrics == nil {
		return
	}
	st := &mig.Status
	r.Metrics.Total.WithLabelValues(string(st.Phase)).Inc()
	if st.Phase == v1alpha1.PhaseSucceeded && st.Timings.FreezeMs > 0 {
		r.Metrics.Freeze.Observe(float64(st.Timings.FreezeMs) / 1000)
	}
	if st.WireBytes > 0 {
		r.Metrics.WireBytes.Observe(float64(st.WireBytes))
	}
}

func msSince(from *metav1.MicroTime, to time.Time) int64 {
	if from == nil {
		return 0
	}
	return to.Sub(from.Time).Milliseconds()
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package controller contains the migration state machine.
//
// Ground rules:
//   - The source pod is never deleted before phase Frozen (Frozen is set only
//     by the source agent, after a successful final dump).
//   - Every phase change is a merge patch with resourceVersion
//     (optimistic lock). If the controller loses the race against an agent,
//     it re-reads and decides again – never acts twice.
//   - Patches only touch fields owned by the controller; the agents write
//     status.source/target/containers/wireBytes/timings.* in parallel.
package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
)

// Time limits of the state machine.
const (
	// The replacement pod must exist within this time after the source is deleted.
	TargetPodTimeout = 60 * time.Second
	// Bare pod: wait this long for the old object to disappear,
	// then force-delete again.
	BareDeleteWait = 30 * time.Second
	// Wait this long for Ready after the restore (only with a readiness probe).
	ReadyWait = 60 * time.Second
	// Aborting: wait this long for the source agent to thaw.
	AbortTimeout = 60 * time.Second
	// PreCopy: the source agent accepts a migration within seconds (also
	// one that was just restarted). One that has not after this long is
	// not coming; waiting out the whole timeout would hold an eviction –
	// and the drain behind it – for ten minutes.
	SourcePickupTimeout = 90 * time.Second
	// Restoring: upper bound from source deletion (the wrapper waits up to
	// 100 s of silence for the data, then cold-starts).
	RestoreTimeout = 5 * time.Minute
	// If a consumed registry entry waits this long without a pod, it is
	// re-armed (pod creation failed after the mutation).
	ReRegisterAfter = 10 * time.Second

	// Short requeue during cutover (the freeze is ticking!).
	fastRequeue = 250 * time.Millisecond

	// conflictRequeue: an agent patched the status concurrently; read it
	// again soon and decide anew (nothing has happened).
	conflictRequeue = 50 * time.Millisecond

	// pollInterval: progress the watches do not announce (restore, readiness,
	// re-announce, a release by an ended migration) is looked at this often.
	pollInterval = time.Second

	// workers: reconciles in parallel. Each migration is handled by one at a
	// time; more workers let a drain's migrations progress side by side.
	workers = 8
)

// MigrationReconciler drives the state machine of a migration.
type MigrationReconciler struct {
	client.Client
	// APIReader reads bypassing the cache (e.g. "is the source pod really gone?").
	APIReader client.Reader
	Recorder  events.EventRecorder
	Registry  webhook.Interceptor
	// Adapter returns the cluster's detected CNI adapter.
	Adapter func() netadapter.Adapter
	Metrics *Metrics
	Clock   clock.PassiveClock
	// Pools rotates the Cilium sticky pool at cutover; nil if not Cilium.
	Pools PoolRotator
	// PhantomAuto lets spec.network=Auto fall back to Phantom mode (instead
	// of Generic) when the IP cannot be kept and every node supports it.
	PhantomAuto bool
	// CommitGate: replacements that keep the IP wait at the commit gate on
	// the target node (gate.go); needs resource.k8s.io/v1.
	CommitGate bool
	// EarlyHandOver: with the commit gate and a Cilium sticky pool, the
	// replacement's sandbox is created while the final dump runs
	// (network.earlyHandOver).
	EarlyHandOver bool
	// PhantomExtraCIDRs are additional in-cluster prefixes for Phantom mode
	// (e.g. pod ranges a CNI does not publish).
	PhantomExtraCIDRs []string
	// PerNode bounds the migrations that move pods off one node at a time
	// (0: no bound); further ones wait in Pending (queue.go).
	PerNode int
	// EvictionTargetWait is how long a migration that an eviction started
	// waits for a node to move to (0: it fails at once; targetwait.go).
	EvictionTargetWait time.Duration

	startMu sync.Mutex // the bound's count and the start of a migration

	// bridgeTimes: the endpoint bridge's timing (bridge.go); nil means
	// defaultBridgeTimes. touchLimit: nil means the package's touchLimit.
	// Tests set them before the reconciler runs.
	bridgeTimes *bridgeTimes
	touchLimit  *rate.Limiter
}

// PoolRotator manages the sticky pool generations of a migration
// (implemented by netadapter.CiliumRotator): PreparePool creates the
// replacement's generation during pre-copy, RotatePool retires the source's
// at cutover (and creates the new one if it was not prepared), DiscardPool
// removes a prepared generation after a rollback.
type PoolRotator interface {
	PreparePool(ctx context.Context, newPool string, ip netip.Addr, targetNode string) error
	RotatePool(ctx context.Context, oldPool, newPool string, ip netip.Addr, targetNode string) error
	DiscardPool(ctx context.Context, pool string) error
	// Reannounce routes the address of a pod's endpoint to it again once
	// replacedBy's endpoint, which had taken the address over, is gone.
	Reannounce(ctx context.Context, namespace, endpoint, replacedBy string) (done bool, err error)
}

// SetupWithManager registers the controller and watches.
func (r *MigrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Clock == nil {
		r.Clock = clock.RealClock{}
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, indexRestoreID, restoreIDOf); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("migration").
		For(&v1alpha1.Migration{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.podToMigrations)).
		Watches(&storagev1.VolumeAttachment{}, handler.EnqueueRequestsFromMapFunc(r.attachmentToMigrations)).
		WithOptions(controller.Options{MaxConcurrentReconciles: workers}).
		Complete(r)
}

// Reconcile implements reconcile.Reconciler.
func (r *MigrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	var mig v1alpha1.Migration
	if err := r.Get(ctx, req.NamespacedName, &mig); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ctx = logf.IntoContext(ctx, log.WithValues("phase", mig.Status.Phase, "pod", mig.Spec.PodName))

	res, err := r.reconcile(ctx, &mig)
	if apierrors.IsConflict(err) {
		// An agent patched concurrently: re-read and decide again.
		return ctrl.Result{RequeueAfter: conflictRequeue}, nil
	}
	return res, err
}

func (r *MigrationReconciler) reconcile(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	phase := mig.Status.Phase
	if phase.Terminal() {
		return r.cleanupTerminal(ctx, mig)
	}

	if !mig.DeletionTimestamp.IsZero() {
		switch phase {
		case "", v1alpha1.PhasePending, v1alpha1.PhasePreflight:
			// Nothing touched yet.
			return ctrl.Result{}, r.removeFinalizer(ctx, mig)
		case v1alpha1.PhasePreCopy:
			return ctrl.Result{}, r.abort(ctx, mig, "migration was deleted")
		case v1alpha1.PhaseFrozen:
			// Committed: a warm replacement may already be restoring from
			// the final images – rolling back now could leave two copies
			// running. Only without a replacement is the source the only
			// copy; otherwise the cutover finishes, then the deletion.
			target, err := r.findTargetPod(ctx, mig)
			if err != nil {
				return ctrl.Result{}, err
			}
			if target == nil {
				return ctrl.Result{}, r.abort(ctx, mig, "migration was deleted")
			}
		}
		// Aborting/CuttingOver/Restoring run to completion normally.
	}

	switch phase {
	case "", v1alpha1.PhasePending:
		return r.start(ctx, mig)
	case v1alpha1.PhasePreflight:
		return r.preflight(ctx, mig)
	case v1alpha1.PhasePreCopy:
		return r.watchPreCopy(ctx, mig)
	case v1alpha1.PhaseFrozen:
		return r.beginCutover(ctx, mig)
	case v1alpha1.PhaseCuttingOver:
		return r.continueCutover(ctx, mig)
	case v1alpha1.PhaseRestoring:
		return r.watchRestore(ctx, mig)
	case v1alpha1.PhaseAborting:
		return r.watchAbort(ctx, mig)
	}
	return ctrl.Result{}, nil
}

// start: Pending → Preflight, once the pod's node has room for another
// migration (queue.go).
func (r *MigrationReconciler) start(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(mig, v1alpha1.Finalizer) {
		base := mig.DeepCopy()
		controllerutil.AddFinalizer(mig, v1alpha1.Finalizer)
		if err := r.Patch(ctx, mig, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, err
		}
	}
	r.startMu.Lock()
	defer r.startMu.Unlock()
	node, wait, err := r.queued(ctx, mig)
	if err != nil {
		return ctrl.Result{}, err
	}
	if wait != "" {
		return ctrl.Result{RequeueAfter: queuePoll}, r.reportQueued(ctx, mig, wait)
	}
	now := r.now()
	return ctrl.Result{}, r.transition(ctx, mig, v1alpha1.PhasePreflight, "checking pod and selecting target node",
		func(st *v1alpha1.MigrationStatus) {
			if st.StartedAt == nil {
				st.StartedAt = &now
			}
			st.SourceNode = node
		})
}

// watchPreCopy: wait until the source agent sets Frozen; timeout/error → Aborting.
func (r *MigrationReconciler) watchPreCopy(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	st := &mig.Status
	if st.Source.Error != "" {
		return ctrl.Result{}, r.abort(ctx, mig, "source agent reported: "+st.Source.Error)
	}
	if st.Target.Error != "" && !st.Target.Ready {
		return ctrl.Result{}, r.abort(ctx, mig, "target agent reported: "+st.Target.Error)
	}
	pod, err := r.sourcePod(ctx, mig)
	if err != nil {
		return ctrl.Result{}, err
	}
	if pod == nil {
		// Disappeared before the freeze: nothing frozen, nothing to save.
		return ctrl.Result{}, r.fail(ctx, mig, "source pod disappeared before freeze (deleted by someone else?)")
	}
	remaining := r.remaining(mig)
	if remaining <= 0 {
		return ctrl.Result{}, r.abort(ctx, mig, fmt.Sprintf("timeout: source not frozen within %ds", mig.Spec.TimeoutSeconds))
	}
	if !st.Source.Accepted && st.PhaseChangedAt != nil {
		left := SourcePickupTimeout - r.Clock.Since(st.PhaseChangedAt.Time)
		if left <= 0 {
			return ctrl.Result{}, r.abort(ctx, mig, fmt.Sprintf("the source agent on %s did not pick up the migration within %s",
				st.SourceNode, SourcePickupTimeout))
		}
		remaining = min(remaining, left)
	}
	r.preparePool(ctx, mig)
	if st.Network.CommitGate && st.TargetPodName != "" {
		if target, err := r.findTargetPod(ctx, mig); err == nil && target != nil {
			if err := r.ensureGateClaim(ctx, mig, target); err != nil {
				r.emitTyped(mig, corev1.EventTypeWarning, "CommitGate", err.Error())
			}
		}
	}
	if isEarly(mig) && replacementDue(st) {
		res, err := r.ensureEarlyReplacement(ctx, mig, pod)
		if err != nil || mig.Status.Phase != v1alpha1.PhasePreCopy {
			return ctrl.Result{}, err
		}
		if res.RequeueAfter > 0 && res.RequeueAfter < remaining {
			return res, nil
		}
	}
	return ctrl.Result{RequeueAfter: remaining}, nil
}

// replacementDue decides when the early (warm) replacement pod may exist.
// With a kept IP its sandbox waits for the IP until the cutover, so it is
// created right away. With a new IP its sandbox comes up at once and its
// containers wait in paguro-runc for the checkpoint – for a bounded time and
// within kubelet's CRI timeout. It is therefore created only when pre-copy
// has converged, and the source freezes once the sandbox is up
// (FreezeAfterTargetSandbox) – unless a volume that could not be
// pre-attached holds the sandbox back until the cutover anyway.
func replacementDue(st *v1alpha1.MigrationStatus) bool {
	switch {
	case st.IPPreserved:
		return true
	case !st.Target.Ready:
		return false // pre-attach result not known yet
	case st.FreezeAfterTargetSandbox():
		return st.Source.ReadyToFreezeAt != nil
	default:
		return true
	}
}

// remaining returns the time left until spec.timeoutSeconds from startedAt.
func (r *MigrationReconciler) remaining(mig *v1alpha1.Migration) time.Duration {
	if mig.Status.StartedAt == nil {
		return time.Hour
	}
	timeout := time.Duration(mig.Spec.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 600 * time.Second
	}
	return mig.Status.StartedAt.Add(timeout).Sub(r.now().Time)
}

// sourcePod returns the source pod (nil if gone or replaced by another pod
// with the same name).
func (r *MigrationReconciler) sourcePod(ctx context.Context, mig *v1alpha1.Migration) (*corev1.Pod, error) {
	var pod corev1.Pod
	err := r.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: mig.Spec.PodName}, &pod)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if mig.Status.SourcePodUID != "" && string(pod.UID) != mig.Status.SourcePodUID {
		return nil, nil
	}
	return &pod, nil
}

func (r *MigrationReconciler) removeFinalizer(ctx context.Context, mig *v1alpha1.Migration) error {
	if !controllerutil.ContainsFinalizer(mig, v1alpha1.Finalizer) {
		return nil
	}
	base := mig.DeepCopy()
	controllerutil.RemoveFinalizer(mig, v1alpha1.Finalizer)
	return client.IgnoreNotFound(r.Patch(ctx, mig, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})))
}

// podToMigrations maps pod events to the running migrations in the
// namespace (source pod, replacement pod, the owner's pods).
func (r *MigrationReconciler) podToMigrations(ctx context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	var list v1alpha1.MigrationList
	if err := r.List(ctx, &list, client.InNamespace(pod.Namespace)); err != nil {
		return nil
	}
	restoreID := pod.Annotations[v1alpha1.AnnotationRestoreID]
	var owner string
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			owner = string(ref.UID)
		}
	}
	var out []reconcile.Request
	for i := range list.Items {
		m := &list.Items[i]
		if m.Status.Phase.Terminal() {
			continue
		}
		if m.Spec.PodName == pod.Name || m.Status.TargetPodName == pod.Name || string(m.UID) == restoreID ||
			(owner != "" && m.Status.Cutover.ReplacementOwnerUID == owner) {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(m)})
		}
	}
	return out
}

// attachmentToMigrations: VolumeAttachment events only concern migrations
// in cutover/restore.
func (r *MigrationReconciler) attachmentToMigrations(ctx context.Context, _ client.Object) []reconcile.Request {
	var list v1alpha1.MigrationList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		m := &list.Items[i]
		if p := m.Status.Phase; (p == v1alpha1.PhaseCuttingOver || p == v1alpha1.PhaseRestoring) && hasRWO(m) {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(m)})
		}
	}
	return out
}

func hasRWO(m *v1alpha1.Migration) bool {
	for _, v := range m.Status.Volumes {
		if v.Kind == VolumePVCRWO {
			return true
		}
	}
	return false
}

// indexRestoreID indexes pods by their restore id (the migration's UID):
// the replacement of a migration is found without listing the namespace.
const indexRestoreID = "paguro.dev/restore-id"

func restoreIDOf(o client.Object) []string {
	if id := o.GetAnnotations()[v1alpha1.AnnotationRestoreID]; id != "" {
		return []string{id}
	}
	return nil
}

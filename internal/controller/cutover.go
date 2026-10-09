// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/gate"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
)

// beginCutover: Frozen (set by the source agent) → CuttingOver and delete the
// source pod. From here on there is no rollback.
func (r *MigrationReconciler) beginCutover(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	if mig.Status.Source.FrozenAt == nil {
		// The agent sets frozenAt before Frozen; wait briefly instead of deleting blindly.
		logf.FromContext(ctx).Info("phase Frozen without source.frozenAt, waiting")
		return ctrl.Result{RequeueAfter: fastRequeue}, nil
	}
	r.emitTyped(mig, corev1.EventTypeNormal, string(v1alpha1.PhaseFrozen),
		fmt.Sprintf("source frozen on %s, final dump done", mig.Status.SourceNode))
	// Before the source's endpoint can leave its Services (keeper.go).
	if pod, err := r.sourcePod(ctx, mig); err == nil {
		if err := r.ensureBackendKeeper(ctx, mig, pod); err != nil {
			r.emitTyped(mig, corev1.EventTypeWarning, "BackendKeeper",
				"connections through a stateful load balancer may be reset: "+err.Error())
		}
	}
	// Before the source leaves its Services, too (bridge.go).
	r.bridgeEndpoints(ctx, mig)
	if isEarly(mig) {
		return r.beginEarlyCutover(ctx, mig)
	}

	now := r.now()
	// Phase change and deletion timestamp in one patch: if we win the
	// optimistic lock, we are the only one deleting.
	// Arming the interception travels with the phase change: it is
	// visible to every webhook replica before the source deletion makes
	// the owner create the replacement.
	if err := r.transition(ctx, mig, v1alpha1.PhaseCuttingOver,
		"deleting source pod, waiting for replacement on "+mig.Status.TargetNode,
		func(st *v1alpha1.MigrationStatus) {
			st.Cutover.SourceDeletedAt = &now
			if st.Cutover.ReplacementOwnerUID != "" && st.Cutover.Mode != v1alpha1.CutoverSameName &&
				st.Cutover.InterceptArmedAt == nil {
				st.Cutover.InterceptArmedAt = &now
			}
		}); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.registerReplacement(ctx, mig, false); err != nil {
		return ctrl.Result{}, err
	}
	// Pool first: the target's IP is on the critical path, and the source
	// agent has already released the endpoint after the final dump.
	r.rotatePool(ctx, mig)
	// Agones must not take the deletion for the end of the game server.
	if err := r.holdGameServer(ctx, mig); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.deleteSourcePod(ctx, mig); err != nil {
		return ctrl.Result{}, err
	}
	r.coverSourceLeaving(ctx, mig)
	return ctrl.Result{RequeueAfter: fastRequeue}, nil
}

// beginEarlyCutover: The warm replacement pod already exists – just delete the
// source (detached from the ReplicaSet) and go straight to Restoring.
func (r *MigrationReconciler) beginEarlyCutover(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	target, err := r.findTargetPod(ctx, mig)
	if err != nil {
		return ctrl.Result{}, err
	}
	if target == nil {
		// The freeze came before the warm replacement (e.g. StopAndCopy) or it
		// disappeared: keep requesting; roll back after TargetPodTimeout
		// (the source is still alive, frozen).
		source, err := r.sourcePod(ctx, mig)
		if err != nil {
			return ctrl.Result{}, err
		}
		if source == nil {
			return ctrl.Result{}, r.fail(ctx, mig, "frozen source pod disappeared before cutover")
		}
		return r.ensureEarlyReplacement(ctx, mig, source)
	}
	now := r.now()
	if err := r.transition(ctx, mig, v1alpha1.PhaseCuttingOver,
		"deleting source pod, warm target "+target.Name+" takes over on "+mig.Status.TargetNode,
		func(st *v1alpha1.MigrationStatus) { st.Cutover.SourceDeletedAt = &now }); err != nil {
		return ctrl.Result{}, err
	}
	r.rotatePool(ctx, mig) // before the delete, see beginCutover
	if err := r.deleteSourcePod(ctx, mig); err != nil {
		return ctrl.Result{}, err
	}
	// The source's own slice drops the kept IP once kubelet has removed
	// the pod (bridge.go).
	r.coverSourceLeaving(ctx, mig)
	// Usually the target agent has released the gated replacement already
	// (at the commit); this covers a slow or restarted agent.
	if gate.Gated(target) || target.Spec.NodeName == "" {
		if err := gate.ReleaseAndBind(ctx, r.Client, target, mig.Status.TargetNode); err != nil {
			r.emitTyped(mig, corev1.EventTypeWarning, "ReleaseFailed", err.Error())
		}
	}
	// A conflict here is harmless: continueCutover finds the target pod again.
	return ctrl.Result{}, r.enterRestoring(ctx, mig, target)
}

// registerReplacement arms the webhook for the owner.
func (r *MigrationReconciler) registerReplacement(ctx context.Context, mig *v1alpha1.Migration, force bool) error {
	// Same-name: Paguro creates the replacement itself.
	if mig.Status.Cutover.ReplacementOwnerUID == "" || mig.Status.Cutover.Mode == v1alpha1.CutoverSameName {
		return nil
	}
	return r.Registry.Register(ctx, mig, force)
}

// deleteSourcePod deletes the source pod immediately (grace 0). The UID
// precondition protects a replacement that has since taken the same name
// (StatefulSet, bare pod).
func (r *MigrationReconciler) deleteSourcePod(ctx context.Context, mig *v1alpha1.Migration) error {
	if mig.Status.Source.FrozenAt == nil || mig.Status.SourcePodUID == "" {
		return fmt.Errorf("refusing to delete source pod: not frozen")
	}
	uid := types.UID(mig.Status.SourcePodUID)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: mig.Namespace, Name: mig.Spec.PodName}}
	err := r.Delete(ctx, pod, client.GracePeriodSeconds(sourceGracePeriod(mig)), client.Preconditions{UID: &uid})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil // already gone, or the name already belongs to another pod
	}
	return err
}

// ensureSourceDeleted makes sure the source is gone once the migration is
// committed (status.cutover.sourceDeletedAt). The delete at the commit can
// fail, or the controller can lose its leadership between the commit and
// the delete – a source left behind keeps its frozen process, its endpoint
// and, with a kept IP, the replacement's address (seen in the lab after a
// controller rollout: the next migration of the workload picked the frozen
// pod). Called on every step after the commit; reports whether the source
// is gone or terminating.
func (r *MigrationReconciler) ensureSourceDeleted(ctx context.Context, mig *v1alpha1.Migration) (bool, error) {
	if mig.Status.Cutover.SourceDeletedAt == nil {
		return true, nil
	}
	source, err := r.sourcePod(ctx, mig)
	if err != nil {
		return false, err
	}
	if source == nil || !source.DeletionTimestamp.IsZero() {
		return true, nil
	}
	// The cache may not have seen the deletion yet: ask the API server
	// before deleting again and warning about it.
	live := &corev1.Pod{}
	err = r.APIReader.Get(ctx, client.ObjectKeyFromObject(source), live)
	if apierrors.IsNotFound(err) || (err == nil && (live.UID != source.UID || !live.DeletionTimestamp.IsZero())) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	r.emitTyped(mig, corev1.EventTypeWarning, "SourceNotDeleted",
		fmt.Sprintf("source pod %s still exists after the commit, deleting it", source.Name))
	if err := r.deleteSourcePod(ctx, mig); err != nil {
		return false, err
	}
	return true, nil
}

// sourceGracePeriodNewIP bounds how long the frozen source keeps its
// endpoint (as terminating) when the pod IP changes.
const sourceGracePeriodNewIP = 30

// sourceGracePeriod: with a kept IP the source must vanish at once, its IP
// moves to the replacement. With a new IP it is deleted gracefully: its
// endpoint stays in the Service as *terminating* – load balancers send no
// new connection there but keep routing existing ones (which Phantom mode
// translates to the new pod) – until the replacement serves. Measured on
// Cilium: deleting it at once left the NodePort service without any
// backend for ~1 s, and Cilium reset the external connections in that gap.
// The source agent stops the frozen sandbox once the replacement is ready,
// so the grace period is only an upper bound. The frozen process never runs
// again: SIGTERM stays pending, SIGKILL ends it.
//
// Not for owners that create the replacement only once the source is gone
// (StatefulSets: same name; mode on-delete): there the grace period was the
// freeze – measured 33 s. Their load-balancer state is held by the
// backend keeper, which exists before the source is deleted.
func sourceGracePeriod(mig *v1alpha1.Migration) int64 {
	if mig.Status.IPPreserved || mig.Status.Cutover.Mode == v1alpha1.CutoverOnDelete {
		return 0
	}
	return sourceGracePeriodNewIP
}

// continueCutover: wait for the replacement pod (owner) or create it (bare pod).
func (r *MigrationReconciler) continueCutover(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	st := &mig.Status
	if st.Cutover.SourceDeletedAt == nil {
		return ctrl.Result{}, fmt.Errorf("phase CuttingOver without cutover.sourceDeletedAt")
	}
	elapsed := r.Clock.Since(st.Cutover.SourceDeletedAt.Time)
	r.rotatePool(ctx, mig)
	if _, err := r.ensureSourceDeleted(ctx, mig); err != nil {
		return ctrl.Result{}, err
	}

	target, err := r.findTargetPod(ctx, mig)
	if err != nil {
		return ctrl.Result{}, err
	}
	if target != nil {
		return ctrl.Result{}, r.enterRestoring(ctx, mig, target)
	}

	source, err := r.sourcePod(ctx, mig)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Bare pod in the old mode (on-delete), or an owner that never creates a
	// second pod (same-name): create a replacement with the same name.
	bare := (st.Cutover.ReplacementOwnerUID == "" && !isEarly(mig)) || st.Cutover.Mode == v1alpha1.CutoverSameName

	switch {
	case elapsed > TargetPodTimeout:
		detail := ""
		if source != nil {
			detail = fmt.Sprintf(" (source pod still present, finalizers %v)", source.Finalizers)
		}
		return ctrl.Result{}, r.fail(ctx, mig, fmt.Sprintf(
			"replacement pod did not appear within %s after deleting the source%s; the source is gone, "+
				"no rollback possible – the workload's controller will start a fresh pod", TargetPodTimeout, detail))

	case source != nil:
		// Deletion not (yet) through – after a restart or due to finalizers.
		if source.DeletionTimestamp.IsZero() || (bare && elapsed > BareDeleteWait) {
			if err := r.holdGameServer(ctx, mig); err != nil { // after a controller restart
				return ctrl.Result{}, err
			}
			if bare && elapsed > BareDeleteWait {
				r.emitTyped(mig, corev1.EventTypeWarning, "SourceStuck",
					fmt.Sprintf("source pod still exists after %s (finalizers %v), deleting again", BareDeleteWait, source.Finalizers))
			}
			if err := r.deleteSourcePod(ctx, mig); err != nil {
				return ctrl.Result{}, err
			}
		}
		if !bare {
			if err := r.registerReplacement(ctx, mig, false); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{RequeueAfter: fastRequeue}, nil

	case bare:
		return r.createBareReplacement(ctx, mig)
	}

	// Owner case: source gone, replacement not there yet.
	if escaped, err := r.findEscapedReplacement(ctx, mig, st.Cutover.SourceDeletedAt); err != nil {
		return ctrl.Result{}, err
	} else if escaped != "" {
		return ctrl.Result{}, r.fail(ctx, mig, fmt.Sprintf(
			"replacement pod %s was created without restore (webhook did not intercept it); "+
				"the workload cold-started, memory state is lost", escaped))
	}
	// Mutated, but no pod was created (e.g. rejected by another admission
	// plugin)? Then arm again.
	at, ok := r.Registry.ConsumedAt(mig)
	if err := r.registerReplacement(ctx, mig, ok && r.Clock.Since(at) > ReRegisterAfter); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: fastRequeue}, nil
}

// createBareReplacement creates the replacement for a bare pod once the old
// object is really gone (same name).
func (r *MigrationReconciler) createBareReplacement(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	// The cache may have forgotten the old object before it is really gone.
	var live corev1.Pod
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: mig.Spec.PodName}, &live)
	switch {
	case err == nil && string(live.UID) == mig.Status.SourcePodUID:
		return ctrl.Result{RequeueAfter: fastRequeue}, nil
	case err == nil && live.Annotations[v1alpha1.AnnotationRestoreID] == string(mig.UID):
		return ctrl.Result{}, r.enterRestoring(ctx, mig, &live)
	case err == nil:
		return ctrl.Result{}, r.fail(ctx, mig, fmt.Sprintf(
			"a different pod named %s appeared before the replacement could be created; source is gone", live.Name))
	case !apierrors.IsNotFound(err):
		return ctrl.Result{}, err
	}

	pod, err := webhook.BareReplacement(mig, netadapter.ForName(mig.Status.NetworkAdapter))
	if err != nil {
		return ctrl.Result{}, r.fail(ctx, mig, "cannot build replacement pod: "+err.Error())
	}
	if err := r.Create(ctx, pod); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return ctrl.Result{RequeueAfter: fastRequeue}, nil
		}
		if apierrors.IsInvalid(err) || apierrors.IsForbidden(err) {
			return ctrl.Result{}, r.fail(ctx, mig, "creating replacement pod rejected: "+err.Error())
		}
		return ctrl.Result{}, err
	}
	// The GameServer follows its pod (watchRestore retries).
	if err := r.releaseGameServer(ctx, mig, pod); err != nil {
		r.emitTyped(mig, corev1.EventTypeWarning, "GameServer", err.Error())
	}
	return ctrl.Result{}, r.enterRestoring(ctx, mig, pod)
}

// findTargetPod looks for the pod with restore-id == migration UID.
func (r *MigrationReconciler) findTargetPod(ctx context.Context, mig *v1alpha1.Migration) (*corev1.Pod, error) {
	// By the cache's restore-id index: runs on most reconciles, and a list
	// of the namespace copied every pod in it.
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(mig.Namespace),
		client.MatchingFields{indexRestoreID: string(mig.UID)}); err != nil {
		// Without the index (a client that has none): all of the namespace.
		if err := r.List(ctx, &pods, client.InNamespace(mig.Namespace)); err != nil {
			return nil, err
		}
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Annotations[v1alpha1.AnnotationRestoreID] == string(mig.UID) && string(p.UID) != mig.Status.SourcePodUID {
			return p, nil
		}
	}
	return nil, nil
}

// findTargetPodLive is findTargetPod from the API server instead of the
// cache, for decisions a stale cache must not make.
func (r *MigrationReconciler) findTargetPodLive(ctx context.Context, mig *v1alpha1.Migration) (*corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.APIReader.List(ctx, &pods, client.InNamespace(mig.Namespace)); err != nil {
		return nil, err
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Annotations[v1alpha1.AnnotationRestoreID] == string(mig.UID) && string(p.UID) != mig.Status.SourcePodUID {
			return p, nil
		}
	}
	return nil, nil
}

// findEscapedReplacement finds an owner pod created after since (deletion of
// the source or request of the early replacement) that the webhook did not
// intercept.
func (r *MigrationReconciler) findEscapedReplacement(ctx context.Context, mig *v1alpha1.Migration, since *metav1.MicroTime) (string, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(mig.Namespace)); err != nil {
		return "", err
	}
	// creationTimestamp only has second precision.
	deleted := since.Truncate(time.Second)
	for i := range pods.Items {
		p := &pods.Items[i]
		owner := metav1.GetControllerOf(p)
		if owner == nil || string(owner.UID) != mig.Status.Cutover.ReplacementOwnerUID ||
			string(p.UID) == mig.Status.SourcePodUID || p.Annotations[v1alpha1.AnnotationRestoreID] != "" {
			continue
		}
		if !p.CreationTimestamp.Time.Before(deleted) {
			return p.Name, nil
		}
	}
	return "", nil
}

// enterRestoring: replacement pod exists → Restoring.
func (r *MigrationReconciler) enterRestoring(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod) error {
	created := r.now()
	if at, ok := r.Registry.ConsumedAt(mig); ok {
		created = metav1.NewMicroTime(at)
	}
	return r.transition(ctx, mig, v1alpha1.PhaseRestoring,
		fmt.Sprintf("replacement pod %s created on %s, restoring", pod.Name, mig.Status.TargetNode),
		func(st *v1alpha1.MigrationStatus) {
			st.TargetPodName = pod.Name
			st.TargetPodUID = string(pod.UID)
			st.TargetPodIP = pod.Status.PodIP
			if st.Cutover.TargetPodCreatedAt == nil {
				st.Cutover.TargetPodCreatedAt = &created
			}
			// early: the replacement already existed before the deletion → 0.
			st.Timings.CutoverMs = max(0, st.Cutover.TargetPodCreatedAt.Sub(st.Cutover.SourceDeletedAt.Time).Milliseconds())
		})
}

// rotatePool deletes the source's sticky pool and creates the replacement's
// fresh generation (Cilium only, once the cutover is committed, i.e.
// sourceDeletedAt is set). Failures are reported and retried on the next reconcile; once the
// new pool exists it is never removed by the controller.
//
// The address stays routed into the cluster in between: the source agent
// keeps the old pool's /32 on its node until the restore (CiliumHooks.Hold),
// so deleting the old pool does not open a window – not even while an RWO
// volume moves and the target requests the address only seconds later.
func (r *MigrationReconciler) rotatePool(ctx context.Context, mig *v1alpha1.Migration) {
	nw := mig.Status.Network
	if r.Pools == nil || nw.TargetPool == "" || nw.PoolRotatedAt != nil || mig.Status.Cutover.SourceDeletedAt == nil {
		return
	}
	ip, err := netip.ParseAddr(mig.Status.SourcePodIP)
	if err != nil {
		logf.FromContext(ctx).Error(err, "cannot rotate sticky pool", "ip", mig.Status.SourcePodIP)
		return
	}
	if err := r.Pools.RotatePool(ctx, nw.SourcePool, nw.TargetPool, ip, mig.Status.TargetNode); err != nil {
		r.emitTyped(mig, corev1.EventTypeWarning, "PoolRotationFailed", err.Error())
		return
	}
	now := r.now()
	if err := r.patchStatus(ctx, mig, func(st *v1alpha1.MigrationStatus) { st.Network.PoolRotatedAt = &now }); err != nil {
		// Rotation is idempotent; the next reconcile records it.
		logf.FromContext(ctx).Info("recording pool rotation failed, will retry", "error", err.Error())
		return
	}
	r.emitTyped(mig, corev1.EventTypeNormal, "PoolRotated",
		fmt.Sprintf("sticky IP %s: pool %s replaced by %s for node %s", ip, orNone(nw.SourcePool), nw.TargetPool, mig.Status.TargetNode))
}

// preparePool creates the replacement's pool generation during pre-copy
// (Cilium, kept IP), so that the operator hands the /32 to the target node
// before the freeze and the replacement's first sandbox attempt after the
// commit succeeds. The source's endpoint keeps the address meanwhile. A
// failure is reported and retried; without it the cutover creates the pool
// as before.
func (r *MigrationReconciler) preparePool(ctx context.Context, mig *v1alpha1.Migration) {
	nw := mig.Status.Network
	if r.Pools == nil || nw.TargetPool == "" || nw.PoolPreparedAt != nil || !mig.Status.IPPreserved || mig.Status.TargetNode == "" {
		return
	}
	ip, err := netip.ParseAddr(mig.Status.SourcePodIP)
	if err != nil {
		return
	}
	if err := r.Pools.PreparePool(ctx, nw.TargetPool, ip, mig.Status.TargetNode); err != nil {
		r.emitTyped(mig, corev1.EventTypeWarning, "PoolPreparationFailed", err.Error())
		return
	}
	now := r.now()
	if err := r.patchStatus(ctx, mig, func(st *v1alpha1.MigrationStatus) { st.Network.PoolPreparedAt = &now }); err != nil {
		logf.FromContext(ctx).Info("recording pool preparation failed, will retry", "error", err.Error())
		return
	}
	r.emitTyped(mig, corev1.EventTypeNormal, "PoolPrepared",
		fmt.Sprintf("sticky IP %s: pool %s created for node %s ahead of the freeze", ip, nw.TargetPool, mig.Status.TargetNode))
}

// discardPreparedPool removes the prepared generation of a migration that
// is rolled back (other leftovers go to the pool GC).
func (r *MigrationReconciler) discardPreparedPool(ctx context.Context, mig *v1alpha1.Migration) {
	nw := mig.Status.Network
	if r.Pools == nil || nw.PoolPreparedAt == nil || nw.PoolRotatedAt != nil || mig.Status.Cutover.SourceDeletedAt != nil {
		return
	}
	if err := r.Pools.DiscardPool(ctx, nw.TargetPool); err != nil {
		logf.FromContext(ctx).Info("discarding the prepared pool failed (the pool GC removes it later)", "pool", nw.TargetPool, "error", err.Error())
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

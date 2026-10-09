// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/gate"
)

// The hand-over of a kept IP on Cilium, target side.
//
// The replacement's sandbox can only come up once its /32 is usable on this
// node, and kubelet retries a failed sandbox only at its next status refresh
// (once per second: before every sync the pod worker waits for a cache
// update newer than its previous sync). A replacement that tried during
// pre-copy and failed therefore waited half a second on average after the
// address had arrived (measured: attempts at 51.87, 52.54 and 53.55 for an
// address that was ready at ~52.8). Now:
//
//   - The controller creates the replacement's pool generation during
//     pre-copy; preallocate asks this node's Cilium agent for it under the
//     owner the CNI plugin will use, so that the operator hands the /32 to
//     this node ahead of the freeze. The source's endpoint keeps the address
//     meanwhile (an endpoint always takes precedence over a node's CIDR).
//   - The webhook holds the replacement back with a scheduling gate;
//     bindOnCommit releases it and binds it to this node as soon as the
//     migration is committed. kubelet's first sync of a pod does not wait
//     for a status refresh, and its first sandbox attempt finds the address.

// preallocate requests the replacement's pool generation during pre-copy
// under the CNI plugin's owner ("<namespace>/<pod>"). While the pool's CIDR
// is not on this node the request fails and Cilium keeps it as pending –
// that demand makes the operator allocate the /32 here. Once the CIDR is
// here nothing is requested any more: a request would take the address
// itself. The CNI plugin's successful allocation clears the pending request
// (same pool and owner). Ends with the commit.
func (j *targetJob) preallocate(ctx context.Context) {
	if j.a.Cilium == nil || !j.m.Status.IPPreserved {
		return
	}
	key := client.ObjectKeyFromObject(j.m)
	arrived := false
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
		cur := &v1.Migration{}
		if err := j.a.Client.Get(ctx, key, cur); err != nil {
			continue
		}
		if cur.Status.Phase.Terminal() || committed(cur.Status.Phase) {
			return
		}
		nw := cur.Status.Network
		name := replacementPodName(cur)
		if nw.TargetPool == "" || nw.PoolPreparedAt == nil || name == "" {
			continue
		}
		if j.poolOnNode(ctx, nw.TargetPool) {
			if !arrived {
				// The source waits for this report before it freezes.
				err := j.a.patchStatus(ctx, j.m, map[string]any{"target": map[string]any{"addressReadyAt": now()}})
				arrived = err == nil
				j.log.Info("sticky /32 allocated to the target ahead of the freeze", "pool", nw.TargetPool, "requests", n)
			}
			continue
		}
		arrived = false
		owner := cur.Namespace + "/" + name
		taken, err := j.a.Cilium.Hold(ctx, nw.TargetPool, owner)
		switch {
		case err != nil:
			j.log.Warn("requesting the replacement's pool ahead of the freeze", "pool", nw.TargetPool, "err", err)
		case taken != "":
			// The CIDR arrived between the check and the request: give the
			// address back at once, it belongs to the replacement's sandbox.
			if err := j.a.Cilium.Unhold(ctx, nw.TargetPool, owner, taken, taken); err != nil {
				j.log.Warn("returning an address taken ahead of the freeze", "ip", taken, "err", err)
			}
		}
		j.nudgeOwnNode(ctx, n)
	}
}

// bindOnCommit releases a replacement held back by the scheduling gate
// (names.SchedulingGateCommit) and binds it to this node itself – before
// the scheduler gets to it, and independent of a custom scheduler. When:
//   - with the commit gate (status.network.commitGate) as soon as the source
//     is ready to freeze and the gate claim is reserved for the pod: kubelet
//     then takes it through admission and volume setup and holds it at the
//     gate (dragate.go) – the source freezes on that;
//   - otherwise at the commit (the source agent does it right after the
//     dump already; this is the fallback).
//
// The controller does the same at cutover in case this agent is slow.
func (j *targetJob) bindOnCommit(ctx context.Context) {
	if !j.m.Status.IPPreserved {
		return
	}
	key := client.ObjectKeyFromObject(j.m)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Millisecond):
		}
		cur := &v1.Migration{}
		if err := j.a.Client.Get(ctx, key, cur); err != nil {
			continue
		}
		if cur.Status.Phase.Terminal() {
			return
		}
		gated := cur.Status.Network.CommitGate && cur.Status.Source.ReadyToFreezeAt != nil
		if !gated && !committed(cur.Status.Phase) {
			continue
		}
		// Unbound, the pod is not in this agent's cache (pods of this node
		// only): read it from the API server.
		name := replacementPodName(cur)
		if name == "" {
			continue
		}
		pod := &corev1.Pod{}
		if err := j.a.APIReader.Get(ctx, client.ObjectKey{Namespace: cur.Namespace, Name: name}, pod); err != nil ||
			pod.Annotations[v1.AnnotationRestoreID] != string(cur.UID) {
			continue
		}
		if pod.Spec.NodeName != "" {
			return // bound already
		}
		if gated && !committed(cur.Status.Phase) && !gate.ReservedFor(ctx, j.a.APIReader, cur.Namespace, cur.UID, pod.UID) {
			continue // kubelet would refuse the claim
		}
		start := time.Now()
		if err := gate.ReleaseAndBind(ctx, j.a.Client, pod, j.a.NodeName); err != nil {
			j.log.Warn("releasing the replacement", "pod", pod.Name, "err", err)
			continue
		}
		j.log.Info("replacement released and bound to this node", "pod", pod.Name, "atGate", gated && !committed(cur.Status.Phase), "ms", ms(time.Since(start)))
		return
	}
}

// committed: the source is frozen for good and its replacement may run.
func committed(p v1.Phase) bool {
	return p == v1.PhaseFrozen || p == v1.PhaseCuttingOver || p == v1.PhaseRestoring
}

// replacementPodName is the name the replacement has or will have: the
// deterministic name of an early replacement, or the source's own name
// when the owner recreates it under the same name (StatefulSet).
func replacementPodName(m *v1.Migration) string {
	if m.Status.TargetPodName != "" {
		return m.Status.TargetPodName
	}
	if m.Status.Cutover.Mode != v1.CutoverEarly {
		return m.Spec.PodName
	}
	return ""
}

// poolOnNode reports whether this node's CiliumNode holds a CIDR of pool.
func (j *targetJob) poolOnNode(ctx context.Context, pool string) bool {
	cn := &unstructured.Unstructured{}
	cn.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNode"})
	if err := j.a.Client.Get(ctx, client.ObjectKey{Name: j.a.NodeName}, cn); err != nil {
		return false
	}
	allocated, _, _ := unstructured.NestedSlice(cn.Object, "spec", "ipam", "pools", "allocated")
	for _, a := range allocated {
		if m, ok := a.(map[string]any); ok && m["pool"] == pool {
			return true
		}
	}
	return false
}

// nudgeOwnNode touches this node's CiliumNode so that the operator handles
// its pending request at once instead of after its backoff.
func (j *targetJob) nudgeOwnNode(ctx context.Context, n int) {
	cn := &unstructured.Unstructured{}
	cn.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNode"})
	cn.SetName(j.a.NodeName)
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"paguro.dev/nudge":"pre-%d"}}}`, n)
	_ = j.a.Client.Patch(ctx, cn, client.RawPatch(types.MergePatchType, []byte(patch)))
}

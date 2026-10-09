// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package gate holds what controller, webhook and agent share about a
// replacement pod that waits for its migration's commit: releasing and
// binding it, and its commit-gate claim (internal/agent/dragate.go,
// internal/controller/gate.go).
package gate

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/pkg/names"
)

// Gated reports whether pod is held back by the commit gate.
func Gated(pod *corev1.Pod) bool {
	for _, g := range pod.Spec.SchedulingGates {
		if g.Name == names.SchedulingGateCommit {
			return true
		}
	}
	return false
}

// ReleaseAndBind removes the scheduling gates of an unbound pod and binds it
// to node itself – before the scheduler gets to it, and independent of a
// custom scheduler (the pod's node affinity allows only this node anyway).
// A pod bound meanwhile is fine.
func ReleaseAndBind(ctx context.Context, c client.Client, pod *corev1.Pod, node string) error {
	if pod.Spec.NodeName != "" {
		return nil
	}
	if len(pod.Spec.SchedulingGates) > 0 {
		patch := []byte(`{"spec":{"schedulingGates":null}}`)
		if err := c.Patch(ctx, pod, client.RawPatch(types.StrategicMergePatchType, patch)); err != nil {
			return fmt.Errorf("removing the scheduling gate: %w", err)
		}
	}
	binding := &corev1.Binding{
		ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace, UID: pod.UID},
		Target:     corev1.ObjectReference{Kind: "Node", Name: node},
	}
	if err := c.SubResource("binding").Create(ctx, pod, binding); err != nil &&
		!apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("binding to %s: %w", node, err)
	}
	return nil
}

// ClaimName is the ResourceClaim of a migration's commit gate.
func ClaimName(migrationUID types.UID) string {
	return names.GateClaimPrefix + names.UIDSuffix(string(migrationUID))
}

// PodClaim is the entry a replacement gets in spec.resourceClaims.
func PodClaim(migrationUID types.UID) corev1.PodResourceClaim {
	return corev1.PodResourceClaim{Name: names.GateClaim, ResourceClaimName: ptr.To(ClaimName(migrationUID))}
}

// Reserved reports whether the claim is allocated and reserved for the pod
// (kubelet prepares only such a claim).
func Reserved(claim *resourceapi.ResourceClaim, pod types.UID) bool {
	if claim.Status.Allocation == nil {
		return false
	}
	for _, c := range claim.Status.ReservedFor {
		if c.UID == pod {
			return true
		}
	}
	return false
}

// ReservedFor reads the migration's gate claim and reports Reserved.
func ReservedFor(ctx context.Context, c client.Reader, namespace string, migrationUID, pod types.UID) bool {
	claim := &resourceapi.ResourceClaim{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ClaimName(migrationUID)}, claim); err != nil {
		return false
	}
	return Reserved(claim, pod)
}

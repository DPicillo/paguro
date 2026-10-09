// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

// Commit gate, controller side (agent side: internal/agent/dragate.go).
//
// A replacement that keeps the migrated pod's IP waits, bound to the target
// node, inside kubelet's sync right before its sandbox: the target agent's
// DRA driver holds the preparation of the replacement's claim until the
// migration is committed. The controller decides at preflight whether the
// gate is used, creates the claim, and allocates and reserves it for the
// replacement – Paguro, not a scheduler, places the replacement, so nobody
// else would.

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/gate"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/pkg/names"
)

// gateRequest is the request name inside the gate claim; gateDevice the
// device name Paguro allocates (no ResourceSlice lists it: nothing but this
// driver ever sees the allocation).
const (
	gateRequest = "gate"
	gateDevice  = "gate"
)

// useCommitGate decides at preflight: the controller has the gate enabled,
// the IP is kept – in a pool generation of its own (Cilium: the replacement
// can take the address the moment it leaves the gate) or by Calico (the
// address is free once the source's sandbox is torn down, after the commit;
// the gate opens then) –, the target's agent runs the gate, and no RWO
// volume has to move (kubelet mounts volumes before it prepares claims; an
// RWO volume is only attached to the target after the source's detach,
// after the freeze), and the replacement exists before the commit (an early
// cutover: owners that reuse the pod's name – StatefulSets, GameServers –
// create it only after the source is gone, so nothing would ever arrive at
// the gate). The webhook gates the replacement on the same condition
// (webhook.gateUntilCommit).
func (r *MigrationReconciler) useCommitGate(target *corev1.Node, network v1alpha1.NetworkStatus, adapter string, preserved bool,
	volumes []v1alpha1.VolumeStatus, cutoverMode string) bool {
	// Calico: the gate opens when the source's sandbox is gone
	// (network.handOverAfterSourceStop), not at the commit.
	movable := network.TargetPool != "" || adapter == netadapter.NameCalico
	if !r.CommitGate || !preserved || !movable || target == nil || cutoverMode != v1alpha1.CutoverEarly ||
		target.Annotations[v1alpha1.AnnotationNodeCommitGate] != "true" {
		return false
	}
	for _, v := range volumes {
		if v.Kind == VolumePVCRWO {
			return false
		}
	}
	return true
}

// foreignClaims lists the pod's resource claims other than the commit gate:
// DRA devices (GPUs and the like) cannot be checkpointed.
func foreignClaims(pod *corev1.Pod) []string {
	var out []string
	for _, c := range pod.Spec.ResourceClaims {
		if c.Name != names.GateClaim {
			out = append(out, c.Name)
		}
	}
	return out
}

// ensureGateClaim creates the gate claim of a migration once its replacement
// exists, allocated to the target node and reserved for the replacement.
// kubelet only prepares a claim that is reserved for the pod; the target
// agent binds the replacement only after that. Idempotent.
func (r *MigrationReconciler) ensureGateClaim(ctx context.Context, mig *v1alpha1.Migration, target *corev1.Pod) error {
	if !mig.Status.Network.CommitGate || target == nil || target.UID == "" {
		return nil
	}
	name := gate.ClaimName(mig.UID)
	claim := &resourceapi.ResourceClaim{}
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: name}, claim)
	switch {
	case apierrors.IsNotFound(err):
		claim = &resourceapi.ResourceClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: mig.Namespace,
				Labels: map[string]string{names.LabelMigrationUID: string(mig.UID)},
				// The claim lives as long as the pod: kubelet prepares it again
				// whenever it has to recreate the pod's sandbox.
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1", Kind: "Pod", Name: target.Name, UID: target.UID,
				}},
			},
			Spec: resourceapi.ResourceClaimSpec{Devices: resourceapi.DeviceClaim{
				Requests: []resourceapi.DeviceRequest{{
					Name:    gateRequest,
					Exactly: &resourceapi.ExactDeviceRequest{DeviceClassName: names.GateDriver},
				}},
			}},
		}
		if err := r.Create(ctx, claim); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("commit gate claim: %w", err)
		}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(claim), claim); err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if gate.Reserved(claim, target.UID) {
		return nil
	}
	claim.Status.Allocation = &resourceapi.AllocationResult{
		Devices: resourceapi.DeviceAllocationResult{Results: []resourceapi.DeviceRequestAllocationResult{{
			Request: gateRequest, Driver: names.GateDriver, Pool: mig.Status.TargetNode, Device: gateDevice,
		}}},
		NodeSelector: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
			MatchFields: []corev1.NodeSelectorRequirement{{
				Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{mig.Status.TargetNode},
			}},
		}}},
	}
	claim.Status.ReservedFor = []resourceapi.ResourceClaimConsumerReference{{
		Resource: "pods", Name: target.Name, UID: target.UID,
	}}
	if err := r.Status().Update(ctx, claim); err != nil {
		return fmt.Errorf("allocating the commit gate claim: %w", err)
	}
	return nil
}

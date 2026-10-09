// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

// Agones game servers. A GameServer owns exactly one pod, found by the
// GameServer's own name, and never creates a second one once it is Ready:
// Agones' controllers declare it Unhealthy – and a Fleet replaces it, with
// a fresh process – as soon as that pod is deleted, missing, or shows up on
// another node than status.nodeName ("Node migration occurred").
//
// Paguro therefore replaces the pod itself, under the same name (cutover
// mode same-name), and holds the GameServer while it does: the annotation
// paguro.dev/migrating plus the chart's admission policy (AgonesGuardPolicy)
// turn away Agones' updates to Unhealthy in that window; Agones retries
// them. Once the replacement exists, Paguro points status.nodeName and the
// addresses at the target node, the way Agones computes them, and lifts the
// hold in the same patch – Agones' retries then find a healthy pod where
// the GameServer says it is.

// AgonesGuardPolicy is the chart's ValidatingAdmissionPolicy (value
// agones.enabled).
const AgonesGuardPolicy = "paguro-agones-guard"

var gameServerGVK = schema.GroupVersionKind{Group: "agones.dev", Version: "v1", Kind: "GameServer"}

// agonesNodePodIP is Agones' address type for pod IPs in status.addresses.
const agonesNodePodIP = "PodIP"

func isGameServer(ref *metav1.OwnerReference) bool {
	return ref != nil && ref.Kind == gameServerGVK.Kind && strings.HasPrefix(ref.APIVersion, gameServerGVK.Group+"/")
}

func gameServerOf(mig *v1alpha1.Migration) bool {
	return mig.Status.Cutover.Mode == v1alpha1.CutoverSameName && mig.Status.OwnerKind == gameServerGVK.Kind
}

func newGameServer(namespace, name string) *unstructured.Unstructured {
	gs := &unstructured.Unstructured{}
	gs.SetGroupVersionKind(gameServerGVK)
	gs.SetNamespace(namespace)
	gs.SetName(name)
	return gs
}

// checkGameServer (preflight): only a running GameServer moves, and only
// with the guard policy in place.
func (r *MigrationReconciler) checkGameServer(ctx context.Context, pod *corev1.Pod, owner *metav1.OwnerReference) error {
	gs := newGameServer(pod.Namespace, owner.Name)
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gs), gs); err != nil {
		if apierrors.IsNotFound(err) {
			return reject("GameServer %s not found", owner.Name)
		}
		return err
	}
	if gs.GetDeletionTimestamp() != nil {
		return reject("GameServer %s is being deleted", owner.Name)
	}
	switch state, _, _ := unstructured.NestedString(gs.Object, "status", "state"); state {
	case "Ready", "Reserved", "Allocated":
	default:
		return reject("GameServer %s is %s; only Ready, Reserved and Allocated game servers move", owner.Name, state)
	}
	if held := gs.GetAnnotations()[v1alpha1.AnnotationMigrating]; held != "" {
		return reject("GameServer %s is held by migration %s", owner.Name, held)
	}
	vap := &admissionregistrationv1.ValidatingAdmissionPolicy{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: AgonesGuardPolicy}, vap); err != nil {
		if apierrors.IsNotFound(err) {
			return reject("Agones integration not installed (chart value agones.enabled, Kubernetes >= 1.30): without "+
				"%s Agones declares a GameServer Unhealthy when its pod is replaced", AgonesGuardPolicy)
		}
		return err
	}
	return nil
}

// holdGameServer marks the GameServer before its pod is deleted. Idempotent.
func (r *MigrationReconciler) holdGameServer(ctx context.Context, mig *v1alpha1.Migration) error {
	if !gameServerOf(mig) {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"metadata": map[string]any{
		"annotations": map[string]string{v1alpha1.AnnotationMigrating: string(mig.UID)}}})
	gs := newGameServer(mig.Namespace, mig.Status.OwnerName)
	if err := r.Patch(ctx, gs, client.RawPatch(types.MergePatchType, body)); err != nil {
		return fmt.Errorf("holding GameServer %s: %w", gs.GetName(), err)
	}
	return nil
}

// releaseGameServer points the GameServer at the replacement's node and
// lifts the hold, in one patch. Idempotent; a GameServer this migration
// does not hold is left alone.
func (r *MigrationReconciler) releaseGameServer(ctx context.Context, mig *v1alpha1.Migration, replacement *corev1.Pod) error {
	if !gameServerOf(mig) {
		return nil
	}
	gs := newGameServer(mig.Namespace, mig.Status.OwnerName)
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gs), gs); err != nil {
		return client.IgnoreNotFound(err)
	}
	if gs.GetAnnotations()[v1alpha1.AnnotationMigrating] != string(mig.UID) {
		return nil
	}
	node := &corev1.Node{}
	if err := r.Get(ctx, client.ObjectKey{Name: mig.Status.TargetNode}, node); err != nil {
		return err
	}
	addr, addrs := agonesAddress(node)
	ips := []string{}
	if replacement != nil {
		for _, ip := range replacement.Status.PodIPs {
			ips = append(ips, ip.IP)
		}
	}
	if len(ips) == 0 && mig.Status.IPPreserved && mig.Status.SourcePodIP != "" {
		ips = append(ips, mig.Status.SourcePodIP) // the replacement takes it
	}
	for _, ip := range ips {
		addrs = append(addrs, map[string]any{"type": agonesNodePodIP, "address": ip})
	}
	body, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": gs.GetResourceVersion(),
			"annotations":     map[string]any{v1alpha1.AnnotationMigrating: nil},
		},
		"status": map[string]any{"nodeName": mig.Status.TargetNode, "address": addr, "addresses": addrs},
	})
	if err := r.Patch(ctx, gs, client.RawPatch(types.MergePatchType, body)); err != nil {
		return fmt.Errorf("releasing GameServer %s: %w", gs.GetName(), err)
	}
	r.emitTyped(mig, corev1.EventTypeNormal, "GameServerMoved",
		fmt.Sprintf("GameServer %s now on %s (address %s)", gs.GetName(), mig.Status.TargetNode, addr))
	return nil
}

// forgetGameServer lifts a hold this migration left (it ended before the
// replacement existed). Agones then judges the GameServer by its pod again.
func (r *MigrationReconciler) forgetGameServer(ctx context.Context, mig *v1alpha1.Migration) error {
	if !gameServerOf(mig) {
		return nil
	}
	gs := newGameServer(mig.Namespace, mig.Status.OwnerName)
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gs), gs); err != nil {
		return client.IgnoreNotFound(err)
	}
	if gs.GetAnnotations()[v1alpha1.AnnotationMigrating] != string(mig.UID) {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"metadata": map[string]any{
		"annotations": map[string]any{v1alpha1.AnnotationMigrating: nil}}})
	return client.IgnoreNotFound(r.Patch(ctx, gs, client.RawPatch(types.MergePatchType, body)))
}

// agonesAddress mirrors Agones' choice of a GameServer's address: the
// node's external DNS name, else external IP, internal DNS name, internal
// IP; status.addresses lists all of the node's addresses.
func agonesAddress(node *corev1.Node) (string, []any) {
	addrs := make([]any, 0, len(node.Status.Addresses))
	for _, a := range node.Status.Addresses {
		addrs = append(addrs, map[string]any{"type": string(a.Type), "address": a.Address})
	}
	for _, want := range []corev1.NodeAddressType{corev1.NodeExternalDNS, corev1.NodeExternalIP, corev1.NodeInternalDNS, corev1.NodeInternalIP} {
		for _, a := range node.Status.Addresses {
			if a.Type != want {
				continue
			}
			if (want == corev1.NodeExternalIP || want == corev1.NodeInternalIP) && net.ParseIP(a.Address) == nil {
				continue
			}
			return a.Address, addrs
		}
	}
	return "", addrs
}

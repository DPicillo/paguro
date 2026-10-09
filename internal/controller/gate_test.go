// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/gate"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/pkg/names"
)

func TestUseCommitGate(t *testing.T) {
	r := &MigrationReconciler{CommitGate: true}
	gateNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b", Annotations: map[string]string{v1alpha1.AnnotationNodeCommitGate: "true"}}}
	plain := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-c"}}
	rwx := []v1alpha1.VolumeStatus{{Name: "shared", Kind: VolumePVCRWX}}
	rwo := []v1alpha1.VolumeStatus{{Name: "data", Kind: VolumePVCRWO}}
	for _, c := range []struct {
		name      string
		node      *corev1.Node
		preserved bool
		vols      []v1alpha1.VolumeStatus
		enabled   bool
		want      bool
	}{
		{"kept IP, RWX", gateNode, true, rwx, true, true},
		// Calico: no pool generation, the address is free only after the
		// source's sandbox is gone
		{"kept IP without a pool generation", gateNode, true, nil, true, false},
		{"Calico", gateNode, true, nil, true, true},
		{"new IP", gateNode, false, rwx, true, false},
		{"node without gate", plain, true, nil, true, false},
		// kubelet mounts before it prepares claims: an RWO volume reaches the
		// target only after the source's detach, after the freeze
		{"RWO volume", gateNode, true, rwo, true, false},
		{"disabled", gateNode, true, nil, false, false},
		// the replacement exists only after the source is gone
		{"StatefulSet", gateNode, true, rwx, true, false},
		{"GameServer", gateNode, true, rwx, true, false},
	} {
		r.CommitGate = c.enabled
		nw, adapter := v1alpha1.NetworkStatus{TargetPool: "paguro-10-250-0-2-abcde"}, netadapter.NameCilium
		switch c.name {
		case "kept IP without a pool generation":
			nw.TargetPool, adapter = "", netadapter.NameGeneric
		case "Calico":
			nw.TargetPool, adapter = "", netadapter.NameCalico
		}
		mode := v1alpha1.CutoverEarly
		switch c.name {
		case "StatefulSet":
			mode = v1alpha1.CutoverOnDelete
		case "GameServer":
			mode = v1alpha1.CutoverSameName
		}
		if got := r.useCommitGate(c.node, nw, adapter, c.preserved, c.vols, mode); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCheckPodRejectsDeviceClaims(t *testing.T) {
	pod := testPod()
	pod.Spec.ResourceClaims = []corev1.PodResourceClaim{{Name: names.GateClaim}}
	if _, err := CheckPod(pod); err != nil {
		t.Fatalf("an earlier migration's gate claim must not block: %v", err)
	}
	pod.Spec.ResourceClaims = append(pod.Spec.ResourceClaims, corev1.PodResourceClaim{Name: "gpu"})
	if _, err := CheckPod(pod); err == nil {
		t.Fatal("a pod with DRA devices must be refused")
	}
}

func TestEnsureGateClaim(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&resourceapi.ResourceClaim{}).Build()
	r := &MigrationReconciler{Client: cl, APIReader: cl}
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{TargetNode: "node-b", Network: v1alpha1.NetworkStatus{CommitGate: true}}}
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1-pmigui", Namespace: ns, UID: "pod-uid"}}
	ctx := context.Background()
	for i := 0; i < 2; i++ { // idempotent
		if err := r.ensureGateClaim(ctx, mig, target); err != nil {
			t.Fatal(err)
		}
	}
	claim := &resourceapi.ResourceClaim{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: gate.ClaimName(mig.UID)}, claim); err != nil {
		t.Fatal(err)
	}
	if !gate.Reserved(claim, "pod-uid") {
		t.Fatalf("not reserved for the replacement: %+v", claim.Status)
	}
	res := claim.Status.Allocation.Devices.Results[0]
	if res.Driver != names.GateDriver || res.Pool != "node-b" {
		t.Errorf("allocation %+v", res)
	}
	if len(claim.OwnerReferences) != 1 || claim.OwnerReferences[0].UID != "pod-uid" {
		t.Errorf("the claim must live as long as the pod: %+v", claim.OwnerReferences)
	}
	if claim.Labels[names.LabelMigrationUID] != "abcde-1234" {
		t.Errorf("labels %v", claim.Labels)
	}
	// Without the gate nothing happens.
	mig.Status.Network.CommitGate = false
	other := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: ns, UID: "other"}}
	if err := r.ensureGateClaim(ctx, mig, other); err != nil || gate.ReservedFor(ctx, cl, ns, mig.UID, "other") {
		t.Errorf("gate disabled: %v", err)
	}
}

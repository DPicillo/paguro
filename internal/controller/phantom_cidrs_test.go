// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
)

// On a VPC-native CNI (AWS VPC CNI) no podCIDR names the pods' range; the
// subnets the agents report count as in-cluster, next to the nodes'
// addresses.
func TestPhantomClusterCIDRsNodeSubnets(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	node := func(name, ip, subnets string) *corev1.Node {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}}}
		if subnets != "" {
			n.Annotations = map[string]string{v1alpha1.AnnotationNodeSubnets: subnets}
		}
		return n
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		node("a", "192.168.78.222", "192.168.64.0/19"),
		node("b", "192.168.91.56", "192.168.64.0/19, 192.168.96.0/19"),
		node("c", "10.0.0.5", ""),
	).Build()
	r := &MigrationReconciler{Client: cl, APIReader: cl}
	got := r.phantomClusterCIDRs(context.Background())
	for _, want := range []string{"192.168.64.0/19", "192.168.96.0/19", "10.0.0.5/32", "192.168.78.222/32"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}

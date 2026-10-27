// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
)

// Bottlerocket nodes get the label, other nodes none; a value someone else
// set on another node stays.
func TestNodeOSLabeler(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	node := func(name, os string, labels map[string]string) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OSImage: os}}}
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		node("br", "Bottlerocket OS 1.67.0 (aws-k8s-1.37)", nil),
		node("al", "Amazon Linux 2023.12.20261016", map[string]string{v1alpha1.LabelNodeOS: OSBottlerocket}),
		node("own", "Ubuntu 24.04.3 LTS", map[string]string{v1alpha1.LabelNodeOS: "custom"}),
	).Build()
	l := &NodeOSLabeler{Client: cl}
	ctx := context.Background()
	for _, want := range []struct{ name, label string }{{"br", OSBottlerocket}, {"al", ""}, {"own", "custom"}} {
		if _, err := l.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: want.name}}); err != nil {
			t.Fatal(err)
		}
		n := &corev1.Node{}
		_ = cl.Get(ctx, client.ObjectKey{Name: want.name}, n)
		if got := n.Labels[v1alpha1.LabelNodeOS]; got != want.label {
			t.Errorf("%s: label %q, want %q", want.name, got, want.label)
		}
	}
}

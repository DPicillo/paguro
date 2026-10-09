// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// Only the startup taint goes; every other taint stays.
func TestClearStartupTaint(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	other := corev1.Taint{Key: "dedicated", Value: "games", Effect: corev1.TaintEffectNoSchedule}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{
		other, {Key: v1.TaintAgentNotReady, Effect: corev1.TaintEffectNoSchedule}}}}
	a, cl := nodeReadingAgent(scheme, node)
	ctx := context.Background()
	for range 2 { // the second call finds nothing to do
		if err := a.ClearStartupTaint(ctx); err != nil {
			t.Fatal(err)
		}
		got := &corev1.Node{}
		_ = cl.Get(ctx, client.ObjectKey{Name: "node-a"}, got)
		if len(got.Spec.Taints) != 1 || got.Spec.Taints[0].Key != "dedicated" {
			t.Fatalf("taints %+v", got.Spec.Taints)
		}
	}
}

// nodeReadingAgent: an agent whose cached client cannot read Nodes, as in a
// cluster – the agent may not list them, so the informer never syncs and a
// Get through the cache blocks (an agent that read its Node so never
// started). Node reads must go through APIReader.
func nodeReadingAgent(scheme *runtime.Scheme, objs ...client.Object) (*Agent, client.Client) {
	direct := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	cached := interceptor.NewClient(direct, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, o ...client.GetOption) error {
			if _, ok := obj.(*corev1.Node); ok {
				return errors.New("nodes through the cache: the informer would never sync")
			}
			return c.Get(ctx, key, obj, o...)
		}})
	return &Agent{Client: cached, APIReader: direct, NodeName: "node-a", Log: slog.New(slog.DiscardHandler)}, direct
}

func TestNodeInterruptionSource(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{ProviderID: "aws:///eu-central-1a/i-0abc"}}
	a, _ := nodeReadingAgent(scheme, node)
	src, err := a.NodeInterruptionSource(context.Background())
	if err != nil || src == nil {
		t.Fatalf("source %v, err %v", src, err)
	}
}

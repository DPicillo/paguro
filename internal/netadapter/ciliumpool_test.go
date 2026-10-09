// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package netadapter

import (
	"context"
	"net/netip"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func ciliumObj(apiVersion, kind, name string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"name": name}}}
	if spec != nil {
		u.Object["spec"] = spec
	}
	return u
}

func TestCiliumRotatorAgainstAPI(t *testing.T) {
	poolGVR := schema.GroupVersionResource{Group: "cilium.io", Version: "v2alpha1", Resource: "ciliumpodippools"}
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{poolGVR: "CiliumPodIPPoolList", ciliumNodeGVR: "CiliumNodeList"},
		ciliumObj("cilium.io/v2alpha1", "CiliumPodIPPool", "paguro-10-250-0-2",
			map[string]any{"ipv4": map[string]any{"cidrs": []any{"10.250.0.2/32"}, "maskSize": int64(32)}}),
		ciliumObj("cilium.io/v2", "CiliumNode", "k8s-w-4", nil),
	)
	disc := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}}
	disc.Resources = []*metav1.APIResourceList{{GroupVersion: "cilium.io/v2alpha1",
		APIResources: []metav1.APIResource{{Name: "ciliumpodippools", Kind: "CiliumPodIPPool"}}}}

	store := &CiliumPoolStore{Dynamic: dyn, Discovery: disc}
	alloc, err := NewStickyAllocator("10.250.0.0/16", store)
	if err != nil {
		t.Fatal(err)
	}
	rot := &CiliumRotator{Allocator: alloc, Store: store}
	ctx := context.Background()
	if err := rot.RotatePool(ctx, "paguro-10-250-0-2", "paguro-10-250-0-2-abcde", netip.MustParseAddr("10.250.0.2"), "k8s-w-4"); err != nil {
		t.Fatal(err)
	}

	if ok, _ := store.Exists(ctx, "paguro-10-250-0-2"); ok {
		t.Error("old pool must be deleted")
	}
	np, err := dyn.Resource(poolGVR).Get(ctx, "paguro-10-250-0-2-abcde", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	cidrs, _, _ := unstructured.NestedStringSlice(np.Object, "spec", "ipv4", "cidrs")
	mask, _, _ := unstructured.NestedInt64(np.Object, "spec", "ipv4", "maskSize")
	if len(cidrs) != 1 || cidrs[0] != "10.250.0.2/32" || mask != 32 {
		t.Errorf("new pool spec: %v /%d", cidrs, mask)
	}
	// The nudge runs asynchronously.
	deadline := time.Now().Add(2 * time.Second)
	for {
		node, _ := dyn.Resource(ciliumNodeGVR).Get(ctx, "k8s-w-4", metav1.GetOptions{})
		if node.GetAnnotations()[AnnotationNudge] != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("target CiliumNode not nudged")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Order on the wire: delete before create.
	var verbs []string
	for _, a := range dyn.Actions() {
		if a.GetResource().Resource == "ciliumpodippools" && (a.GetVerb() == "delete" || a.GetVerb() == "create") {
			verbs = append(verbs, a.GetVerb())
		}
	}
	if len(verbs) != 2 || verbs[0] != "delete" || verbs[1] != "create" {
		t.Errorf("pool API calls %v, want [delete create]", verbs)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

func TestCPUBaseline(t *testing.T) {
	node := func(name, flags string, agent bool) *corev1.Node {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{v1.AnnotationNodeCPUFlags: flags}}}
		if agent {
			n.Annotations[v1.AnnotationNodeAgent] = "10.0.0.1:9555"
		}
		return n
	}
	c := fake.NewClientBuilder().WithObjects(
		node("broadwell", "sse2,avx2,adx,rtm,smap", true),
		node("haswell", "sse2,avx2,smep", true),
		node("no-agent", "sse2", false), // Paguro does not run there: not a target
	).Build()
	f, err := CPUBaseline(c, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := f(context.Background()); err != nil || b != "avx2,sse2" {
		t.Fatalf("auto = %q, %v", b, err)
	}
	if f, _ := CPUBaseline(c, "x86-64-v2"); f == nil {
		t.Fatal("level not accepted")
	} else if b, _ := f(context.Background()); b == "" || slices.Contains(strings.Split(b, ","), "avx2") {
		t.Fatalf("x86-64-v2 = %q", b)
	}
	if f, err := CPUBaseline(c, "off"); f != nil || err != nil {
		t.Fatal("off must disable the baseline")
	}
	if _, err := CPUBaseline(c, "x86-64-v9"); err == nil {
		t.Fatal("unknown setting accepted")
	}
}

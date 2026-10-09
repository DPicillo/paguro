// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"net/netip"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func ciliumNode(name string, pools map[string][]any) unstructured.Unstructured {
	n := unstructured.Unstructured{Object: map[string]any{}}
	n.SetName(name)
	var alloc []any
	for p, cidrs := range pools {
		alloc = append(alloc, map[string]any{"pool": p, "cidrs": cidrs})
	}
	_ = unstructured.SetNestedSlice(n.Object, alloc, "spec", "ipam", "pools", "allocated")
	return n
}

// The /32s of Paguro's pools, wherever held; marked where this node holds
// one – also when another node holds the same /32 (a move in progress).
func TestStickyCIDRs(t *testing.T) {
	got := stickyCIDRsOf([]unstructured.Unstructured{
		ciliumNode("a", map[string][]any{"default": {"10.244.0.0/26"}, "paguro-10-250-0-7-aaaaa": {"10.250.0.7/32"}}),
		ciliumNode("b", map[string][]any{"paguro-10-250-0-7-bbbbb": {"10.250.0.7/32"}, "paguro-10-250-0-9": {"10.250.0.9/32"}}),
		ciliumNode("c", map[string][]any{"paguro-bad": {"not-a-cidr", "fd00::1/128"}}),
	}, "a")
	want := map[netip.Prefix]bool{netip.MustParsePrefix("10.250.0.7/32"): true, netip.MustParsePrefix("10.250.0.9/32"): false}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, local := range want {
		if l, ok := got[p]; !ok || l != local {
			t.Errorf("%s: got %v/%v, want local=%v", p, l, ok, local)
		}
	}
}

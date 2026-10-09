// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"paguro.dev/paguro/internal/phantom"
)

// Steering rules are wanted for the live translated flows towards an old
// address, in the namespace where the record routes that address – never
// for the migrated pod's own side, identities or ended flows.
func TestSteeringWanted(t *testing.T) {
	ap := netip.MustParseAddrPort
	old, new := "192.168.93.41", "192.168.90.95"
	tu := func(src, dst string) phantom.Tuple {
		return phantom.Tuple{Proto: phantom.TCP, Src: ap(src), Dst: ap(dst)}
	}
	out := func(s phantom.Scope, match, rewrite phantom.Tuple) phantom.Rule {
		return phantom.Rule{Scope: s, Dir: phantom.Out, Match: match, Rewrite: rewrite}
	}
	hostFlow := phantom.PlanResult{Rules: []phantom.Rule{
		out(phantom.ScopeHost, tu("192.168.78.222:51000", old+":25565"), tu("192.168.78.222:51000", new+":25565")),
		{Scope: phantom.ScopeHost, Dir: phantom.In, Match: tu(new+":25565", "192.168.78.222:51000"), Rewrite: tu(old+":25565", "192.168.78.222:51000")},
	}}
	podFlow := phantom.PlanResult{
		Rules:       []phantom.Rule{out(phantom.ScopePod, tu("10.244.1.10:40000", old+":25565"), tu("10.244.1.10:40000", new+":25565"))},
		Attachments: []phantom.Attachment{{Netns: "/proc/77/ns/net", Ifname: "eth0", Kind: phantom.KindPod}},
	}
	// The target node: the migrated pod's rules (its own netns) and a peer
	// pod on the same node.
	targetFlow := phantom.PlanResult{
		Rules: []phantom.Rule{
			out(phantom.ScopePod, tu(old+":25565", "10.244.1.11:40001"), tu(new+":25565", "10.244.1.11:40001")),
			out(phantom.ScopePod, tu("10.244.1.11:40001", old+":25565"), tu("10.244.1.11:40001", new+":25565")),
		},
		Attachments: []phantom.Attachment{
			{Netns: "/run/netns/migrated", Ifname: "eth0", Kind: phantom.KindPod},
			{Netns: "/proc/88/ns/net", Ifname: "eth0", Kind: phantom.KindPod},
		},
	}
	identity := phantom.PlanResult{Rules: []phantom.Rule{
		out(phantom.ScopeHost, tu("192.168.78.222:51001", old+":25565"), tu("192.168.78.222:51001", old+":25565"))}}
	ended := phantom.PlanResult{Rules: []phantom.Rule{
		out(phantom.ScopeHost, tu("192.168.78.222:51002", old+":25565"), tu("192.168.78.222:51002", new+":25565"))}}
	unrouted := phantom.PlanResult{Rules: []phantom.Rule{
		out(phantom.ScopeHost, tu("192.168.78.222:51003", "192.168.70.1:25565"), tu("192.168.78.222:51003", new+":25565"))}}

	recs := map[types.UID]*phantomRecord{
		"peer": {PerFlow: []phantom.PlanResult{hostFlow, podFlow, identity, ended, unrouted}, Dead: []int32{3},
			Routes: []phantomRoute{{Netns: "", Addr: old}, {Netns: "/proc/77/ns/net", Addr: old}}},
		"target": {Target: true, Netns: "/run/netns/migrated", PerFlow: []phantom.PlanResult{targetFlow},
			Routes: []phantomRoute{{Netns: "/proc/88/ns/net", Addr: old}}},
	}
	got := steeringWanted(recs)
	want := map[string][]phantom.Tuple{
		"":                {tu("192.168.78.222:51000", old+":25565")},
		"/proc/77/ns/net": {tu("10.244.1.10:40000", old+":25565")},
		"/proc/88/ns/net": {tu("10.244.1.11:40001", old+":25565")},
	}
	if len(got) != len(want) {
		t.Fatalf("namespaces %v, want %v", got, want)
	}
	for ns, w := range want {
		if !slices.Equal(got[ns], w) {
			t.Errorf("%q: %v, want %v", ns, got[ns], w)
		}
	}
}

// A flow's routing tuple is read from conntrack once; a failed read is
// reported, and what it did map is used.
func TestRoutingTuplesCached(t *testing.T) {
	ap := netip.MustParseAddrPort
	a := phantom.Tuple{Proto: phantom.TCP, Src: ap("192.168.78.222:51000"), Dst: ap("192.168.93.41:25565")}
	a2 := phantom.Tuple{Proto: phantom.TCP, Src: ap("10.244.1.10:40000"), Dst: ap("192.168.93.41:25565")}
	b := phantom.Tuple{Proto: phantom.TCP, Src: ap("192.168.78.222:51001"), Dst: ap("192.168.93.41:25565")}
	var asked [][]phantom.Tuple
	var fail error
	prev := routingTuplesOf
	defer func() { routingTuplesOf = prev }()
	routingTuplesOf = func(ts []phantom.Tuple) (map[phantom.Tuple]phantom.Tuple, error) {
		asked = append(asked, slices.Clone(ts))
		out := map[phantom.Tuple]phantom.Tuple{}
		if slices.Contains(ts, a) {
			out[a] = a2
		}
		return out, fail
	}
	pm := &phantomManager{log: slog.New(slog.DiscardHandler)}
	out, complete := pm.routingTuples([]phantom.Tuple{a, b})
	if !complete || !slices.Equal(out, []phantom.Tuple{a2, b}) || len(asked) != 1 {
		t.Fatalf("first: %v complete=%v asked %v", out, complete, asked)
	}
	// a is known; b (no entry) is asked again – and the read fails.
	fail = errors.New("ENOBUFS")
	out, complete = pm.routingTuples([]phantom.Tuple{a, b})
	if complete || !slices.Equal(out, []phantom.Tuple{a2, b}) || !slices.Equal(asked[1], []phantom.Tuple{b}) {
		t.Fatalf("second: %v complete=%v asked %v", out, complete, asked)
	}
	// Ended flows leave the cache.
	fail = nil
	pm.routingTuples([]phantom.Tuple{b})
	if _, ok := pm.routeOf[a]; ok {
		t.Fatal("an ended flow stays cached")
	}
	if out, _ := pm.routingTuples([]phantom.Tuple{a}); !slices.Equal(out, []phantom.Tuple{a2}) || !slices.Equal(asked[len(asked)-1], []phantom.Tuple{a}) {
		t.Fatalf("a flow seen again is read again: %v asked %v", out, asked)
	}
}

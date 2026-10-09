// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"net/netip"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"paguro.dev/paguro/internal/phantom"
)

// The route watcher covers devices that appear after a record was
// programmed – for the addresses of live host-scope rules only.
func TestHostScopeNeeds(t *testing.T) {
	ap := netip.MustParseAddrPort
	host := func(old, new string) phantom.PlanResult {
		return phantom.PlanResult{
			Rules: []phantom.Rule{
				{Scope: phantom.ScopeHost, Dir: phantom.Out,
					Match:   phantom.Tuple{Proto: phantom.TCP, Src: ap("192.168.83.93:40001"), Dst: ap(old)},
					Rewrite: phantom.Tuple{Proto: phantom.TCP, Src: ap("192.168.83.93:40001"), Dst: ap(new)}},
				{Scope: phantom.ScopeHost, Dir: phantom.In,
					Match:   phantom.Tuple{Proto: phantom.TCP, Src: ap(new), Dst: ap("192.168.83.93:40001")},
					Rewrite: phantom.Tuple{Proto: phantom.TCP, Src: ap(old), Dst: ap("192.168.83.93:40001")}},
			},
			Attachments: []phantom.Attachment{{Ifname: "enp39s0", Kind: phantom.KindHostDevice}},
		}
	}
	pod := phantom.PlanResult{
		Rules: []phantom.Rule{{Scope: phantom.ScopePod, Dir: phantom.Out,
			Match:   phantom.Tuple{Proto: phantom.TCP, Src: ap("192.168.72.98:40002"), Dst: ap("192.168.10.1:25565")},
			Rewrite: phantom.Tuple{Proto: phantom.TCP, Src: ap("192.168.72.98:40002"), Dst: ap("192.168.10.2:25565")}}},
		Attachments: []phantom.Attachment{{Netns: "/proc/1/ns/net", Ifname: "eth0", Kind: phantom.KindPod}},
	}

	dests, have := hostScopeNeeds(map[types.UID]*phantomRecord{"pods-only": {PerFlow: []phantom.PlanResult{pod}}})
	if len(dests) != 0 || len(have) != 0 {
		t.Errorf("pod-scope rules only: addresses %v, devices %v", dests, have)
	}

	recs := map[types.UID]*phantomRecord{
		"hop": {PerFlow: []phantom.PlanResult{
			host("192.168.93.205:25565", "192.168.81.207:25565"),
			host("192.168.94.250:25565", "192.168.83.182:25565"), // ended
			pod,
		}, Dead: []int32{1}},
	}
	dests, have = hostScopeNeeds(recs)
	want := []netip.Addr{netip.MustParseAddr("192.168.93.205"), netip.MustParseAddr("192.168.81.207")}
	if !slices.Equal(dests, want) {
		t.Errorf("addresses %v, want %v", dests, want)
	}
	if len(have) != 1 || !have["enp39s0"] {
		t.Errorf("devices already covered %v", have)
	}
}

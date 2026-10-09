// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"net/netip"
	"strings"
	"testing"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

func TestRouteGuardRules(t *testing.T) {
	rs := guardRuleset()
	for _, want := range []string{
		"flush chain inet paguro_route_guard transit", // idempotent: never a second copy of the rule
		`ip daddr @v4 iifname != "cali*" oifname != "cali*" counter drop`,
		"flags timeout",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, rs)
		}
	}
	if got := guardElement("add", netip.MustParseAddr("10.245.118.195")); got != "add element inet paguro_route_guard v4 { 10.245.118.195 timeout 120s }\n" {
		t.Errorf("add: %q", got)
	}
	if got := guardElement("delete", netip.MustParseAddr("fd00::5")); got != "delete element inet paguro_route_guard v6 { fd00::5 }\n" {
		t.Errorf("delete: %q", got)
	}
	m := &v1.Migration{Status: v1.MigrationStatus{IPPreserved: true, NetworkAdapter: netadapter.NameCalico}}
	if !needsRouteGuard(m) {
		t.Error("Calico with a kept IP needs the guard")
	}
	m.Status.NetworkAdapter = netadapter.NameCilium
	if needsRouteGuard(m) {
		t.Error("Cilium does not")
	}
}

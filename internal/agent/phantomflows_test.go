// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"net/netip"
	"reflect"
	"testing"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/phantom"
)

func TestFlowsRoundTrip(t *testing.T) {
	ap := netip.MustParseAddrPort
	flows := []phantom.Flow{
		{Proto: phantom.TCP, Local: ap("10.0.0.5:7000"), Remote: ap("10.0.1.9:41000"), Class: phantom.ClassInCluster, Server: true},
		{Proto: phantom.TCP, Local: ap("10.0.0.5:39000"), Remote: ap("10.96.0.10:80"), Wire: ap("10.0.2.3:8080"), Class: phantom.ClassInCluster},
		{Proto: phantom.UDP, Local: ap("10.0.0.5:5353"), Remote: ap("1.1.1.1:53"), Class: phantom.ClassExternalSNAT},
		{Proto: phantom.TCP, Local: ap("[fd00::5]:443"), Remote: ap("[fd00::9]:50000"), Class: phantom.ClassExternalDirect, Server: true},
	}
	api := flowsToAPI(flows)
	if api[1].Wire != "10.0.2.3:8080" || api[0].Wire != "" || api[2].Class != "external-snat" || api[3].Local != "[fd00::5]:443" {
		t.Fatalf("unexpected API form: %+v", api)
	}
	back, err := flowsFromAPI(api)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, flows) {
		t.Fatalf("round trip changed the flows:\n got %+v\nwant %+v", back, flows)
	}
}

func TestFlowsFromAPIRejectsGarbage(t *testing.T) {
	for _, f := range []v1.PhantomFlow{
		{Proto: "sctp", Local: "10.0.0.1:1", Remote: "10.0.0.2:2", Class: "in-cluster"},
		{Proto: "tcp", Local: "10.0.0.1", Remote: "10.0.0.2:2", Class: "in-cluster"},
		{Proto: "tcp", Local: "10.0.0.1:1", Remote: "10.0.0.2:2", Class: "somewhere"},
	} {
		if _, err := flowsFromAPI([]v1.PhantomFlow{f}); err == nil {
			t.Errorf("accepted %+v", f)
		}
	}
}

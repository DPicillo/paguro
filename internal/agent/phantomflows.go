// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"fmt"
	"net/netip"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/phantom"
)

// Conversion between the datapath's flow type and its API form
// (status.source.phantom.flows). The API uses strings so that `kubectl get -o
// yaml` stays readable.

var flowClassNames = map[phantom.FlowClass]string{
	phantom.ClassInCluster:      "in-cluster",
	phantom.ClassExternalDirect: "external-direct",
	phantom.ClassExternalSNAT:   "external-snat",
}

func flowsToAPI(flows []phantom.Flow) []v1.PhantomFlow {
	out := make([]v1.PhantomFlow, 0, len(flows))
	for _, f := range flows {
		a := v1.PhantomFlow{
			Proto:  f.Proto.String(),
			Local:  f.Local.String(),
			Remote: f.Remote.String(),
			Class:  flowClassNames[f.Class],
			Server: f.Server,
		}
		if f.Wire.IsValid() && f.Wire != f.Remote {
			a.Wire = f.Wire.String()
		}
		out = append(out, a)
	}
	return out
}

func flowsFromAPI(in []v1.PhantomFlow) ([]phantom.Flow, error) {
	out := make([]phantom.Flow, 0, len(in))
	for i, a := range in {
		f := phantom.Flow{Server: a.Server}
		switch a.Proto {
		case "tcp":
			f.Proto = phantom.TCP
		case "udp":
			f.Proto = phantom.UDP
		default:
			return nil, fmt.Errorf("flow %d: unknown protocol %q", i, a.Proto)
		}
		var err error
		if f.Local, err = netip.ParseAddrPort(a.Local); err != nil {
			return nil, fmt.Errorf("flow %d: local: %w", i, err)
		}
		if f.Remote, err = netip.ParseAddrPort(a.Remote); err != nil {
			return nil, fmt.Errorf("flow %d: remote: %w", i, err)
		}
		if a.Wire != "" {
			if f.Wire, err = netip.ParseAddrPort(a.Wire); err != nil {
				return nil, fmt.Errorf("flow %d: wire: %w", i, err)
			}
		}
		found := false
		for c, name := range flowClassNames {
			if name == a.Class {
				f.Class, found = c, true
			}
		}
		if !found {
			return nil, fmt.Errorf("flow %d: unknown class %q", i, a.Class)
		}
		out = append(out, f)
	}
	return out, nil
}

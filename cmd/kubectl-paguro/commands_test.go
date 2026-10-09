// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"testing"
	"time"

	"paguro.dev/paguro/api/v1alpha1"
)

// --network reads like the pod annotation (any case) and refuses an
// unknown value with the webhook's message.
func TestMigrateFlagsNetwork(t *testing.T) {
	flags := func(network string) *migrateFlags {
		return &migrateFlags{strategy: "PreCopy", network: network, cpuPolicy: "Strict",
			freezeBudget: 500 * time.Millisecond, timeout: time.Minute}
	}
	for in, want := range map[string]v1alpha1.NetworkMode{
		"Auto": v1alpha1.NetworkAuto, "preserve": v1alpha1.NetworkPreserve,
		"Phantom": v1alpha1.NetworkPhantom, "PHANTOM": v1alpha1.NetworkPhantom, "generic": v1alpha1.NetworkGeneric,
	} {
		spec, err := flags(in).spec("web-0")
		if err != nil || spec.Network != want {
			t.Errorf("--network %s: %q %v, want %q", in, spec.Network, err, want)
		}
	}
	_, err := flags("keep").spec("web-0")
	if want := `--network: unknown network mode "keep" (want auto, preserve, phantom or generic)`; err == nil || err.Error() != want {
		t.Errorf("--network keep: %v, want %q", err, want)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package v1alpha1

import (
	"strings"
	"testing"
)

// An unknown network mode must be an error, never Auto: Auto gives a pod
// under Cilium a sticky IP, which rules out the Phantom mode it asked for.
func TestParseNetworkMode(t *testing.T) {
	for _, c := range []struct {
		in      string
		want    NetworkMode
		wantErr string
	}{
		{"", NetworkAuto, ""},
		{"auto", NetworkAuto, ""},
		{"Auto", NetworkAuto, ""},
		{"preserve", NetworkPreserve, ""},
		{"Preserve", NetworkPreserve, ""},
		{"phantom", NetworkPhantom, ""},
		{"PHANTOM", NetworkPhantom, ""},
		{"Phantom", NetworkPhantom, ""},
		{"generic", NetworkGeneric, ""},
		{"Generic", NetworkGeneric, ""},
		{"phantom ", "", `unknown network mode "phantom "`},
		{"keep", "", `unknown network mode "keep" (want auto, preserve, phantom or generic)`},
	} {
		got, err := ParseNetworkMode(c.in)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%q: error %v, want %q", c.in, err, c.wantErr)
			}
			if got != "" {
				t.Errorf("%q: mode %q next to an error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: %q %v, want %q", c.in, got, err, c.want)
		}
	}
}

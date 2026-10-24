// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"slices"
	"testing"

	"paguro.dev/paguro/pkg/names"
)

// The bundle's tools come after the host's own, once.
func TestWithBundlePath(t *testing.T) {
	got := withBundlePath([]string{"HOME=/root", "PATH=/usr/sbin:/usr/bin"})
	if !slices.Contains(got, "PATH=/usr/sbin:/usr/bin:"+names.BundleBin) || !slices.Contains(got, "HOME=/root") {
		t.Fatalf("env %v", got)
	}
	if again := withBundlePath(got); !slices.Equal(again, got) {
		t.Fatalf("appended twice: %v", again)
	}
	if none := withBundlePath(nil); len(none) != 1 || none[0] != "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"+names.BundleBin {
		t.Fatalf("without PATH: %v", none)
	}
}

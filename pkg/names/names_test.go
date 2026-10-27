// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 David Picillo

package names

import "testing"

func TestReplacementName(t *testing.T) {
	got := ReplacementName("echo-9676564c4-", "73a7185a-2eb3-4139-9959-8c8c26030f0b")
	if got != "echo-9676564c4-p73a71" {
		t.Fatalf("got %q", got)
	}
	long := ReplacementName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-", "abcdef")
	if len(long) != 63 {
		t.Fatalf("len=%d", len(long))
	}
}

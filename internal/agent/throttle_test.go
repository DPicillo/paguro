// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestThrottleRecord(t *testing.T) {
	dir := t.TempDir()
	rec := filepath.Join(dir, throttleFile("app"))
	th := &Throttle{file: "/sys/fs/cgroup/kubepods.slice/x/cpu.max", original: "max 100000"}
	if err := th.Persist(rec); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(rec)
	if err != nil || string(b) != "/sys/fs/cgroup/kubepods.slice/x/cpu.max\nmax 100000\n" {
		t.Fatalf("record %q, %v", b, err)
	}
	h := &Host{}
	if err := h.RestoreThrottle(context.Background(), filepath.Join(dir, "none")); err != nil {
		t.Fatalf("no record must be no error: %v", err)
	}
	// A record that does not point into the cgroup tree is refused.
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("/etc/passwd\nroot\n"), 0o600)
	if err := h.RestoreThrottle(context.Background(), bad); err == nil {
		t.Fatal("record outside /sys/fs/cgroup accepted")
	}
}

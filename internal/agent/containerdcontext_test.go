// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 David Picillo

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainerdContext(t *testing.T) {
	proc := t.TempDir()
	add := func(pid, comm, cgroup, attr string) {
		d := filepath.Join(proc, pid)
		if err := os.MkdirAll(filepath.Join(d, "attr"), 0o755); err != nil {
			t.Fatal(err)
		}
		for f, v := range map[string]string{"comm": comm + "\n", "cgroup": cgroup + "\n", "attr/current": attr + "\x00"} {
			if err := os.WriteFile(filepath.Join(d, f), []byte(v), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Bottlerocket: host-containerd first, kubelet's containerd second.
	add("1200", "containerd", "0::/system.slice/host-containerd.service", "system_u:system_r:runtime_t:s0")
	add("1300", "containerd-shim", "0::/runtime.slice/containerd.service", "system_u:system_r:runtime_t:s0:c0.c1023")
	if _, err := ContainerdContext(proc); err == nil {
		t.Fatal("found a containerd outside containerd.service")
	}
	add("1400", "containerd", "0::/runtime.slice/containerd.service", "system_u:system_r:runtime_t:s0:c0.c1023")
	got, err := ContainerdContext(proc)
	if err != nil || got != "system_u:system_r:runtime_t:s0:c0.c1023" {
		t.Fatalf("got %q, %v", got, err)
	}
}

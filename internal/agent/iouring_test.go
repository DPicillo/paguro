// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIoUringHolders(t *testing.T) {
	root := t.TempDir()
	proc := func(pid, comm string, links ...string) {
		fd := filepath.Join(root, pid, "fd")
		if err := os.MkdirAll(fd, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(root, pid, "comm"), []byte(comm+"\n"), 0o644)
		for i, l := range links {
			if err := os.Symlink(l, filepath.Join(fd, string(rune('0'+i)))); err != nil {
				t.Fatal(err)
			}
		}
	}
	proc("10", "node", "/dev/null", "socket:[1234]", "anon_inode:[io_uring]", "anon_inode:[eventpoll]")
	proc("11", "sh", "/dev/null", "pipe:[99]")
	got := ioUringHolders(root, []int{10, 11, 12})
	if len(got) != 1 || got[0] != "10 (node)" {
		t.Fatalf("ioUringHolders = %q", got)
	}
}

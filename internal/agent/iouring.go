// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ioUringHolders returns "pid (comm)" for every process of pids that holds
// an io_uring instance. CRIU cannot checkpoint io_uring; without this check
// the final dump fails – inside the freeze. procRoot is /proc (tests: a
// fake tree). Threads share their process's descriptor table, so the
// processes are enough.
func ioUringHolders(procRoot string, pids []int) []string {
	var out []string
	for _, p := range pids {
		dir := filepath.Join(procRoot, fmt.Sprint(p), "fd")
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue // gone, or not ours to read
		}
		for _, fd := range fds {
			if t, err := os.Readlink(filepath.Join(dir, fd.Name())); err == nil && t == "anon_inode:[io_uring]" {
				comm, _ := os.ReadFile(filepath.Join(procRoot, fmt.Sprint(p), "comm"))
				out = append(out, fmt.Sprintf("%d (%s)", p, strings.TrimSpace(string(comm))))
				break
			}
		}
	}
	return out
}

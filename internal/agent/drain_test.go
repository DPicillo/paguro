// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// /proc/net/tcp as the kernel prints it: a listener with two connections in
// its accept queue, one handshake in progress, one established connection.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1B58 00000000:0000 0A 00000000:00000002 00:00000000 00000000     0        0 4711 1 0000000000000000 100 0 0 10 0
   1: 0700FA0A:1B58 0A00F40A:A1B2 03 00000000:00000000 01:00000064 00000000     0        0 0 1 0000000000000000
   2: 0700FA0A:1B58 0A00F40A:A1B3 01 00000000:00000000 00:00000000 00000000     0        0 4712 1 0000000000000000 20 4 30 10 -1
`

func TestPendingConnections(t *testing.T) {
	if got := countPending(procNetTCP); got != 3 {
		t.Fatalf("pending = %d, want 3 (2 in the accept queue, 1 handshake)", got)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "42", "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(procNetTCP), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := pendingConnections(root, 42); err != nil || n != 3 {
		t.Fatalf("pendingConnections = %d, %v (no tcp6 is fine)", n, err)
	}
	if n := countPending(""); n != 0 {
		t.Fatal(n)
	}
}

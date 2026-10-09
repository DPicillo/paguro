// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAwaitNetnsMount(t *testing.T) {
	ctx := context.Background()
	if err := awaitNetnsMount(ctx, "/proc/self/ns/net", time.Second); err != nil {
		t.Fatalf("a namespace: %v", err)
	}
	dir := t.TempDir()
	if err := awaitNetnsMount(ctx, filepath.Join(dir, "gone"), time.Second); !os.IsNotExist(err) {
		t.Fatalf("missing entry: err = %v, want not-exist", err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := awaitNetnsMount(ctx, plain, 20*time.Millisecond); err == nil {
		t.Fatal("a plain file passed as a namespace")
	}

	// containerd's order: the entry exists as a plain file first, the
	// namespace is mounted onto it a moment later.
	entry := filepath.Join(dir, "cni-1")
	if err := os.Symlink(plain, entry); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		tmp := entry + ".new"
		_ = os.Symlink("/proc/self/ns/net", tmp)
		_ = os.Rename(tmp, entry)
	}()
	start := time.Now()
	if err := awaitNetnsMount(ctx, entry, time.Second); err != nil {
		t.Fatalf("mounted later: %v", err)
	}
	if d := time.Since(start); d < 25*time.Millisecond {
		t.Fatalf("returned after %s, before the namespace appeared", d)
	}
}

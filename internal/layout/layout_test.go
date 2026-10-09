// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package layout

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Names from the network become paths on the node, addresses go onto the
// pod's loopback: nothing else gets through.
func TestMetaValidate(t *testing.T) {
	ok := Meta{Containers: []ContainerMeta{{Name: "game"}}, EmptyDirs: []string{"cache"},
		SourceIP: "10.0.0.1", BoundIPs: []string{"10.0.0.1", "fd00::1"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]Meta{
		"container ..":    {Containers: []ContainerMeta{{Name: "../../etc"}}},
		"container slash": {Containers: []ContainerMeta{{Name: "a/b"}}},
		"emptyDir":        {EmptyDirs: []string{".."}},
		"bound IP":        {BoundIPs: []string{"10.0.0.1/8"}},
		"source IP":       {SourceIP: "dev lo"},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLatestWrite(t *testing.T) {
	dir := t.TempDir()
	if !LatestWrite(filepath.Join(dir, "missing")).IsZero() {
		t.Fatal("missing directory must give the zero time")
	}
	sub := filepath.Join(dir, "final")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	f := filepath.Join(sub, "pages-1.img")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(f, old, old)
	_ = os.Chtimes(sub, old, old)
	_ = os.Chtimes(dir, old, old)
	if got := LatestWrite(dir); !got.Equal(old) {
		t.Fatalf("LatestWrite = %v, want %v", got, old)
	}
}

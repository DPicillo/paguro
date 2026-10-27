// SPDX-License-Identifier: Apache-2.0
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

func TestValidUIDAndCreateRoot(t *testing.T) {
	StateDir = t.TempDir()
	for uid, ok := range map[string]bool{
		"0d4c7f6e-6a7b-4c3d-9e8f-1a2b3c4d5e6f": true,
		"..":                                   false,
		"../0d4c7f6e-6a7b-4c3d-9e8f-1a2b3c4d5e6f": false,
		"0d4c7f6e-6a7b-4c3d-9e8f-1a2b3c4d5e6f/x":  false,
		"mig-1":                                   false,
		"":                                        false,
	} {
		if ValidUID(uid) != ok {
			t.Errorf("ValidUID(%q) = %v", uid, !ok)
		}
	}
	if err := CreateRoot("../x", "shop"); err == nil {
		t.Fatal("CreateRoot accepted a path")
	}
	uid := "0d4c7f6e-6a7b-4c3d-9e8f-1a2b3c4d5e6f"
	if err := CreateRoot(uid, "shop"); err != nil {
		t.Fatal(err)
	}
	if got := Namespace(uid); got != "shop" {
		t.Fatalf("namespace %q", got)
	}
	if _, err := os.Stat(filepath.Join(Root(uid), "NAMESPACE.tmp")); !os.IsNotExist(err) {
		t.Fatal("temporary file left")
	}
}

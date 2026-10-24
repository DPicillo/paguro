// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package selinuxlabel

import (
	"os"
	"path/filepath"
	"testing"
)

// Where the runtime labels nothing, nothing is labelled or created.
func TestPrepareWorkDirWithoutLabel(t *testing.T) {
	dir := t.TempDir()
	if err := PrepareWorkDir(dir, "", "dump.log"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dump.log")); !os.IsNotExist(err) {
		t.Fatalf("dump.log created without a label: %v", err)
	}
	if err := Set(dir, ""); err != nil {
		t.Fatal(err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criuimg

import (
	"path/filepath"
	"testing"
)

// A file deleted while open on NFS (silly-renamed) and its link remap:
// files.img names both, remap-fpath.img links them; ghost remaps are not
// listed.
func TestLinkedRemaps(t *testing.T) {
	dir := t.TempDir()
	if got, err := LinkedRemaps(dir); err != nil || got != nil {
		t.Fatalf("no remap image: %v %v", got, err)
	}
	reg := func(id uint64, name string) []byte {
		return msg(1, uint64(1), 2, id, 3, msg(1, id, 2, uint64(0), 3, uint64(0), 6, []byte(name)))
	}
	writeImg(t, filepath.Join(dir, "files.img"), filesMagic,
		reg(5, "/data/.cache/JNA/temp/.nfs000000000010019400000001"),
		reg(9, "/data/.cache/JNA/temp/link_remap.9"),
		reg(11, "/tmp/deleted.log"),
		msg(1, uint64(2), 2, uint64(12))) // a pipe: no reg entry
	writeImg(t, filepath.Join(dir, "remap-fpath.img"), remapFpathMagic,
		msg(1, uint64(5), 2, uint64(9)),                 // linked (default type)
		msg(1, uint64(11), 2, uint64(13), 3, uint64(1))) // ghost
	got, err := LinkedRemaps(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := LinkedRemap{Orig: "/data/.cache/JNA/temp/.nfs000000000010019400000001", Remap: "/data/.cache/JNA/temp/link_remap.9"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %+v, want [%+v]", got, want)
	}
}

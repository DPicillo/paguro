// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	write(t, filepath.Join(src, "a/b/c.txt"), "hello")
	write(t, filepath.Join(src, "top"), "x")
	os.Symlink("a/b/c.txt", filepath.Join(src, "link"))
	os.Link(filepath.Join(src, "top"), filepath.Join(src, "hard"))

	var buf bytes.Buffer
	st, err := Pack(&buf, src, PackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 2 { // top + c.txt; hard is a hard link
		t.Fatalf("files=%d", st.Files)
	}
	if _, err := Unpack(&buf, dst, UnpackOptions{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dst, "link"))
	if string(b) != "hello" {
		t.Fatalf("symlink: %q", b)
	}
	fi, _ := os.Stat(filepath.Join(dst, "a/b/c.txt"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	a, _ := os.Stat(filepath.Join(dst, "top"))
	h, _ := os.Stat(filepath.Join(dst, "hard"))
	if !os.SameFile(a, h) {
		t.Fatal("hard link not preserved")
	}
}

// TestOverlayWhiteouts checks that the delta deletes a file and empties a
// directory.
func TestOverlayWhiteouts(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "etc/old.conf"), "gone")
	write(t, filepath.Join(root, "var/cache/x"), "gone")
	write(t, filepath.Join(root, "var/cache/y"), "gone")

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "etc/.wh.old.conf", Typeflag: tar.TypeReg, Mode: 0o600})
	tw.WriteHeader(&tar.Header{Name: "var/cache/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "var/cache/.wh..wh..opq", Typeflag: tar.TypeReg, Mode: 0o600})
	tw.WriteHeader(&tar.Header{Name: "var/cache/new", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	tw.Write([]byte("new"))
	tw.Close()

	st, err := Unpack(&buf, root, UnpackOptions{Overlay: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Whiteouts != 2 {
		t.Fatalf("whiteouts=%d", st.Whiteouts)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/old.conf")); !os.IsNotExist(err) {
		t.Fatal("whiteout not applied")
	}
	entries, _ := os.ReadDir(filepath.Join(root, "var/cache"))
	if len(entries) != 1 || entries[0].Name() != "new" {
		t.Fatalf("opaque: %v", entries)
	}
}

// TestNoEscapeViaSymlink checks that a malicious symlink in the target cannot
// lead out of the root.
func TestNoEscapeViaSymlink(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	os.Symlink(outside, filepath.Join(root, "evil"))
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "evil/pwned", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	tw.Write([]byte("x"))
	tw.WriteHeader(&tar.Header{Name: "../../escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	if _, err := Unpack(&buf, root, UnpackOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("file created outside the root")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape")); err == nil {
		t.Fatal("escaped via ..")
	}
}

// A whiteout never removes its parent or anything above the root: ".wh.."
// at the top would have deleted the bundle directory on the host.
func TestWhiteoutCannotEscape(t *testing.T) {
	for _, name := range []string{".wh..", "sub/.wh..", ".wh..wh.", ".wh."} {
		bundle := t.TempDir()
		root := filepath.Join(bundle, "rootfs")
		write(t, filepath.Join(root, "sub/keep"), "x")
		write(t, filepath.Join(bundle, "config.json"), "{}")
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600})
		_ = tw.Close()
		if _, err := Unpack(&buf, root, UnpackOptions{Overlay: true}); err == nil && name != ".wh..wh." {
			t.Errorf("%s: accepted", name)
		}
		for _, p := range []string{filepath.Join(bundle, "config.json"), filepath.Join(root, "sub/keep")} {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("%s: %s removed", name, p)
			}
		}
	}
}

// A regular file the container named ".wh.x" is left out instead of
// becoming a whiteout of x on the target.
func TestPackSkipsFilesNamedLikeWhiteouts(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	write(t, filepath.Join(src, ".wh.x"), "data")
	write(t, filepath.Join(dst, "x"), "keep")
	var buf bytes.Buffer
	st, err := Pack(&buf, src, PackOptions{Overlay: true})
	if err != nil || st.Skipped != 1 {
		t.Fatalf("pack: %+v %v", st, err)
	}
	if _, err := Unpack(&buf, dst, UnpackOptions{Overlay: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "x")); err != nil {
		t.Fatal("x was whited out")
	}
}

// A base recorded while the tree is in use and a delta at the end bring the
// target to exactly the final tree: changed and new files, deleted files
// and directories; an unchanged file travels only when Always asks for it.
func TestBaseAndDelta(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	write(t, filepath.Join(src, "static/big.bin"), strings.Repeat("x", 1<<16))
	write(t, filepath.Join(src, "world/level.dat"), "v1")
	write(t, filepath.Join(src, "world/region/r.0.0"), "region")
	write(t, filepath.Join(src, "gone/a"), "a")
	write(t, filepath.Join(src, "gone/sub/b"), "b")
	write(t, filepath.Join(src, "mapped.db"), "same size")
	// Settled files: written a while ago.
	past := time.Now().Add(-time.Hour)
	_ = filepath.WalkDir(src, func(p string, _ fs.DirEntry, _ error) error { return os.Chtimes(p, past, past) })
	base := Manifest{}
	var buf bytes.Buffer
	if _, err := Pack(&buf, src, PackOptions{Record: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(&buf, dst, UnpackOptions{}); err != nil {
		t.Fatal(err)
	}

	// The application goes on.
	write(t, filepath.Join(src, "world/level.dat"), "v2 longer")
	write(t, filepath.Join(src, "world/new.dat"), "new")
	os.RemoveAll(filepath.Join(src, "gone"))
	os.Remove(filepath.Join(src, "world/region/r.0.0"))
	buf.Reset()
	st, err := Pack(&buf, src, PackOptions{Since: base, Always: func(n string) bool { return n == "mapped.db" }})
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 3 || st.Whiteouts != 2 {
		t.Fatalf("delta: %d files, %d whiteouts; want 3 (level.dat, new.dat, mapped.db) and 2 (gone, r.0.0)", st.Files, st.Whiteouts)
	}
	if st.Bytes > 100 {
		t.Fatalf("delta carries %d bytes: the unchanged big file went again", st.Bytes)
	}
	if _, err := Unpack(&buf, dst, UnpackOptions{Overlay: true}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"static/big.bin", "world/level.dat", "world/new.dat", "mapped.db"} {
		want, _ := os.ReadFile(filepath.Join(src, f))
		if got, err := os.ReadFile(filepath.Join(dst, f)); err != nil || string(got) != string(want) {
			t.Errorf("%s differs: %v", f, err)
		}
	}
	for _, f := range []string{"gone", "world/region/r.0.0"} {
		if _, err := os.Stat(filepath.Join(dst, f)); err == nil {
			t.Errorf("%s survived its deletion", f)
		}
	}
}

// A file written within the last second when the base is recorded is sent
// again: a second write in the same timestamp tick would go unnoticed.
func TestRecentlyWrittenIsSentAgain(t *testing.T) {
	src := t.TempDir()
	write(t, filepath.Join(src, "hot"), "v1")
	base := Manifest{}
	if _, err := Pack(io.Discard, src, PackOptions{Record: base}); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(src, "hot"), "v2") // same size, maybe the same mtime
	var buf bytes.Buffer
	if st, err := Pack(&buf, src, PackOptions{Since: base}); err != nil || st.Files != 1 {
		t.Fatalf("delta: %+v %v – the second write is missing", st, err)
	}
}

// Setuid, setgid and sticky bits survive: /tmp is 1777 again after a
// restore (it was 0777, and Ruby refuses such a temporary directory).
func TestSpecialModeBits(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for _, d := range []struct {
		name string
		mode os.FileMode
	}{{"tmp", 0o777 | os.ModeSticky}, {"shared", 0o775 | os.ModeSetgid}} {
		if err := os.Mkdir(filepath.Join(src, d.name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(src, d.name), d.mode); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(src, "bin/tool"), "#!/bin/sh")
	if err := os.Chmod(filepath.Join(src, "bin/tool"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Pack(&buf, src, PackOptions{}); err != nil {
		t.Fatal(err)
	}
	// A directory that exists on the target already (as /tmp in a fresh
	// root) gets the mode too.
	if err := os.Mkdir(filepath.Join(dst, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(&buf, dst, UnpackOptions{}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{
		"tmp":      os.ModeDir | os.ModeSticky | 0o777,
		"shared":   os.ModeDir | os.ModeSetgid | 0o775,
		"bin/tool": os.ModeSetuid | 0o755,
	} {
		fi, err := os.Lstat(filepath.Join(dst, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != want {
			t.Errorf("%s: mode %v, want %v", name, fi.Mode(), want)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeProc builds /proc/<pid>/{fd,fdinfo,mountinfo} for one process.
func fakeProc(t *testing.T, root string, pid int, mountinfo string, fds map[string][2]string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	for _, d := range []string{"fd", "fdinfo"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	for fd, v := range fds { // v: target path, fdinfo content
		if err := os.Symlink(v[0], filepath.Join(dir, "fd", fd)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "fdinfo", fd), []byte(v[1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSharedFSLocks(t *testing.T) {
	root := t.TempDir()
	mountinfo := `1500 1400 0:61 /pvc-30 /data rw,relatime - nfs4 10.104.92.226:/pvc-30 rw,vers=4.1
1501 1400 252:16 / /local rw,relatime - ext4 /dev/vdb rw
`
	fakeProc(t, root, 42, mountinfo, map[string][2]string{
		// locked file on NFS: reported
		"3": {"/data/lock", "pos:\t0\nflags:\t02102\nmnt_id:\t1500\nino:\t524291\nlock:\t1: POSIX  ADVISORY  WRITE 42 00:3d:524291 0 EOF\n"},
		// open on NFS without a lock: ignored
		"4": {"/data/log", "pos:\t118\nflags:\t02102001\nmnt_id:\t1500\nino:\t524292\n"},
		// locked file on a local filesystem: the target's kernel has its own lock table
		"5": {"/local/db.lock", "pos:\t0\nflags:\t02\nmnt_id:\t1501\nino:\t12\nlock:\t2: FLOCK  ADVISORY  WRITE 42 fc:10:12 0 EOF\n"},
	})
	got := sharedFSLocks(root, []int{42, 4711 /* gone */})
	if len(got) != 1 {
		t.Fatalf("locks %+v, want exactly the NFS one", got)
	}
	if l := got[0]; l.PID != 42 || l.Path != "/data/lock" || l.FSType != "nfs4" {
		t.Errorf("lock %+v", l)
	}
}

func TestSharedFSLocksNone(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 7, "1500 1400 0:61 / /data rw - nfs4 srv:/ rw\n", map[string][2]string{
		"3": {"/data/log", "pos:\t0\nflags:\t02\nmnt_id:\t1500\n"},
	})
	if got := sharedFSLocks(root, []int{7}); len(got) != 0 {
		t.Fatalf("no locks expected, got %+v", got)
	}
}

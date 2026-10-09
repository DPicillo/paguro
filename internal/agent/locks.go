// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// File locks on shared filesystems (RWX volumes: NFS, CephFS, SMB …).
//
// CRIU dumps a process's locks and takes them again in the restored process
// (--file-locks). On a local filesystem that is trivial: the target node's
// kernel has its own lock table. On a shared filesystem the lock lives on
// the server, and the frozen source process still holds it until it exits –
// the restore asked for a lock its own predecessor held. CRIU waits for it
// (F_SETLKW); the NFS client then waits up to 30 s for the server's
// notification before it asks again (measured: every restore of a lock
// holder took 30.2–30.5 s). Meanwhile, once kubelet had killed the source,
// any process on another node could take the lock (measured: a contender
// polling every 50 ms held it for the whole 30 s).
//
// So the source ends its processes itself – after the commit, once its pod
// is terminating (kubelet must not restart them) and the target sandbox is
// up – and only then sends READY: the restore takes the free lock at once,
// and the time without an owner shrinks to the hand-over itself.

// heldLock is one lock a process holds, as /proc/<pid>/fdinfo shows it.
type heldLock struct {
	PID    int
	Path   string
	FSType string
	Lock   string // the fdinfo "lock:" line
}

// sharedFSLocks lists the locks that pids hold on shared filesystems
// (SharedFS). procRoot is /proc (a directory tree in tests).
func sharedFSLocks(procRoot string, pids []int) []heldLock {
	var out []heldLock
	for _, pid := range pids {
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		fds, err := os.ReadDir(filepath.Join(dir, "fdinfo"))
		if err != nil {
			continue // gone
		}
		var mounts map[int]string // mount ID → fs type, read on first need
		for _, fd := range fds {
			mnt, locks := parseFdinfo(filepath.Join(dir, "fdinfo", fd.Name()))
			if len(locks) == 0 {
				continue
			}
			if mounts == nil {
				mounts = mountTypesByID(filepath.Join(dir, "mountinfo"))
			}
			fstype := mounts[mnt]
			if !SharedFS(fstype) {
				continue
			}
			path, _ := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			for _, l := range locks {
				out = append(out, heldLock{PID: pid, Path: path, FSType: fstype, Lock: l})
			}
		}
	}
	return out
}

// parseFdinfo returns the mount ID of an open file and its "lock:" lines
// (fs/proc/fd.c: the locks this file or its owner holds on the inode).
func parseFdinfo(path string) (mntID int, locks []string) {
	f, err := os.Open(path)
	if err != nil {
		return -1, nil
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if v, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			mntID, _ = strconv.Atoi(strings.TrimSpace(v))
		} else if v, ok := strings.CutPrefix(line, "lock:"); ok {
			locks = append(locks, strings.TrimSpace(v))
		}
	}
	return mntID, locks
}

// mountTypesByID maps mount IDs to filesystem types from a mountinfo file.
func mountTypesByID(path string) map[int]string {
	out := map[int]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		pre, post, ok := strings.Cut(s.Text(), " - ")
		if !ok {
			continue
		}
		f, pf := strings.Fields(pre), strings.Fields(post)
		if len(f) < 1 || len(pf) < 1 {
			continue
		}
		if id, err := strconv.Atoi(f[0]); err == nil {
			out[id] = pf[0]
		}
	}
	return out
}

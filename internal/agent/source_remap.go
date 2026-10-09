// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/criuimg"
)

// Files deleted while open on a shared filesystem.
//
// NFS keeps a file that is deleted while a client has it open under a
// "silly rename" (.nfsXXXX) until the client closes it. CRIU cannot copy
// such a file into the images like a deleted local file; it refuses the dump
// unless it may link the file under a stable name ("link-remap": CRIU
// creates link_remap.<id> next to it and the restore opens and removes
// it). Measured: the Minecraft image extracts a JNA library to
// /data/.cache/JNA/temp and deletes it after loading – with the world on
// NFS every final dump failed ("Can't create link remap") and the
// migration rolled back.
//
// But CRIU removes its link remaps again at the end of a dump that leaves
// the process running – and the final dump does, so that a rollback is
// just a thaw. So the source agent creates the links itself once the dump
// is done, from the dump's images, while the frozen process still holds
// the .nfsXXXX name; a rollback removes them. The target sees them through
// the shared filesystem. A link remap anywhere else (the container's
// rootfs, an emptyDir) would not reach the target: the migration rolls
// back instead.

// sharedFSMagics are the filesystems the target sees as the source does.
var sharedFSMagics = map[int64]string{
	0x6969:     "nfs",
	0x00c36400: "ceph",
	0xfe534d42: "smb2",
	0xff534d42: "cifs",
	0x65735546: "fuse",
}

// hasSharedVolume: the pod mounts a ReadWriteMany volume.
func hasSharedVolume(m *v1.Migration) bool {
	for _, v := range m.Status.Volumes {
		if v.Kind == v1.VolumeKindPVCRWX {
			return true
		}
	}
	return false
}

// relinkRemaps creates the link remaps of a container's final dump (see
// above) and records them for a rollback.
func (j *sourceJob) relinkRemaps(c *srcContainer, imageDir string) error {
	remaps, err := criuimg.LinkedRemaps(j.a.Host.Path(imageDir))
	if err != nil {
		return fmt.Errorf("reading the dump's link remaps: %w", err)
	}
	root := filepath.Join("/proc", strconv.Itoa(c.pid), "root") // the container's mount namespace
	for _, r := range remaps {
		orig, link := filepath.Join(root, r.Orig), filepath.Join(root, r.Remap)
		var st unix.Statfs_t
		if err := unix.Statfs(filepath.Dir(link), &st); err != nil {
			return fmt.Errorf("link remap %s: %w", r.Remap, err)
		}
		if _, ok := sharedFSMagics[int64(st.Type)]; !ok {
			return fmt.Errorf("%s was deleted while open outside shared storage (filesystem %#x): it cannot reach the target", r.Orig, st.Type)
		}
		if err := os.Link(orig, link); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("link remap %s -> %s: %w", r.Orig, r.Remap, err)
		}
		j.mu.Lock()
		j.remapLinks = append(j.remapLinks, link)
		j.mu.Unlock()
		j.log.Info("file deleted while open kept for the target", "file", r.Orig, "link", r.Remap)
	}
	return nil
}

// removeRemapLinks undoes relinkRemaps (rollback); j.mu must be held.
func (j *sourceJob) removeRemapLinks() {
	for _, l := range j.remapLinks {
		if err := os.Remove(l); err != nil && !errors.Is(err, fs.ErrNotExist) {
			j.log.Warn("removing a link remap after the rollback", "link", l, "err", err)
		}
	}
	j.remapLinks = nil
}

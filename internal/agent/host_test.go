// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"strings"
	"testing"
)

func TestParseMountTypes(t *testing.T) {
	info := `22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
812 22 0:61 /pvc-30 /var/lib/kubelet/pods/u1/volumes/kubernetes.io~csi/pvc-30/mount rw,relatime shared:401 - nfs4 10.104.92.226:/pvc-30 rw,vers=4.1
813 22 252:16 / /var/lib/kubelet/pods/u1/volumes/kubernetes.io~csi/pvc-31/mount rw,relatime shared:402 - ext4 /dev/vdb rw
814 22 0:62 / /mnt/with\040space rw - fuse.s3fs s3fs rw
`
	got := parseMountTypes(strings.NewReader(info))
	for path, want := range map[string]string{
		"/": "ext4",
		"/var/lib/kubelet/pods/u1/volumes/kubernetes.io~csi/pvc-30/mount": "nfs4",
		"/var/lib/kubelet/pods/u1/volumes/kubernetes.io~csi/pvc-31/mount": "ext4",
		"/mnt/with space": "fuse.s3fs",
	} {
		if got[path] != want {
			t.Errorf("%s: %q, want %q", path, got[path], want)
		}
	}
}

func TestSharedFS(t *testing.T) {
	for _, fs := range []string{"nfs", "nfs4", "ceph", "cifs", "fuse.s3fs", "fuse", "virtiofs"} {
		if !SharedFS(fs) {
			t.Errorf("%s must count as shared", fs)
		}
	}
	for _, fs := range []string{"ext4", "xfs", "btrfs", "tmpfs", "overlay", ""} {
		if SharedFS(fs) {
			t.Errorf("%s must not count as shared", fs)
		}
	}
}

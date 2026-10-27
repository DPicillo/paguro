// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 David Picillo

// Package selinuxlabel reads and sets the SELinux labels of files, for
// nodes whose container runtime labels containers (containerd with
// enable_selinux, Bottlerocket): every pod runs with categories of its own
// (container_t:s0:c12,c345) and may only use files that carry them.
// Without SELinux every function does nothing.
package selinuxlabel

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Xattr is the extended attribute that holds a file's SELinux label.
const Xattr = "security.selinux"

// Of returns path's label, "" if it has none (no SELinux, or a file system
// without labels).
func Of(path string) string {
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, Xattr, buf)
	if err != nil || n == 0 {
		return ""
	}
	return strings.TrimRight(string(buf[:n]), "\x00")
}

// Set gives path the label; nothing for "".
func Set(path, label string) error {
	if label == "" {
		return nil
	}
	return unix.Lsetxattr(path, Xattr, []byte(label), 0)
}

// PrepareWorkDir labels CRIU's work directory and creates its log files
// with the container's file label (its mount label). CRIU's parasite (on
// dump) and restorer (on restore) run inside the container's processes,
// in the container's context, and write to CRIU's log: a log the
// container may not append to fails the dump ("Can't switch parasite to
// daemon mode") or the restore. Podman and CRI-O label their checkpoint
// directories the same way.
func PrepareWorkDir(dir, label string, logs ...string) error {
	if label == "" {
		return nil
	}
	if err := Set(dir, label); err != nil {
		return err
	}
	for _, name := range logs {
		p := filepath.Join(dir, name)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
		if err := Set(p, label); err != nil {
			return err
		}
	}
	return nil
}

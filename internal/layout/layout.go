// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package layout describes the directory in which a checkpoint is stored on
// the target node, and the metadata shared by the source agent and the
// wrapper.
//
//	/var/lib/paguro/restore/<migration-uid>/
//	├── meta.json                      what was dumped and how
//	├── SANDBOX, SANDBOX_NETNS         the replacement's sandbox exists (wrapper)
//	├── HANDOVER                       the source is paused (early hand-over)
//	├── ABORTED                        rolled back before the commit (agent)
//	├── emptydir/<volume>.tar          content of an emptyDir, or
//	│   <volume>.base/ + .delta.tar    its pre-copied base and the delta of the freeze
//	└── containers/<name>/
//	    ├── images/
//	    │   ├── 1 … n/                 pre-copy rounds as received (page data
//	    │   │                          removed once applied to base/)
//	    │   ├── base/, delta/          the rounds folded into flat images;
//	    │   │                          base/ROUND: complete up to that round
//	    │   └── final/                 the freeze dump, parent → delta/ or base/
//	    ├── rootfs-diff.tar            delta of the writable layer
//	    ├── READY | FAILED             set by the agent for the source
//	    ├── RESTORED | COLDSTART       set by the wrapper
//	    └── work-<container-id>/       CRIU's restore work directory
package layout

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"paguro.dev/paguro/pkg/names"
)

// DumpOptions must be mirrored exactly on restore, otherwise CRIU rejects
// the images (e.g. file locks without --file-locks).
type DumpOptions struct {
	TCPEstablished bool `json:"tcpEstablished"`
	FileLocks      bool `json:"fileLocks"`
	ExtUnixSk      bool `json:"extUnixSk"`
	// ShellJob/TTY is not supported (the preflight rejects tty).
}

type ContainerMeta struct {
	Name  string      `json:"name"`
	Image string      `json:"image"`
	Opts  DumpOptions `json:"opts"`
	// Rounds is the number of pre-copy rounds before "final".
	Rounds int `json:"rounds"`
	// LazyPages asks the restore wrapper for a post-copy restore: the process
	// resumes before its memory is written back, pages are faulted in on
	// first access (userfaultfd) and pushed in the background from the local
	// checkpoint. The freeze then no longer grows with the container's RSS.
	LazyPages bool `json:"lazyPages,omitempty"`
}

type Meta struct {
	Migration  string `json:"migration"`
	Namespace  string `json:"namespace"`
	UID        string `json:"uid"`
	SourceNode string `json:"sourceNode"`
	SourceIP   string `json:"sourceIP"`
	// BoundIPs are the local addresses the pod's sockets were bound to at
	// the freeze (wildcard and loopback excluded). With a new pod IP the
	// wrapper configures all of them before the restore: after an earlier
	// migration some sockets may still use an older IP.
	BoundIPs   []string        `json:"boundIPs,omitempty"`
	Containers []ContainerMeta `json:"containers"`
	EmptyDirs  []string        `json:"emptyDirs,omitempty"`
	FrozenAt   time.Time       `json:"frozenAt"`
}

// pathName: a container or volume name that is safe in a path.
var pathName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$`)

// Validate checks what arrives over the network before anything on the
// node uses it: names become paths, addresses go onto the pod's loopback.
func (m *Meta) Validate() error {
	for _, c := range m.Containers {
		if !pathName.MatchString(c.Name) {
			return fmt.Errorf("container name %q", c.Name)
		}
	}
	for _, v := range m.EmptyDirs {
		if !pathName.MatchString(v) {
			return fmt.Errorf("emptyDir name %q", v)
		}
	}
	for _, a := range append([]string{m.SourceIP}, m.BoundIPs...) {
		if _, err := netip.ParseAddr(a); a != "" && err != nil {
			return fmt.Errorf("address %q", a)
		}
	}
	return nil
}

// Restored is the content of RESTORED or COLDSTART.
type Restored struct {
	ContainerID string    `json:"containerID"`
	StartedAt   time.Time `json:"startedAt"`
	FinishedAt  time.Time `json:"finishedAt"`
	WaitMs      int64     `json:"waitMs"`    // waiting for data
	ApplyMs     int64     `json:"applyMs"`   // rootfs/emptyDir delta
	RestoreMs   int64     `json:"restoreMs"` // runc restore
	Reason      string    `json:"reason,omitempty"`
}

// StateDir is the node's Paguro state directory (a variable for tests).
var StateDir = names.StateDir

func Root(uid string) string { return filepath.Join(StateDir, "restore", uid) }

func ContainerDir(uid, name string) string {
	return filepath.Join(Root(uid), "containers", name)
}

func ImagesDir(uid, name string) string {
	return filepath.Join(ContainerDir(uid, name), names.DirImages)
}

// DevShmVolume is the name under which the pod's own /dev/shm – the
// sandbox's tmpfs the containers share, not a volume – travels with the
// emptyDirs. Not a valid volume name (no dots in a DNS label), so it never
// meets a real one.
const DevShmVolume = "dev.shm"

func EmptyDirTar(uid, vol string) string {
	return filepath.Join(Root(uid), "emptydir", vol+".tar")
}

// EmptyDirBase is the emptyDir's content copied during pre-copy, already
// unpacked (complete once EmptyDirBase+".complete" exists); the freeze
// then only sends EmptyDirDeltaTar.
func EmptyDirBase(uid, vol string) string {
	return filepath.Join(Root(uid), "emptydir", vol+".base")
}

// EmptyDirDeltaTar is what changed in the emptyDir since its base, with
// whiteouts for what was deleted.
func EmptyDirDeltaTar(uid, vol string) string {
	return filepath.Join(Root(uid), "emptydir", vol+".delta.tar")
}

func ReadMeta(uid string) (*Meta, error) {
	b, err := os.ReadFile(filepath.Join(Root(uid), names.FileMeta))
	if err != nil {
		return nil, err
	}
	m := &Meta{}
	return m, json.Unmarshal(b, m)
}

// WriteJSONAtomic first writes to a temporary file and then renames it, so
// that readers never see a partial file.
func WriteJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// RestorePending reports whether migration uid's checkpoint still waits to
// be restored on this node: its restore directory exists (the target agent
// creates it before any data arrives) and not every container has been
// restored or cold-started. A pod keeps its restore annotations for life;
// only a pending restore may shield it.
func RestorePending(uid string) bool {
	if !Exists(Root(uid)) {
		return false
	}
	meta, err := ReadMeta(uid)
	if err != nil {
		return true // the source has not sent its metadata yet
	}
	for _, c := range meta.Containers {
		d := ContainerDir(uid, c.Name)
		if !Exists(filepath.Join(d, names.FileRestored)) && !Exists(filepath.Join(d, names.FileColdStart)) {
			return true
		}
	}
	return false
}

// LatestWrite is the newest modification time below dir: how both the
// wrapper and the agent's janitor tell a transfer still arriving from a
// dead one.
func LatestWrite(dir string) time.Time {
	var latest time.Time
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
		return nil
	})
	return latest
}

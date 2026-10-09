// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"paguro.dev/paguro/internal/archive"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/ocispec"
	"paguro.dev/paguro/pkg/names"
)

// This is how containerd's runc shim (go-runc) invokes create.
func TestParseCreate(t *testing.T) {
	args := []string{"--root", "/run/containerd/runc/k8s.io", "--log", "/run/x/log.json", "--log-format", "json",
		"--systemd-cgroup", "create", "--bundle", "/run/b", "--pid-file", "/run/b/init.pid", "--preserve-fds=2", "abc123"}
	inv := parse(args)
	if inv.cmd != "create" || inv.id != "abc123" || inv.bundle != "/run/b" || inv.pidFile != "/run/b/init.pid" || inv.preserveFDs != 2 {
		t.Fatalf("%+v", inv)
	}
	if inv.logFile != "/run/x/log.json" {
		t.Fatalf("log=%q", inv.logFile)
	}
	want := []string{"--root", "/run/containerd/runc/k8s.io", "--log", "/run/x/log.json", "--log-format", "json", "--systemd-cgroup"}
	if !reflect.DeepEqual(inv.global, want) {
		t.Fatalf("global=%v", inv.global)
	}
}

func TestParseStart(t *testing.T) {
	inv := parse([]string{"--root", "/r", "start", "id1"})
	if inv.cmd != "start" || inv.id != "id1" {
		t.Fatalf("%+v", inv)
	}
}

// A pod keeps its restore annotations for life; only a restore that is
// still to come may shield a new sandbox (found: a migrated pod stayed
// unreachable after its node rebooted).
func TestRestorePending(t *testing.T) {
	layout.StateDir = t.TempDir()
	uid := "mig-1"
	if layout.RestorePending(uid) {
		t.Fatal("no restore directory: nothing pending")
	}
	if err := os.MkdirAll(layout.Root(uid), 0o700); err != nil {
		t.Fatal(err)
	}
	if !layout.RestorePending(uid) {
		t.Fatal("directory without metadata: data still arriving")
	}
	meta := layout.Meta{UID: uid, Containers: []layout.ContainerMeta{{Name: "a"}, {Name: "b"}}}
	if err := layout.WriteJSONAtomic(filepath.Join(layout.Root(uid), names.FileMeta), meta); err != nil {
		t.Fatal(err)
	}
	mark := func(c, f string) {
		if err := os.MkdirAll(layout.ContainerDir(uid, c), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(layout.ContainerDir(uid, c), f), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mark("a", names.FileRestored)
	if !layout.RestorePending(uid) {
		t.Fatal("container b not restored yet")
	}
	mark("b", names.FileColdStart)
	if layout.RestorePending(uid) {
		t.Fatal("every container done: a new sandbox (node reboot) must not be shielded")
	}
}

// A replacement of a migration that was rolled back before its commit must
// neither restore nor cold-start: the source runs on.
func TestRolledBackReplacementNeverStarts(t *testing.T) {
	layout.StateDir = t.TempDir()
	uid := "mig-2"
	if err := os.MkdirAll(layout.Root(uid), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.Root(uid), names.FileAborted), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	spec := &ocispec.Spec{Annotations: map[string]string{ocispec.AnnContainerName: "app"}}
	if code := restoreContainer(invocation{cmd: "create", id: "c1"}, spec, uid); code == 0 {
		t.Fatal("create must fail")
	}
	if layout.Exists(filepath.Join(layout.ContainerDir(uid, "app"), names.FileColdStart)) {
		t.Fatal("cold-started a replacement of a rolled-back migration")
	}
}

// restoreArgs keeps what runc restore understands of the create call and
// adds CRIU's options from the dump.
func TestRestoreArgs(t *testing.T) {
	create := []string{"--bundle", "/b", "--pid-file=/p", "--console-socket", "/s", "--no-pivot",
		"--preserve-fds", "3", "--pidfd-socket=/x"}
	got := restoreArgs(create, layout.DumpOptions{TCPEstablished: true, FileLocks: true}, "/img", "/work")
	want := []string{"--detach", "--image-path", "/img", "--work-path", "/work",
		"--bundle", "/b", "--pid-file=/p", "--console-socket", "/s", "--no-pivot", "--tcp-established", "--file-locks"}
	if !slices.Equal(got, want) {
		t.Fatalf("restoreArgs:\n got %v\nwant %v", got, want)
	}
}

// An emptyDir sent as a base during pre-copy and a delta in the freeze ends
// up in the new pod's emptyDir as it was at the freeze.
func TestApplyEmptyDirBaseAndDelta(t *testing.T) {
	layout.StateDir = t.TempDir()
	uid := "mig"
	pod := t.TempDir()
	srcDir := filepath.Join(t.TempDir(), "data")
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(srcDir, "server.bin"), "binary")
	write(filepath.Join(srcDir, "worlds/level.dat"), "v1")
	write(filepath.Join(srcDir, "old.log"), "x")

	// Pre-copy: the base, unpacked into the staging directory.
	manifest := archive.Manifest{}
	var buf bytes.Buffer
	if _, err := archive.Pack(&buf, srcDir, archive.PackOptions{Record: manifest}); err != nil {
		t.Fatal(err)
	}
	base := layout.EmptyDirBase(uid, "data")
	if _, err := archive.Unpack(&buf, base, archive.UnpackOptions{}); err != nil {
		t.Fatal(err)
	}
	write(base+".complete", "")
	// Freeze: the changes.
	write(filepath.Join(srcDir, "worlds/level.dat"), "v2")
	os.Remove(filepath.Join(srcDir, "old.log"))
	buf.Reset()
	if _, err := archive.Pack(&buf, srcDir, archive.PackOptions{Since: manifest}); err != nil {
		t.Fatal(err)
	}
	write(layout.EmptyDirDeltaTar(uid, "data"), buf.String())

	dst := filepath.Join(pod, "volumes/kubernetes.io~empty-dir/data")
	if err := os.MkdirAll(dst, 0o777); err != nil {
		t.Fatal(err)
	}
	spec := &ocispec.Spec{Mounts: []ocispec.Mount{{Destination: "/data", Source: dst}}}
	if err := applyEmptyDirs(uid, spec); err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]string{"server.bin": "binary", "worlds/level.dat": "v2"} {
		if b, err := os.ReadFile(filepath.Join(dst, f)); err != nil || string(b) != want {
			t.Errorf("%s = %q (%v), want %q", f, b, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "old.log")); err == nil {
		t.Error("a file deleted before the freeze came back")
	}
}

// The pod's own /dev/shm (the sandbox's tmpfs, bind-mounted) gets its
// files back before the restore – once per pod, with their modes; never
// the host's /dev/shm, never a container's own tmpfs.
func TestApplyDevShm(t *testing.T) {
	layout.StateDir = t.TempDir()
	uid := "mig"
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "gitlab/sidekiq"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "gitlab/sidekiq/counter.db"), []byte("metrics"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "PostgreSQL.1234"), []byte("dsm"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := archive.Pack(&buf, src, archive.PackOptions{}); err != nil {
		t.Fatal(err)
	}
	tarPath := layout.EmptyDirTar(uid, layout.DevShmVolume)
	if err := os.MkdirAll(filepath.Dir(tarPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tarPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	shm := filepath.Join(t.TempDir(), "io.containerd.grpc.v1.cri/sandboxes/abc/shm")
	own := filepath.Join(t.TempDir(), "own")
	for _, d := range []string{shm, own} {
		if err := os.MkdirAll(d, 0o1777); err != nil {
			t.Fatal(err)
		}
	}
	spec := &ocispec.Spec{Mounts: []ocispec.Mount{
		{Destination: "/dev/shm", Type: "bind", Source: shm, Options: []string{"rbind", "ro"}},
	}}
	if err := applyEmptyDirs(uid, spec); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(shm, "gitlab/sidekiq/counter.db"))
	if err != nil || string(b) != "metrics" {
		t.Fatalf("counter.db: %q %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(shm, "PostgreSQL.1234")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("PostgreSQL.1234: %v %v", fi, err)
	}
	// Once per pod: the next container's restore leaves it alone.
	if err := os.Remove(filepath.Join(shm, "PostgreSQL.1234")); err != nil {
		t.Fatal(err)
	}
	if err := applyEmptyDirs(uid, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(shm, "PostgreSQL.1234")); err == nil {
		t.Fatal("applied twice")
	}
	for _, m := range []ocispec.Mount{
		{Destination: "/dev/shm", Type: "bind", Source: "/dev/shm", Options: []string{"rbind"}}, // the host's
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm"},                                 // the container's own
		{Destination: "/dev/shm", Type: "bind", Source: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~empty-dir/shm"},
		{Destination: "/data", Type: "bind", Source: own, Options: []string{"rbind"}},
	} {
		if sandboxShm(m) {
			t.Errorf("%+v taken for the pod's own /dev/shm", m)
		}
	}
	if !sandboxShm(spec.Mounts[0]) {
		t.Error("the sandbox's /dev/shm not recognized")
	}
}

// Only failures where lazy pages are involved get an eager second attempt.
func TestEagerMayHelp(t *testing.T) {
	for msg, want := range map[string]bool{
		"runc restore exit 1: criu: vdso: Invalid ELF magic; Restorer fail 578":                          true,
		"runc restore exit 1: criu: uffd: Can't register region":                                         true,
		"runc restore exit 1: criu: Can't open file dev/shm/gitlab/x":                                    false,
		"runc restore exit 1: criu: Can't bind inet socket: Address in use":                              false,
		"runc restore exit 1 (log: /var/lib/paguro/restore/u/containers/lazy-worker/restore-failed.log)": false,
	} {
		if got := eagerMayHelp(errors.New(msg)); got != want {
			t.Errorf("%q: %v, want %v", msg, got, want)
		}
	}
}

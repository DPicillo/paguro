// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
)

// An agent restarted before its two-minute cleanup left the images behind;
// the janitor removes them once the migration ended and the directory is
// quiet – never while it runs or a process still uses it.
func TestStateJanitor(t *testing.T) {
	oldState, oldProc := layout.StateDir, procRoot
	layout.StateDir, procRoot = t.TempDir(), t.TempDir() // no process uses the test's migrations
	defer func() { layout.StateDir, procRoot = oldState, oldProc }()
	hostRoot := t.TempDir()
	now := time.Now()

	mig := func(uid string, phase v1.Phase) *v1.Migration {
		return &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: uid, Namespace: "ns", UID: types.UID(uid)},
			Status: v1.MigrationStatus{Phase: phase}}
	}
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	// "awaited" failed after the commit; its replacement still waits on this
	// node (the volume has not arrived) – the checkpoint is its only copy.
	replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns",
		Annotations: map[string]string{v1.AnnotationRestoreID: "awaited"}}, Spec: corev1.PodSpec{NodeName: "n1"},
		Status: corev1.PodStatus{Phase: corev1.PodPending}}
	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(mig("running", v1.PhasePreCopy), mig("ended", v1.PhaseSucceeded), mig("awaited", v1.PhaseFailed), replacement).Build()
	a := &Agent{Client: cl, APIReader: cl, NodeName: "n1", Host: &Host{Root: hostRoot}, Log: slog.New(slog.DiscardHandler)}

	// target directory with images, aged
	target := func(uid string, age time.Duration) {
		img := filepath.Join(layout.ImagesDir(uid, "c"), "final", "pages-1.img")
		if err := os.MkdirAll(filepath.Dir(img), 0o700); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(img, []byte("secret memory"), 0o600)
		_ = os.WriteFile(filepath.Join(layout.ContainerDir(uid, "c"), v1.FileRestored), nil, 0o600)
		age1(t, layout.Root(uid), now.Add(-age))
	}
	dump := func(uid string, age time.Duration) string {
		d := filepath.Join(hostRoot, v1.StateDir, "dump", uid)
		_ = os.MkdirAll(filepath.Join(d, "containers", "c"), 0o700)
		_ = os.WriteFile(filepath.Join(d, "containers", "c", "pages-1.img"), []byte("x"), 0o600)
		age1(t, d, now.Add(-age))
		return d
	}
	target("running", time.Hour)
	target("ended", 20*time.Minute)
	target("gone", 20*time.Minute)
	target("fresh", time.Minute)
	target("ancient", 8*24*time.Hour)
	target("awaited", time.Hour)
	_ = os.Remove(filepath.Join(layout.ContainerDir("awaited", "c"), v1.FileRestored)) // restore pending
	_ = os.WriteFile(filepath.Join(layout.Root("awaited"), "meta.json"), []byte(`{"containers":[{"name":"c"}]}`), 0o600)
	dRunning, dEnded := dump("running", time.Hour), dump("ended", time.Hour)

	a.sweepState(context.Background(), now)

	for uid, want := range map[string]bool{"running": true, "ended": false, "gone": false, "fresh": true, "awaited": true} {
		if got := hasImages(uid); got != want {
			t.Errorf("%s: images present %v, want %v", uid, got, want)
		}
	}
	if !layout.Exists(filepath.Join(layout.ContainerDir("ended", "c"), v1.FileRestored)) {
		t.Error("markers and logs must stay for tracing")
	}
	if layout.Exists(layout.Root("ancient")) {
		t.Error("directory older than the retention kept")
	}
	if !layout.Exists(dRunning) || layout.Exists(dEnded) {
		t.Error("want the running dump kept and the ended one removed")
	}
}

// A process naming the migration (a lazy-pages daemon) keeps its images.
func TestStateJanitorSkipsUsedImages(t *testing.T) {
	oldProc := procRoot
	procRoot = t.TempDir()
	defer func() { procRoot = oldProc }()
	_ = os.MkdirAll(filepath.Join(procRoot, "4242"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "4242", "cmdline"),
		[]byte("criu\x00lazy-pages\x00--images-dir\x00/var/lib/paguro/restore/abc-123/containers/c/images/final"), 0o644)
	if !inUse("abc-123") || inUse("def-456") {
		t.Fatal("inUse")
	}
}

func age1(t *testing.T, dir string, at time.Time) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			err = os.Chtimes(p, at, at)
		}
		return err
	})
}

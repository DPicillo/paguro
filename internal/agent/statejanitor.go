// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
)

// Checkpoints hold a workload's complete memory – its keys, tokens and user
// data – and can take gigabytes. Both sides remove them when they see the
// migration end: the source its dump at once, the target its images two
// minutes later (lazy pages may still be served). An agent restarted in
// between never did – found in the lab: 5 GB of images from days earlier.
// The state janitor catches up after imageRetention of quiet: images and
// dumps of migrations that ended or no longer exist go, the rest of a
// target directory (logs, markers for tracing) after dirRetention.

const (
	stateJanitorInterval = 10 * time.Minute
	imageRetention       = 10 * time.Minute
	dirRetention         = 7 * 24 * time.Hour
)

// RunStateJanitor sweeps this node's state directory until ctx ends.
func (a *Agent) RunStateJanitor(ctx context.Context) {
	for {
		a.sweepState(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(stateJanitorInterval):
		}
	}
}

func (a *Agent) sweepState(ctx context.Context, now time.Time) {
	// Live list: the janitor starts before the manager's cache.
	migs := &v1.MigrationList{}
	if err := a.APIReader.List(ctx, migs); err != nil {
		a.Log.Warn("state janitor: listing migrations", "err", err)
		return
	}
	running := map[string]bool{}
	for _, m := range migs.Items {
		if !m.Status.Phase.Terminal() {
			running[string(m.UID)] = true
		}
	}
	ended := func(dir string) bool {
		uid := filepath.Base(dir)
		return safeName.MatchString(uid) && !running[uid] && now.Sub(layout.LatestWrite(dir)) >= imageRetention && !inUse(uid)
	}

	targets, _ := os.ReadDir(filepath.Join(layout.StateDir, "restore"))
	for _, e := range targets {
		dir := layout.Root(e.Name())
		if !e.IsDir() || !ended(dir) || a.restoreAwaited(ctx, e.Name()) {
			continue
		}
		if now.Sub(layout.LatestWrite(dir)) >= dirRetention {
			if os.RemoveAll(dir) == nil {
				stateCleanups.WithLabelValues("directory").Inc()
				a.Log.Info("state janitor: removed an old migration directory", "migration", e.Name())
			}
			continue
		}
		if hasImages(e.Name()) {
			cleanupImages(e.Name())
			stateCleanups.WithLabelValues("images").Inc()
			a.Log.Info("state janitor: removed the images of an ended migration", "migration", e.Name())
		}
	}

	dumps := a.Host.Path(filepath.Join(v1.StateDir, "dump"))
	sources, _ := os.ReadDir(dumps)
	for _, e := range sources {
		dir := filepath.Join(dumps, e.Name())
		if e.IsDir() && ended(dir) && os.RemoveAll(dir) == nil {
			stateCleanups.WithLabelValues("dump").Inc()
			a.Log.Info("state janitor: removed the dump of an ended migration", "migration", e.Name())
		}
	}
}

// restoreAwaited reports whether a replacement of the migration on this
// node still waits for its restore. Its checkpoint is then the workload's
// only copy: a migration that failed after the commit (found: the restore
// timed out while the cloud could not attach the volume) keeps it for the
// rescue – removing the images made the replacement cold-start once the
// volume arrived 16 minutes later.
func (a *Agent) restoreAwaited(ctx context.Context, uid string) bool {
	if !layout.RestorePending(uid) {
		return false
	}
	pods := &corev1.PodList{}
	if err := a.Client.List(ctx, pods); err != nil {
		return true // unsure: keep
	}
	for _, p := range pods.Items {
		if p.Annotations[v1.AnnotationRestoreID] == uid && p.Spec.NodeName == a.NodeName && p.DeletionTimestamp == nil &&
			p.Status.Phase != corev1.PodFailed && p.Status.Phase != corev1.PodSucceeded {
			return true
		}
	}
	return false
}

// hasImages reports whether a target directory still holds data that
// cleanupImages removes.
func hasImages(uid string) bool {
	entries, _ := os.ReadDir(filepath.Join(layout.Root(uid), "containers"))
	for _, e := range entries {
		if layout.Exists(layout.ImagesDir(uid, e.Name())) ||
			layout.Exists(filepath.Join(layout.ContainerDir(uid, e.Name()), v1.FileRootfsDiff)) {
			return true
		}
	}
	return layout.Exists(filepath.Join(layout.Root(uid), "emptydir"))
}

// procRoot is the host's /proc (the agent runs with hostPID).
var procRoot = "/proc"

// inUse reports whether a process on the node names the migration in its
// command line – a lazy-pages daemon still serving its images, for one.
func inUse(uid string) bool {
	entries, _ := os.ReadDir(procRoot)
	for _, e := range entries {
		if e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline")); err == nil && strings.Contains(string(b), uid) {
			return true
		}
	}
	return false
}

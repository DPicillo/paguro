// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Source side, part 3: freeze and thaw, page cache write-back of shared
// volumes, and the hand-over of locks on shared filesystems.

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/shield"
)

func (j *sourceJob) freeze(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	// The shield: from now on no TCP segment leaves the pod, and incoming
	// ones are dropped instead of being acknowledged by the frozen pod's
	// kernel stack – otherwise the source could acknowledge data that the
	// target never sees. It goes up in parallel with the pause (both start
	// a host program); whatever the kernel acknowledges until then is in
	// the socket queues the final dump captures.
	//
	// Like dump(), never cancelled halfway: cancelling kills only nsenter,
	// runc or nft would go on, and a thaw racing them would find the pod
	// running and leave it paused.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostCommandTimeout)
	defer cancel()
	j.frozen = true
	shieldErr := make(chan error, 1)
	go func() { shieldErr <- shield.Raise(j.a.Host.ShieldRunner(ctx), j.netns) }()
	// All containers at once: each pause is a host program of its own.
	pauseErrs := make([]error, len(j.cs))
	var wg sync.WaitGroup
	for i, c := range j.cs {
		wg.Go(func() {
			if err := j.a.Host.Pause(ctx, c.id); err != nil {
				pauseErrs[i] = fmt.Errorf("pause %s: %w", c.name, err)
			}
		})
	}
	wg.Wait()
	return errors.Join(append(pauseErrs, <-shieldErr)...)
}

// hostCommandTimeout bounds a host program that must not be cancelled
// halfway (pause, shield).
const hostCommandTimeout = 30 * time.Second

// thaw undoes the freeze: containers keep running as if nothing had
// happened. TCP connections survive because the kernel state of the sockets
// was never touched.
func (j *sourceJob) thaw(ctx context.Context) error {
	// A dump still running would freeze the cgroup again when it ends.
	j.dumping.Lock()
	defer j.dumping.Unlock()
	j.mu.Lock()
	defer j.mu.Unlock()
	j.restoreThrottles()
	j.removeRemapLinks()
	if !j.frozen && !j.drained {
		return nil
	}
	var errs []error
	for _, c := range j.cs {
		if !j.frozen {
			break // only drained (drain.go), never paused
		}
		if err := j.a.Host.Resume(ctx, c.id); err != nil {
			errs = append(errs, err)
		}
	}
	if err := shield.Lower(j.a.Host.ShieldRunner(ctx), j.netns); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		j.frozen, j.drained = false, false
		j.log.Info("source thawed – rollback without loss")
	}
	return errors.Join(errs...)
}

// syncVolumes writes the page cache of all PVCs of the pod to the volume.
// For a block volume (RWO) the later unmount would do that too – but only
// after the commit and in the critical path of the detach; running syncfs
// now shortens the detach, and a failure is only logged.
//
// For a shared filesystem (NFS, CephFS, SMB, FUSE – RWX volumes) this sync is
// what makes the handover correct: the target mounts it while the source
// node still has it mounted, and data the frozen process wrote that the
// source node has not written back would be missing on the target (or be
// written back later, over the restored process's own writes). The
// processes are frozen here, so nothing new can follow. If the sync fails
// or does not finish within syncTimeout, the migration is aborted before
// the commit and the source thawed.
func (j *sourceJob) syncVolumes(ctx context.Context) error {
	base := filepath.Join("/var/lib/kubelet/pods", string(j.pod.UID), "volumes")
	types, err := MountTypes("/proc/1/mountinfo")
	if err != nil {
		j.log.Warn("reading host mounts", "err", err)
	}
	type vol struct{ name, path, fstype string }
	var vols []vol
	entries, _ := os.ReadDir(j.a.Host.Path(base))
	for _, plugin := range entries {
		dirs, _ := os.ReadDir(j.a.Host.Path(filepath.Join(base, plugin.Name())))
		for _, v := range dirs {
			p := filepath.Join(base, plugin.Name(), v.Name())
			if plugin.Name() == "kubernetes.io~csi" {
				p = filepath.Join(p, "mount")
			}
			// Tokens, ConfigMaps, Secrets, memory-backed emptyDirs: nothing to
			// write back (measured: a process per such volume, 80–160 ms of
			// freeze for a pod with two of them).
			// Not a mount of its own (an emptyDir on the node's disk): its
			// content travels with the delta; a syncfs would write back the
			// node's whole root filesystem.
			if fs := types[p]; fs == "" || fs == "tmpfs" || fs == "ramfs" {
				continue
			}
			vols = append(vols, vol{v.Name(), p, types[p]})
		}
	}
	errs := make([]error, len(vols))
	var wg sync.WaitGroup
	for i, v := range vols {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := j.syncfs(ctx, v.path)
			switch {
			case err != nil && SharedFS(v.fstype):
				errs[i] = fmt.Errorf("writing back shared volume %s (%s): %w", v.name, v.fstype, err)
			case err != nil:
				j.log.Warn("syncfs", "path", v.path, "err", err)
			case SharedFS(v.fstype):
				j.log.Info("shared volume written back", "volume", v.name, "fstype", v.fstype, "ms", ms(time.Since(start)))
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// syncfs writes back the filesystem of a host path – syncfs(2) on a
// descriptor opened through the host root, no process to start. Bounded by
// syncTimeout: a write-back stuck on an unreachable server cannot be
// interrupted, so the wait is abandoned rather than the call awaited.
func (j *sourceJob) syncfs(ctx context.Context, p string) error {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		f, err := os.Open(j.a.Host.Path(p))
		if err != nil {
			done <- err
			return
		}
		defer f.Close()
		done <- unix.Syncfs(int(f.Fd()))
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("not finished after %s", syncTimeout)
	}
}

// syncTimeout bounds the write-back of a volume inside the freeze.
var syncTimeout = 30 * time.Second

// podPIDs lists the processes of the pod's containers.
func (j *sourceJob) podPIDs(ctx context.Context) []int {
	var pids []int
	for _, c := range j.cs {
		out, err := j.a.Host.Runc(ctx, "ps", "--format", "json", c.id)
		if err != nil {
			j.log.Warn("listing the container's processes", "container", c.name, "err", err)
			continue
		}
		var ps []int
		if err := json.Unmarshal(out, &ps); err == nil {
			pids = append(pids, ps...)
		}
	}
	return pids
}

// handOverLocks ends the frozen processes before READY when they hold locks
// on a shared filesystem (locks.go): after the commit, once the pod is
// terminating – kubelet must not restart its containers – and the target
// sandbox is up, so that the restore follows within milliseconds. It never
// fails the migration: without the hand-over the restore still gets the
// lock, only later.
func (j *sourceJob) handOverLocks(ctx context.Context, held []heldLock) error {
	if len(held) == 0 {
		return nil
	}
	start := time.Now()
	key, podKey := client.ObjectKeyFromObject(j.m), client.ObjectKeyFromObject(j.pod)
	for {
		cur := &v1.Migration{}
		if err := j.a.Client.Get(ctx, key, cur); err == nil {
			if cur.Status.Phase.Terminal() {
				return nil
			}
			pod := &corev1.Pod{}
			err := j.a.Client.Get(ctx, podKey, pod)
			terminating := apierrors.IsNotFound(err) || (err == nil && (pod.UID != j.pod.UID || pod.DeletionTimestamp != nil))
			if terminating && cur.Status.Target.SandboxReadyAt != nil {
				break
			}
		}
		if time.Since(start) > lockHandOverWait {
			j.log.Warn("file locks on shared filesystems not handed over: the target sandbox did not come up", "locks", len(held))
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	waited := time.Since(start)
	for _, c := range j.cs {
		if _, err := j.a.Host.Runc(ctx, "kill", "--all", c.id, "KILL"); err != nil {
			j.log.Warn("ending the source process", "container", c.name, "err", err)
		}
	}
	// A lock is released when its owner exits.
	pids := map[int]bool{}
	for _, l := range held {
		pids[l.PID] = true
	}
	for pid := range pids {
		waitExited(ctx, pid, 5*time.Second)
	}
	j.log.Info("source processes ended before READY: their locks on shared filesystems are free for the restore",
		"locks", len(held), "path", held[0].Path, "fstype", held[0].FSType, "waitMs", ms(waited), "endMs", ms(time.Since(start)-waited))
	return nil
}

// lockHandOverWait bounds the wait for the target sandbox in handOverLocks.
const lockHandOverWait = 5 * time.Minute

// waitExited waits until pid has exited (gone or a zombie), at most d.
func waitExited(ctx context.Context, pid int, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return
		}
		// "pid (comm) S …": the state follows the last ')'
		if i := strings.LastIndexByte(string(b), ')'); i >= 0 && i+2 < len(b) && b[i+2] == 'Z' {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

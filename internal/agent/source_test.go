// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestConverging(t *testing.T) {
	for _, c := range []struct {
		pages, prev, target int64
		left                int
		want                bool
	}{
		{1000, 2000, 2000, 3, true},          // already there
		{1900, 2000, 100, 8, false},          // < 20 % per round
		{514_000, 857_000, 10_000, 5, false}, // 8 GiB at 50 MB/s: 0.6 per round needs ~8 rounds
		{100_000, 857_000, 10_000, 5, true},  // 0.12 per round: two more
		{100_000, 857_000, 10_000, 0, false}, // no round left
	} {
		if got := converging(c.pages, c.prev, c.target, c.left); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

// The pod's own /dev/shm is read through a container without a volume
// there; an emptyDir at /dev/shm travels as an emptyDir, a hostIPC pod's
// is the host's.
func TestDevShmOf(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", VolumeMounts: []corev1.VolumeMount{{Name: "shm", MountPath: "/dev/shm/"}}},
		{Name: "sidecar"},
	}}}
	cs := []*srcContainer{{name: "app", pid: 10}, {name: "sidecar", pid: 20}}
	if got := devShmOf(pod, cs); got != "/proc/20/root/dev/shm" {
		t.Errorf("got %q, want the sidecar's", got)
	}
	pod.Spec.Containers[1].VolumeMounts = []corev1.VolumeMount{{Name: "dev", MountPath: "/dev"}}
	if got := devShmOf(pod, cs); got != "" {
		t.Errorf("every container mounts a volume there: %q", got)
	}
	pod.Spec.Containers[1].VolumeMounts = nil
	pod.Spec.HostIPC = true
	if got := devShmOf(pod, cs); got != "" {
		t.Errorf("hostIPC: %q", got)
	}
}

// A pre-dump that could not freeze the processes starts over (bounded);
// other failures end the pre-copy as before.
func TestDumpRetrying(t *testing.T) {
	defer func(w time.Duration) { preDumpRetryWait = w }(preDumpRetryWait)
	preDumpRetryWait = time.Millisecond
	stuck := &criuFailure{op: "pre-dump", err: errors.New("exit status 1"),
		summary: "Timeout reached. Try to interrupt: 0; Unseizable non-zombie 46025 found, state D, err -1/4"}
	run := func(fails int, failure error) (calls, cleans int, err error) {
		_, err = dumpRetrying(context.Background(), func() (DumpResult, error) {
			calls++
			if calls <= fails {
				return DumpResult{}, failure
			}
			return DumpResult{Pages: 1}, nil
		}, func() error { cleans++; return nil }, slog.New(slog.DiscardHandler))
		return calls, cleans, err
	}
	if calls, cleans, err := run(1, stuck); err != nil || calls != 2 || cleans != 1 {
		t.Errorf("one stuck round: calls %d cleans %d err %v", calls, cleans, err)
	}
	if calls, _, err := run(10, stuck); err == nil || calls != 1+preDumpRetries {
		t.Errorf("always stuck: calls %d err %v", calls, err)
	}
	other := &criuFailure{op: "pre-dump", err: errors.New("exit status 1"), summary: "anon_inode:[io_uring]"}
	if calls, _, err := run(1, other); err == nil || calls != 1 {
		t.Errorf("another failure is not retried: calls %d err %v", calls, err)
	}
}

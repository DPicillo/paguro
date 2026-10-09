// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"paguro.dev/paguro/internal/criulog"
)

// RuncState is the output of "runc state".
type RuncState struct {
	ID     string `json:"id"`
	Pid    int    `json:"pid"`
	Status string `json:"status"` // created | running | paused | stopped
	Bundle string `json:"bundle"`
	Rootfs string `json:"rootfs"`
	// Annotations carry the CRI identity (io.kubernetes.cri.sandbox-id, ...).
	Annotations map[string]string `json:"annotations"`
}

func (h *Host) State(ctx context.Context, id string) (*RuncState, error) {
	out, err := h.Runc(ctx, "state", id)
	if err != nil {
		return nil, err
	}
	st := &RuncState{}
	return st, json.Unmarshal(out, st)
}

// DumpKind distinguishes pre-copy rounds from the final dump.
type DumpKind int

const (
	PreDump DumpKind = iota
	FinalDump
)

// DumpRequest describes a CRIU run via runc.
type DumpRequest struct {
	ContainerID string
	ImageDir    string // absolute path on the host
	ParentDir   string // previous round ("" = none)
	WorkDir     string
	Kind        DumpKind
	TCP         bool
	FileLocks   bool
	ExtUnixSk   bool
	// LinkRemap lets CRIU dump files that are open under an NFS silly
	// rename (.nfsXXXX: deleted while open) as hard links (final dump
	// only; see relinkRemaps).
	LinkRemap bool
}

// DumpResult holds the measurements of one round.
type DumpResult struct {
	Pages    int64 // 4 KiB pages written
	Bytes    int64 // size of all image files
	Duration time.Duration
}

// Dump runs runc checkpoint.
//
// Pre-dump: freezes only briefly (to collect the memory maps), the app keeps
// running afterwards; the kernel tracks via the soft-dirty bit which pages it
// writes after that.
//
// Final dump: runs on a paused container with --leave-running. At the end,
// CRIU restores the freezer state it found – so the container stays frozen.
// This guarantees that not a single write happens after the dump (no PVC
// write, no network packet), while kubelet does not see a terminated
// container that it would restart. A rollback is then just "runc resume".
func (h *Host) Dump(ctx context.Context, r DumpRequest) (DumpResult, error) {
	if err := os.MkdirAll(h.Path(r.ImageDir), 0o700); err != nil {
		return DumpResult{}, err
	}
	if err := os.MkdirAll(h.Path(r.WorkDir), 0o700); err != nil {
		return DumpResult{}, err
	}
	args := []string{"checkpoint", "--image-path", r.ImageDir, "--work-path", r.WorkDir, "--manage-cgroups-mode", "soft"}
	if r.ParentDir != "" {
		rel, err := filepath.Rel(r.ImageDir, r.ParentDir)
		if err != nil {
			return DumpResult{}, err
		}
		args = append(args, "--parent-path", rel)
	}
	switch r.Kind {
	case PreDump:
		args = append(args, "--pre-dump")
	case FinalDump:
		args = append(args, "--leave-running")
		if r.TCP {
			args = append(args, "--tcp-established")
		}
		if r.FileLocks {
			args = append(args, "--file-locks")
		}
		if r.ExtUnixSk {
			args = append(args, "--ext-unix-sk")
		}
		if r.LinkRemap {
			args = append(args, "--link-remap")
		}
	}
	args = append(args, r.ContainerID)

	start := time.Now()
	_, err := h.Runc(ctx, args...)
	res := DumpResult{Duration: time.Since(start)}
	if err != nil {
		// runc names CRIU's log dump.log for pre-dumps too.
		b, _ := os.ReadFile(h.Path(filepath.Join(r.WorkDir, "dump.log")))
		op := "dump"
		if r.Kind == PreDump {
			op = "pre-dump"
		}
		// CRIU's error lines can sit anywhere in a verbose log: summarize
		// the whole log, keep only its tail for the agent's log.
		return res, &criuFailure{op: op, err: err, summary: criulog.Summary(string(b)), log: tail(string(b), 2000)}
	}
	res.Pages, res.Bytes = imageStats(h.Path(r.ImageDir))
	return res, nil
}

// criuFailure is a failed runc checkpoint. Error() is short – CRIU's own
// error messages and a hint – because it ends up in the Migration status;
// the runc error (command line, output) and the CRIU log tail are for the
// agent's log.
type criuFailure struct {
	op      string // "dump", "pre-dump"
	err     error
	summary string // CRIU's error lines and a hint (criulog.Summary)
	log     string // tail of the CRIU log
}

func (f *criuFailure) Error() string {
	if f.summary != "" {
		return "criu " + f.op + ": " + f.summary
	}
	if s := criulog.Summary(f.err.Error()); s != "" {
		return "criu " + f.op + ": " + s
	}
	return "criu " + f.op + " failed: " + tail(f.err.Error(), 300)
}

func (f *criuFailure) Unwrap() error { return f.err }

// imageStats counts the pages (pages-*.img) and the total size.
func imageStats(dir string) (pages, bytes int64) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		bytes += fi.Size()
		if strings.HasPrefix(e.Name(), "pages-") && strings.HasSuffix(e.Name(), ".img") {
			pages += fi.Size() / pageSize
		}
	}
	return
}

func (h *Host) Pause(ctx context.Context, id string) error {
	_, err := h.Runc(ctx, "pause", id)
	return err
}

func (h *Host) Resume(ctx context.Context, id string) error {
	st, err := h.State(ctx, id)
	if err == nil && st.Status != "paused" {
		return nil
	}
	_, err = h.Runc(ctx, "resume", id)
	return err
}

// ---------------------------------------------------------------------------
// Auto-converge: CPU throttling via cgroup v2 cpu.max
// ---------------------------------------------------------------------------

// cgroupDir returns the cgroup v2 directory of a process (host view). The
// agent pod has its own cgroup namespace; /proc/<pid>/cgroup must therefore
// be read in the host namespace (nsenter -C), otherwise the paths are wrong.
func (h *Host) cgroupDir(ctx context.Context, pid int) (string, error) {
	b, err := h.Run(ctx, nil, "cat", fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(b))
	i := strings.LastIndex(line, "::")
	if i < 0 {
		return "", fmt.Errorf("no cgroup v2 entry: %q", line)
	}
	return filepath.Join("/sys/fs/cgroup", line[i+2:]), nil
}

// Throttle remembers the original cpu.max value so that it is restored
// exactly. The target container gets its cgroup fresh from the pod spec
// anyway – a throttle does not migrate along.
type Throttle struct {
	h        *Host
	file     string
	original string
}

// NewThrottle prepares the throttle for the process's cgroup.
func (h *Host) NewThrottle(ctx context.Context, pid int) (*Throttle, error) {
	dir, err := h.cgroupDir(ctx, pid)
	if err != nil {
		return nil, err
	}
	f := filepath.Join(dir, "cpu.max")
	b, err := h.Run(ctx, nil, "cat", f)
	if err != nil {
		return nil, err
	}
	return &Throttle{h: h, file: f, original: strings.TrimSpace(string(b))}, nil
}

// Set throttles to pct percent of the current CPU quota (100 = no
// throttling). Without a quota ("max"), the number of CPUs of the node is
// used as the base.
func (t *Throttle) Set(ctx context.Context, pct int) error {
	if pct >= 100 {
		return t.Restore(ctx)
	}
	quota, period := int64(runtime.NumCPU())*100000, int64(100000)
	if f := strings.Fields(t.original); len(f) == 2 {
		if p, err := strconv.ParseInt(f[1], 10, 64); err == nil && p > 0 {
			period = p
			quota = int64(runtime.NumCPU()) * p
		}
		if q, err := strconv.ParseInt(f[0], 10, 64); err == nil && q > 0 {
			quota = q
		}
	}
	q := quota * int64(pct) / 100
	if q < 1000 {
		q = 1000 // kernel minimum
	}
	return t.write(ctx, fmt.Sprintf("%d %d", q, period))
}

func (t *Throttle) Restore(ctx context.Context) error { return t.write(ctx, t.original) }

// throttleFile is where a container's original CPU quota is kept, relative
// to the migration's dump directory.
func throttleFile(container string) string {
	return filepath.Join("containers", container, "cpu.max.orig")
}

// Persist records the original quota (local path), so that a restarted
// agent can undo a throttle it no longer remembers (RestoreThrottle).
func (t *Throttle) Persist(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(t.file+"\n"+t.original+"\n"), 0o600)
}

// RestoreThrottle undoes a throttle recorded at path (local path) and
// removes the record; no record is no error.
func (h *Host) RestoreThrottle(ctx context.Context, path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f := strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)
	if len(f) != 2 || !strings.HasPrefix(f[0], "/sys/fs/cgroup/") {
		return fmt.Errorf("%s: not a throttle record", path)
	}
	if err := (&Throttle{h: h, file: f[0], original: strings.TrimSpace(f[1])}).Restore(ctx); err != nil {
		return err
	}
	return os.Remove(path)
}

func (t *Throttle) write(ctx context.Context, v string) error {
	_, err := t.h.Run(ctx, []byte(v), "tee", t.file)
	return err
}

// CgroupPids returns the processes in the cgroup of pid (just pid if the
// cgroup cannot be read).
func (h *Host) CgroupPids(ctx context.Context, pid int) []int {
	dir, err := h.cgroupDir(ctx, pid)
	if err != nil {
		return []int{pid}
	}
	procs, err := h.Run(ctx, nil, "cat", filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return []int{pid}
	}
	var out []int
	for _, l := range strings.Fields(string(procs)) {
		if p, err := strconv.Atoi(l); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// TreeRSS sums VmRSS over all processes in the cgroup of pid.
func (h *Host) TreeRSS(ctx context.Context, pid int) int64 {
	var total int64
	for _, p := range h.CgroupPids(ctx, pid) {
		total += RSS(p)
	}
	return total
}

func sortStrings(s []string) { sort.Strings(s) }

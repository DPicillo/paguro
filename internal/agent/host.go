// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 David Picillo

package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"paguro.dev/paguro/pkg/names"
)

// Host encapsulates access to the node. The agent runs privileged with
// hostPID; it starts host programs (runc, criu, nft, crictl) via nsenter in
// the mount namespace of PID 1 so that they see exactly the mounts containerd
// sees. It reads host files via /proc/1/root.
type Host struct {
	// Root is the prefix for host paths ("/proc/1/root" in the pod, "" directly
	// on the host).
	Root string
	// Nsenter sends commands into the host mount namespace via nsenter.
	Nsenter  bool
	RuncRoot string
	// RuntimeContext, if set, is the SELinux context checkpoints run in
	// (Bottlerocket: containerd's, runtime_t:s0:c0.c1023). CRIU's parasite
	// runs inside the container and writes the memory into CRIU's pipes; a
	// pipe of the agent's own context (super_t there) is closed to
	// containers, one of the runtime's is not – and with every MCS category
	// CRIU may write the container's /proc files (clear_refs). systemd
	// starts the dump in that context.
	RuntimeContext string
}

func (h *Host) Path(p string) string { return filepath.Join(h.Root, p) }

// Run executes a host command and returns stdout+stderr.
func (h *Host) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	if h.Nsenter {
		argv = append([]string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "-C", "--"}, argv...)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if h.Nsenter {
		// nsenter looks the program up in the host's file system with our
		// PATH; the bundle's tools come after the host's own.
		cmd.Env = withBundlePath(os.Environ())
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, tail(out.String(), 600))
	}
	return out.Bytes(), nil
}

// ShieldRunner adapts Host.Run to the signature of shield.Runner.
func (h *Host) ShieldRunner(ctx context.Context) func(stdin, name string, args ...string) (string, error) {
	return func(stdin, name string, args ...string) (string, error) {
		var in []byte
		if stdin != "" {
			in = []byte(stdin)
		}
		out, err := h.Run(ctx, in, name, args...)
		return string(out), err
	}
}

// Runc runs runc against containerd's state root.
func (h *Host) Runc(ctx context.Context, args ...string) ([]byte, error) {
	return h.Run(ctx, nil, "runc", append([]string{"--root", h.RuncRoot}, args...)...)
}

// RuncAsRuntime runs runc in RuntimeContext if one is set, else like Runc.
// A transient systemd unit enters the context: systemd may, the agent may
// not. The unit gets no pipe of ours (systemd-run --pipe hands them over
// the bus, which may not use a pipe of the agent's context either); it
// writes runc's output into a file under RunDir. As with Runc, a canceled
// context leaves a running dump to finish – stopping CRIU halfway could
// leave the container frozen.
func (h *Host) RuncAsRuntime(ctx context.Context, args ...string) ([]byte, error) {
	if h.RuntimeContext == "" {
		return h.Runc(ctx, args...)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	unit := "paguro-runc-" + hex.EncodeToString(id[:])
	if err := os.MkdirAll(h.Path(names.RunDir), 0o700); err != nil {
		return nil, err
	}
	outFile := filepath.Join(names.RunDir, unit+".out")
	defer os.Remove(h.Path(outFile))
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, e := range withBundlePath(os.Environ()) {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			path = v
		}
	}
	argv := append([]string{"--wait", "--quiet", "--collect", "--unit=" + unit,
		"--property=SELinuxContext=" + h.RuntimeContext,
		"--property=StandardOutput=truncate:" + outFile, "--property=StandardError=inherit",
		"--setenv=PATH=" + path, "--", "runc", "--root", h.RuncRoot}, args...)
	_, err := h.Run(ctx, nil, "systemd-run", argv...)
	out, _ := os.ReadFile(h.Path(outFile))
	if err != nil {
		return out, fmt.Errorf("runc %s (unit %s): %w: %s", strings.Join(args, " "), unit, err, tail(string(out), 600))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// /proc helpers
// ---------------------------------------------------------------------------

// RSS returns the VmRSS of a process in bytes.
func RSS(pid int) int64 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "VmRSS:"); ok {
			kb, _ := strconv.ParseInt(strings.Fields(v)[0], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// UpperDir reads the overlay upperdir of the container process's root
// filesystem (the writable layer) from its mountinfo.
func UpperDir(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		// 36 35 0:42 / / rw,relatime - overlay overlay rw,lowerdir=…,upperdir=…,workdir=…
		pre, post, ok := strings.Cut(s.Text(), " - ")
		if !ok {
			continue
		}
		f := strings.Fields(pre)
		if len(f) < 5 || f[4] != "/" {
			continue
		}
		pf := strings.Fields(post)
		if len(pf) < 3 || pf[0] != "overlay" {
			continue
		}
		for _, opt := range strings.Split(pf[2], ",") {
			if v, ok := strings.CutPrefix(opt, "upperdir="); ok {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("no overlay root for pid %d", pid)
}

// CPUInfo returns the model name and the sorted flags of the first CPU
// ("flags" on x86, "Features" on arm64).
func CPUInfo() (model string, flags []string) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name":
			if model == "" {
				model = v
			}
		case "flags", "Features": // x86, arm64
			if flags == nil {
				flags = strings.Fields(v)
			}
		}
		if model != "" && flags != nil {
			break
		}
	}
	return model, sortUnique(flags)
}

func sortUnique(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sortStrings(out)
	return out
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func ms(d time.Duration) int64 { return d.Milliseconds() }

// MountTypes maps mount points to filesystem types, from a mountinfo file.
func MountTypes(mountinfo string) (map[string]string, error) {
	f, err := os.Open(mountinfo)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMountTypes(f), nil
}

func parseMountTypes(r io.Reader) map[string]string {
	out := map[string]string{}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		// 36 35 0:42 /pvc-1 /var/lib/kubelet/…/mount rw,relatime shared:1 - nfs4 10.0.0.1:/pvc-1 rw,…
		pre, post, ok := strings.Cut(s.Text(), " - ")
		if !ok {
			continue
		}
		f, pf := strings.Fields(pre), strings.Fields(post)
		if len(f) < 5 || len(pf) < 1 {
			continue
		}
		out[unescapeMount(f[4])] = pf[0]
	}
	return out
}

// unescapeMount decodes the octal escapes of mountinfo (\040 for a space).
func unescapeMount(p string) string {
	if !strings.Contains(p, `\`) {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+3 < len(p) {
			if v, err := strconv.ParseUint(p[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// SharedFS reports whether a filesystem type is a network or FUSE
// filesystem that other nodes may mount at the same time (RWX volumes).
func SharedFS(fstype string) bool {
	switch {
	case fstype == "nfs", fstype == "nfs4", fstype == "ceph", fstype == "cifs", fstype == "smb3",
		fstype == "glusterfs", fstype == "lustre", fstype == "gpfs", fstype == "9p", fstype == "virtiofs":
		return true
	case strings.HasPrefix(fstype, "fuse"): // fuse, fuse.s3fs, fuse.juicefs, …
		return true
	}
	return false
}

// withBundlePath appends the node installer's bin directory to PATH in env.
func withBundlePath(env []string) []string {
	out := make([]string, 0, len(env)+1)
	found := false
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			found = true
			if !slices.Contains(filepath.SplitList(v), names.BundleBin) {
				e += string(filepath.ListSeparator) + names.BundleBin
			}
		}
		out = append(out, e)
	}
	if !found {
		out = append(out, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"+names.BundleBin)
	}
	return out
}

// ContainerdContext returns the SELinux context of the containerd that
// serves the kubelet, read from proc (the host's /proc with hostPID): the
// process named containerd in the unit containerd.service – Bottlerocket
// runs a second one for its own host containers (host-containerd.service).
func ContainerdContext(proc string) (string, error) {
	dirs, _ := filepath.Glob(filepath.Join(proc, "[0-9]*"))
	for _, d := range dirs {
		comm, err := os.ReadFile(filepath.Join(d, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "containerd" {
			continue
		}
		cg, _ := os.ReadFile(filepath.Join(d, "cgroup"))
		if !slices.ContainsFunc(strings.Split(string(cg), "\n"), func(l string) bool {
			return strings.HasPrefix(l, "0::") && strings.HasSuffix(l, "/containerd.service")
		}) {
			continue
		}
		attr, err := os.ReadFile(filepath.Join(d, "attr", "current"))
		if err != nil {
			return "", err
		}
		if c := strings.TrimRight(string(attr), "\x00\n"); c != "" {
			return c, nil
		}
	}
	return "", fmt.Errorf("no containerd in containerd.service under %s", proc)
}

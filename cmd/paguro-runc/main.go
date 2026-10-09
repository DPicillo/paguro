// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// paguro-runc is an OCI runtime wrapper around runc.
//
// containerd invokes it through the "paguro" runtime handler exactly like
// runc. For almost every command it replaces itself with the real runc via
// execve – zero overhead, zero change in behaviour. It intervenes in only two
// cases, and only when the pod carries the paguro.dev/restore-id annotation:
//
//	create (sandbox)   → create normally, then raise the RST shield in the network namespace
//	create (container) → wait for the checkpoint, apply the rootfs/emptyDir
//	                     delta, run "runc restore --detach" instead of create
//	start  (restored)  → do nothing, the process is already running
//
// Why not containerd's built-in checkpoint/restore? It only knows "one
// archive, one restore": no pre-copy chain, no --tcp-established, no shield,
// no fallback to a cold start. It also requires the checkpoint to be stored
// as an OCI image in a registry.
//
// If the restore fails, the wrapper cold-starts the container. The memory
// state is lost in that case, but the application runs – with the data on
// its PVC. A migration must never end worse than an ordinary pod restart.
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"paguro.dev/paguro/internal/cpufeat"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/ocispec"
	"paguro.dev/paguro/internal/shield"
	"paguro.dev/paguro/pkg/names"
)

// waitForData is how long create waits for the data from the source agent.
// kubelet aborts CRI calls after runtime-request-timeout (default 2 min).
const waitForData = 100 * time.Second

func main() {
	args := os.Args[1:]
	inv := parse(args)

	switch inv.cmd {
	case "create":
		if code, handled := create(inv); handled {
			os.Exit(code)
		}
	case "start":
		if isRestored(inv.id) {
			logf("start %s: already restored, nothing to do", inv.id)
			os.Exit(0)
		}
	case "delete":
		_ = os.Remove(restoredMarker(inv.id))
	}
	execRunc(args)
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

type invocation struct {
	global      []string // everything before the subcommand
	cmd         string
	cmdArgs     []string // everything after the subcommand, without the ID
	id          string
	bundle      string
	pidFile     string
	logFile     string
	preserveFDs int
}

// globalWithValue lists the global runc flags that take a value.
var globalWithValue = map[string]bool{"--root": true, "--log": true, "--log-format": true, "--criu": true, "--rootless": true}

// createWithValue lists the create flags that take a value.
var createWithValue = map[string]bool{"--bundle": true, "-b": true, "--pid-file": true, "--console-socket": true, "--pidfd-socket": true, "--preserve-fds": true}

func parse(args []string) invocation {
	inv := invocation{}
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			break
		}
		inv.global = append(inv.global, a)
		name, val, hasVal := strings.Cut(a, "=")
		if globalWithValue[name] && !hasVal && i+1 < len(args) {
			i++
			val = args[i]
			inv.global = append(inv.global, val)
		}
		if name == "--log" {
			inv.logFile = val
		}
	}
	if i >= len(args) {
		return inv
	}
	inv.cmd = args[i]
	rest := args[i+1:]
	for j := 0; j < len(rest); j++ {
		a := rest[j]
		if !strings.HasPrefix(a, "-") {
			inv.id = a
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		if createWithValue[name] && !hasVal && j+1 < len(rest) {
			inv.cmdArgs = append(inv.cmdArgs, a, rest[j+1])
			val = rest[j+1]
			j++
		} else {
			inv.cmdArgs = append(inv.cmdArgs, a)
		}
		switch name {
		case "--bundle", "-b":
			inv.bundle = val
		case "--pid-file":
			inv.pidFile = val
		case "--preserve-fds":
			inv.preserveFDs, _ = strconv.Atoi(val)
		}
	}
	if inv.bundle == "" && inv.cmd == "create" {
		inv.bundle, _ = os.Getwd()
	}
	return inv
}

// ---------------------------------------------------------------------------
// create
// applyCPUBaseline starts a container with the common runtimes limited to
// the pod's CPU baseline (internal/cpufeat): features of this host outside
// it are switched off in glibc, Go, OpenSSL, the JVM, .NET and PyTorch, so
// the pod's processes can later continue on a node without them. A restored
// process keeps the environment it was started with; this matters for first
// starts and cold starts.
func applyCPUBaseline(inv invocation, spec *ocispec.Spec) {
	b := spec.Ann(names.AnnotationCPUBaseline)
	if b == "" {
		return
	}
	host, err := cpufeat.HostFlags()
	if err != nil {
		logf("container %s: CPU baseline not applied: %v", inv.id, err)
		return
	}
	masked := cpufeat.Masked(host, cpufeat.Parse(b))
	if len(masked) == 0 {
		return
	}
	set, err := ocispec.EditEnv(inv.bundle, func(env []string) ([]string, []string) { return cpufeat.Env(env, masked) })
	if err != nil {
		logf("container %s: CPU baseline not applied: %v", inv.id, err)
		return
	}
	logf("container %s: CPU features outside the baseline switched off (%s) via %s",
		inv.id, strings.Join(masked, ","), strings.Join(set, ","))
}

// ---------------------------------------------------------------------------

// create returns (exit code, true) when the wrapper handled the call itself;
// (0, false) means "pass through to runc".
func create(inv invocation) (int, bool) {
	spec, err := ocispec.Load(inv.bundle)
	if err != nil {
		return 0, false
	}
	// Every app container under Paguro gets its own time namespace – including
	// the first start on the source; otherwise there would later be nothing
	// from which CRIU could continue the clock.
	if spec.Ann(ocispec.AnnContainerType) == ocispec.TypeContainer {
		if changed, err := ocispec.EnsureTimeNamespace(inv.bundle); err != nil {
			logf("container %s: time namespace not set: %v", inv.id, err)
		} else if changed {
			logf("container %s: own time namespace", inv.id)
		}
		applyCPUBaseline(inv, spec)
	}
	// Every sandbox under Paguro gets MPTCP disabled in its network namespace.
	// CRIU cannot checkpoint MPTCP sockets ("inet: Unsupported proto 262"),
	// and Go >= 1.24 opens listeners as MPTCP by default when the kernel
	// allows it – the final dump would fail at freeze time. With
	// net.mptcp.enabled=0, socket(IPPROTO_MPTCP) fails and applications
	// (Go included) transparently fall back to plain TCP. The netns already
	// exists here: containerd runs CNI before creating the sandbox container.
	sandboxStart := time.Now()
	if spec.Ann(ocispec.AnnContainerType) == ocispec.TypeSandbox {
		if ns := spec.NetNSPath(); ns != "" {
			if _, err := shield.Exec("", "nsenter", "--net="+ns, "sysctl", "-q", "-w", "net.mptcp.enabled=0"); err != nil {
				logf("sandbox %s: could not disable MPTCP: %v", inv.id, err)
			}
		}
	}
	uid := spec.Ann(names.AnnotationRestoreID)
	if uid == "" {
		return 0, false
	}

	switch spec.Ann(ocispec.AnnContainerType) {
	case ocispec.TypeSandbox:
		// Create the sandbox normally; afterwards the network namespace exists
		// with the (old) pod IP. Shield it immediately, before a client
		// retransmit hits a kernel without a socket.
		mptcpDone := time.Now()
		code := runRunc(inv.global, "create", inv.cmdArgs, inv.id, inv.preserveFDs)
		createDone := time.Now()
		if code == 0 && !layout.RestorePending(uid) {
			// A pod keeps its restore annotations for life. When its sandbox
			// is created again later (node reboot, sandbox crash), the
			// restore is long done: no shield, or nobody would lower it.
			logf("sandbox %s: restore %s already done – no shield", inv.id, uid)
			return code, true
		}
		if code == 0 {
			_ = os.MkdirAll(layout.Root(uid), 0o700)
			// The netns path first: an agent that sees the sandbox marker
			// may need it right away (Phantom mode programs the new pod).
			_ = os.WriteFile(filepath.Join(layout.Root(uid), names.FileSandboxNetns), []byte(spec.NetNSPath()), 0o600)
			_ = os.WriteFile(filepath.Join(layout.Root(uid), names.FileSandbox), []byte(time.Now().Format(time.RFC3339Nano)), 0o600)
			if ns := spec.NetNSPath(); ns != "" {
				if err := shield.Raise(shield.Exec, ns); err != nil {
					logf("sandbox %s: could not raise shield: %v", inv.id, err)
				} else {
					logf("sandbox %s: shield raised in %s (mptcp %d ms, runc create %d ms, shield %d ms)", inv.id, ns,
						mptcpDone.Sub(sandboxStart).Milliseconds(), createDone.Sub(mptcpDone).Milliseconds(), time.Since(createDone).Milliseconds())
				}
			}
		}
		return code, true

	case ocispec.TypeContainer:
		return restoreContainer(inv, spec, uid), true
	}
	return 0, false
}

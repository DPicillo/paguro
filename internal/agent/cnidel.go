// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/version"
)

// Releasing the frozen source's network before its sandbox is stopped.
//
// With a kept IP on Calico the replacement gets the address only after the
// source's CNI DEL. Stopping the sandbox (crictl stopp) first kills the
// frozen containers and the pause container and only then runs the CNI –
// measured 0.32 s of kills and shim cleanup before Calico's DEL (0.23 s).
// After the commit the frozen process never runs again, so its network can
// go first: Paguro runs the CNI DEL itself, exactly as containerd would –
// the network list, namespace and arguments containerd cached when it set
// the sandbox up (/var/lib/cni/results). The sandbox stop that follows runs
// DEL again, which every CNI plugin must tolerate.

// cniBinDirs are searched for the plugins (containerd's default first).
var cniBinDirs = []string{"/opt/cni/bin", "/usr/libexec/cni", "/usr/lib/cni"}

// cniCacheDir is where containerd's CNI library caches attachments.
var cniCacheDir = "/var/lib/cni" // a variable for the tests

// releaseNetwork runs CNI DEL for every network attachment of the sandbox.
// Reports whether at least one was released and none failed.
func (a *Agent) releaseNetwork(ctx context.Context, sandboxID string) (bool, error) {
	if sandboxID == "" {
		return false, fmt.Errorf("no sandbox id")
	}
	cni := libcni.NewCNIConfigWithCacheDir(cniBinDirs, a.Host.Path(cniCacheDir), hostExec{a.Host})
	atts, err := cni.GetCachedAttachments(sandboxID)
	if err != nil {
		return false, fmt.Errorf("reading the CNI cache: %w", err)
	}
	released := 0
	for _, att := range atts {
		// libcni caches the network list's bytes with each attachment.
		conf, err := libcni.ConfListFromBytes(att.Config)
		if err != nil {
			return released > 0, fmt.Errorf("cached config of %s: %w", att.Network, err)
		}
		if conf.Name == "cni-loopback" {
			continue // nothing to release
		}
		rt := &libcni.RuntimeConf{
			ContainerID: att.ContainerID, NetNS: att.NetNS, IfName: att.IfName,
			Args: att.CniArgs, CapabilityArgs: att.CapabilityArgs,
		}
		if err := cni.DelNetworkList(ctx, conf, rt); err != nil {
			return released > 0, fmt.Errorf("CNI DEL %s: %w", att.Network, err)
		}
		released++
	}
	if released == 0 {
		return false, fmt.Errorf("no cached network attachment for sandbox %s", sandboxID)
	}
	return true, nil
}

// hostExec runs CNI plugins on the host (its mount and network namespace),
// the way containerd does.
type hostExec struct{ h *Host }

func (e hostExec) ExecPlugin(ctx context.Context, pluginPath string, stdin []byte, environ []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	argv := append([]string{"env", "-i"}, environ...)
	argv = append(argv, pluginPath)
	if e.h.Nsenter {
		argv = append([]string{"nsenter", "-t", "1", "-m", "-n", "--"}, argv...)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// A plugin reports its error as JSON on stdout.
		if msg := bytes.TrimSpace(stdout.Bytes()); len(msg) > 0 {
			return nil, fmt.Errorf("%s: %s", filepath.Base(pluginPath), msg)
		}
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(pluginPath), err, lastLine(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (e hostExec) FindInPath(plugin string, paths []string) (string, error) {
	for _, p := range paths {
		full := filepath.Join(p, plugin)
		if fi, err := os.Stat(e.h.Path(full)); err == nil && fi.Mode().IsRegular() {
			return full, nil
		}
	}
	return "", fmt.Errorf("CNI plugin %s not found in %v", plugin, paths)
}

func (e hostExec) Decode(b []byte) (version.PluginInfo, error) {
	return (&version.PluginDecoder{}).Decode(b)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Calling the real runc, and the wrapper's own log.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

var runcCandidates = []string{"/usr/local/sbin/runc", "/usr/local/bin/runc", "/usr/sbin/runc", "/usr/bin/runc"}

func runcPath() string {
	if p := os.Getenv("PAGURO_RUNC"); p != "" {
		return p
	}
	if b, err := os.ReadFile("/etc/paguro/runc-path"); err == nil {
		if p := strings.TrimSpace(string(b)); p != "" {
			return p
		}
	}
	self, _ := os.Executable()
	for _, c := range runcCandidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && c != self {
			return c
		}
	}
	return "runc"
}

// execRunc replaces the process with runc (the normal case, no overhead).
func execRunc(args []string) {
	p := runcPath()
	err := syscall.Exec(p, append([]string{"runc"}, args...), os.Environ())
	fmt.Fprintf(os.Stderr, "paguro-runc: exec %s: %v\n", p, err)
	os.Exit(127)
}

// runRunc starts runc as a child process with our stdio descriptors. These
// are the pipes of the containerd shim – runc restore attaches them to the
// restored processes based on descriptors.json (so stdout/stderr end up in
// the container log again).
func runRunc(global []string, cmd string, cmdArgs []string, id string, preserveFDs int) int {
	argv := append(append(append([]string{}, global...), cmd), cmdArgs...)
	if id != "" {
		argv = append(argv, id)
	}
	c := exec.Command(runcPath(), argv...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	for i := 0; i < preserveFDs; i++ {
		c.ExtraFiles = append(c.ExtraFiles, os.NewFile(uintptr(3+i), "preserved"))
	}
	if err := c.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		logf("runc %s: %v", cmd, err)
		return 1
	}
	return 0
}

func logf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	_ = os.MkdirAll("/var/log/paguro", 0o755)
	if f, err := os.OpenFile("/var/log/paguro/paguro-runc.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%s [%d] %s\n", time.Now().Format(time.RFC3339Nano), os.Getpid(), line)
		f.Close()
	}
	// On errors containerd reads the runc log (--log, JSON) and shows the last
	// message in the pod event – so the user sees the reason directly in
	// "kubectl describe pod".
	if logFile := currentLogFile(); logFile != "" {
		if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			b, _ := json.Marshal(map[string]string{"level": "info", "msg": "paguro: " + line, "time": time.Now().Format(time.RFC3339Nano)})
			f.Write(append(b, '\n'))
			f.Close()
		}
	}
}

func currentLogFile() string {
	return parse(os.Args[1:]).logFile
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package criulog turns CRIU logs into messages a user can act on.
//
// When CRIU fails, runc reports little more than an exit status and its own
// command line; the reason is in CRIU's log (dump.log, restore.log), among
// hundreds of debug lines. Errors picks CRIU's own error messages, Hint adds
// what to do about the ones Paguro knows.
package criulog

import (
	"regexp"
	"slices"
	"strings"
)

// errorLine matches CRIU's error lines, in its own log
//
//	(00.025877) Error (criu/sk-inet.c:137): inet: Unsupported proto 262 for socket 262b3
//
// and as runc relays them (level=warning msg="522:(00.038859) Error (...): ...").
var errorLine = regexp.MustCompile(`Error \([^)]*\): (.*?)"?$`)

// generic matches summary lines that carry no reason.
var generic = regexp.MustCompile(`^(Dumping|Pre-dumping|Restoring) FAILED|^Dump files \(pid: \d+\) failed`)

// Errors returns CRIU's distinct error messages from log in order, without
// timestamps, source locations and summary lines; at most max.
func Errors(log string, max int) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		m := errorLine.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		msg := strings.TrimSpace(m[1])
		if msg == "" || generic.MatchString(msg) || slices.Contains(out, msg) {
			continue
		}
		if out = append(out, msg); len(out) == max {
			break
		}
	}
	return out
}

// hints map known CRIU errors to what the user can do.
var hints = []struct {
	re   *regexp.Regexp
	hint string
}{
	{regexp.MustCompile(`Unsupported proto 262\b`), MPTCPHint},
	{regexp.MustCompile(`anon_inode:\[io_uring\]`), IOUringHint},
}

// IOUringHint explains the io_uring case: CRIU cannot checkpoint io_uring
// instances (Node.js' libuv, PostgreSQL 18 and Rust runtimes can use them).
const IOUringHint = "CRIU cannot checkpoint io_uring instances: run the application without io_uring " +
	"(Node.js: UV_USE_IO_URING=0; PostgreSQL 18: io_method=worker) or disable io_uring on the nodes " +
	"(sysctl kernel.io_uring_disabled=2)"

// MPTCPHint explains the MPTCP case: CRIU cannot checkpoint Multipath TCP
// sockets, and Go >= 1.24 opens listeners as MPTCP by default when the
// kernel allows it.
const MPTCPHint = "CRIU cannot checkpoint Multipath TCP sockets (Go >= 1.24 listens with MPTCP by default): " +
	"set the label paguro.dev/migratable=true in the pod template and restart the pod once – " +
	"Paguro then disables MPTCP in its network namespace – or set GODEBUG=multipathtcp=0"

// Hint returns advice for the first known error, "" if none is known.
func Hint(errs []string) string {
	for _, e := range errs {
		for _, h := range hints {
			if h.re.MatchString(e) {
				return h.hint
			}
		}
	}
	return ""
}

// Summary condenses a CRIU log into one line: its first error messages
// and, if known, a hint. "" if the log holds no error message.
func Summary(log string) string {
	errs := Errors(log, 3)
	if len(errs) == 0 {
		return ""
	}
	s := strings.Join(errs, "; ")
	if h := Hint(errs); h != "" {
		s += " – " + h
	}
	return s
}

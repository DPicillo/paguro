// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criulog

import (
	"strings"
	"testing"
)

// A real dump.log excerpt (final dump of a Go 1.26 echo server).
const dumpLog = `(00.025860) Dumping socket 262b3
(00.025877) Error (criu/sk-inet.c:137): inet: Unsupported proto 262 for socket 262b3
(00.025905) Error (criu/sk-inet.c:139): inet: For Go programs, consider using "GODEBUG=multipathtcp=0" to disable MPTCP
(00.025946) Error (criu/cr-dump.c:1545): Dump files (pid: 42838) failed with -1
(00.026540) Running network-unlock scripts
(00.038859) Error (criu/cr-dump.c:1975): Dumping FAILED.
`

// The same error as runc relays it on stderr.
const runcOutput = `time="2026-10-02T19:20:26Z" level=warning msg="518:(00.026540) Running network-unlock scripts"
time="2026-10-02T19:20:26Z" level=warning msg="522:(00.038859) Error (criu/cr-dump.c:1975): Dumping FAILED."
time="2026-10-02T19:20:26Z" level=warning msg="510:(00.025877) Error (criu/sk-inet.c:137): inet: Unsupported proto 262 for socket 262b3"
time="2026-10-02T19:20:26Z" level=error msg="criu failed: type DUMP errno 0"
`

func TestErrors(t *testing.T) {
	got := Errors(dumpLog, 5)
	want := []string{
		"inet: Unsupported proto 262 for socket 262b3",
		`inet: For Go programs, consider using "GODEBUG=multipathtcp=0" to disable MPTCP`,
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("Errors = %q, want %q", got, want)
	}
	if got := Errors(dumpLog, 1); len(got) != 1 {
		t.Fatalf("max not honored: %q", got)
	}
	if got := Errors(runcOutput, 5); len(got) != 1 || got[0] != "inet: Unsupported proto 262 for socket 262b3" {
		t.Fatalf("runc output: %q", got)
	}
	if got := Errors("(00.1) Warn (criu/x.c:1): nothing\n", 5); got != nil {
		t.Fatalf("warnings are not errors: %q", got)
	}
}

func TestSummary(t *testing.T) {
	s := Summary(dumpLog)
	if !strings.HasPrefix(s, "inet: Unsupported proto 262 for socket 262b3; ") || !strings.HasSuffix(s, " – "+MPTCPHint) {
		t.Fatalf("Summary = %q", s)
	}
	if s := Summary("(00.1) Error (criu/files-reg.c:1): File /data/x has bad size 10 (expect 20)\n"); s != "File /data/x has bad size 10 (expect 20)" {
		t.Fatalf("unknown error: %q", s)
	}
	if s := Summary("no errors here"); s != "" {
		t.Fatalf("no error: %q", s)
	}
}

func TestIOUringHint(t *testing.T) {
	log := "(00.031) Error (criu/files.c:513): Can't dump file 5 of that type [600] anon_inode:[io_uring]\n"
	if s := Summary(log); !strings.HasSuffix(s, " – "+IOUringHint) {
		t.Fatalf("Summary = %q", s)
	}
}

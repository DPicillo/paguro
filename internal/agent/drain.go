// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"paguro.dev/paguro/internal/shield"
)

// drainMax bounds the drain: an application that does not accept its
// connections in time fails the final dump, and the migration rolls back.
const drainMax = 200 * time.Millisecond

// drain lets the pod finish its pending TCP handshakes and accept them
// before the freeze (shield.RaiseDrain): new connection requests are
// dropped – the clients retry, as they would during the freeze – while
// handshakes in progress complete and the application accepts them.
// Measured without it: a connection waiting in the accept queue at the
// freeze made CRIU refuse the final dump ("In-flight connection"), with a
// fresh connection every 25 ms in 1 of 7 migrations. Best effort.
func (j *sourceJob) drain(ctx context.Context) {
	if len(j.cs) == 0 || j.cs[0].pid == 0 {
		return
	}
	j.mu.Lock()
	j.drained = true // thaw lowers it again
	j.mu.Unlock()
	start := time.Now()
	// Not cancelled halfway (see freeze).
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostCommandTimeout)
	defer cancel()
	if err := shield.RaiseDrain(j.a.Host.ShieldRunner(hctx), j.netns); err != nil {
		j.log.Warn("draining pending connections", "err", err)
		return
	}
	raised := time.Since(start)
	pid := j.cs[0].pid // the pod's containers share its network namespace
	var pending int
	for {
		n, err := pendingConnections("/proc", pid)
		if err != nil {
			j.log.Warn("reading the pod's TCP sockets", "err", err)
			return
		}
		pending = n
		if n == 0 || time.Since(start) > drainMax || ctx.Err() != nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if pending > 0 {
		j.log.Warn("connections still pending at the freeze – the final dump may fail", "pending", pending)
	}
	j.log.Info("pending connections drained", "raiseMs", ms(raised), "ms", ms(time.Since(start)), "pending", pending)
}

// pendingConnections counts the handshakes in progress (SYN_RECV) and the
// connections waiting in accept queues (rx_queue of a LISTEN socket) in the
// network namespace of pid, from /proc/<pid>/net/tcp and tcp6.
func pendingConnections(procRoot string, pid int) (int, error) {
	n := 0
	for _, f := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "net", f))
		if err != nil {
			if os.IsNotExist(err) && f == "tcp6" {
				continue // no IPv6
			}
			return 0, err
		}
		n += countPending(string(b))
	}
	return n, nil
}

func countPending(table string) int {
	n := 0
	lines := strings.Split(table, "\n")
	for _, line := range lines[min(1, len(lines)):] {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		switch fields[3] {
		case "03": // SYN_RECV
			n++
		case "0A": // LISTEN: rx_queue is the accept backlog
			if _, rx, ok := strings.Cut(fields[4], ":"); ok {
				if v, err := strconv.ParseUint(rx, 16, 32); err == nil {
					n += int(v)
				}
			}
		}
	}
	return n
}

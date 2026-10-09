// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// mptcpSockets returns how many Multipath TCP sockets (listening or
// connected) the network namespace of pid holds, from the per-namespace
// counters in /proc/<pid>/net/protocols. "ss -M" is no substitute: it needs
// the mptcp_diag module, which stock kernels do not load on demand, and
// then reports nothing although MPTCP sockets exist.
func mptcpSockets(pid int) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/protocols", pid))
	if err != nil {
		return 0, err
	}
	return countMPTCP(string(b)), nil
}

// countMPTCP sums the "sockets" column of the MPTCP and MPTCPv6 lines.
func countMPTCP(protocols string) int {
	n := 0
	for _, l := range strings.Split(protocols, "\n") {
		f := strings.Fields(l)
		if len(f) > 2 && (f[0] == "MPTCP" || f[0] == "MPTCPv6") {
			if v, err := strconv.Atoi(f[2]); err == nil {
				n += v
			}
		}
	}
	return n
}

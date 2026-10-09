// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import "testing"

func TestCountMPTCP(t *testing.T) {
	// /proc/<pid>/net/protocols of a Go 1.26 server pod (two listeners).
	const protocols = `protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em
MPTCPv6   2096      2     282   no       0   yes  kernel      y  y  y  n  y  y  y  y  y  y  y  y  n  n  y  y  y  n
TCPv6     2496      2     282   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  n  y  n  y  y  y  y
MPTCP     1936      0     282   no       0   yes  kernel      y  y  y  n  y  y  y  y  y  y  y  y  n  n  y  y  y  n
TCP       2336      1     282   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  n  y  n  y  y  y  y
`
	if n := countMPTCP(protocols); n != 2 {
		t.Fatalf("countMPTCP = %d, want 2", n)
	}
	if n := countMPTCP("protocol  size sockets\nTCP 2336 5 282\n"); n != 0 {
		t.Fatalf("kernel without MPTCP: %d", n)
	}
}

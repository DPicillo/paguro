// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package shield

import (
	"strings"
	"testing"
	"time"
)

// Raise must be a single nft transaction – never a separate delete followed
// by a create, which opens a window in which the kernel answers client
// retransmits with RST.
func TestRaiseIsSingleAtomicTransaction(t *testing.T) {
	var calls []string
	var stdin string
	run := func(in, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		stdin = in
		return "", nil
	}
	if err := Raise(run, "/run/netns/x"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || !strings.HasSuffix(calls[0], "nft -f -") {
		t.Fatalf("expected exactly one 'nft -f -' call, got %v", calls)
	}
	if !strings.Contains(stdin, "flush table inet "+Table) || strings.Contains(stdin, "delete table") {
		t.Fatalf("ruleset must flush, not delete:\n%s", stdin)
	}
}

// UDP datagrams before the restore must not be answered with "port
// unreachable" (connected client sockets would fail with ECONNREFUSED).
func TestShieldSuppressesUnreachable(t *testing.T) {
	for _, want := range []string{"icmp type destination-unreachable counter drop", "icmpv6 type destination-unreachable counter drop"} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
}

// The drain shield drops new connection requests only, in the same table
// (Raise replaces it atomically).
func TestDrainDropsOnlyNewConnections(t *testing.T) {
	var stdin string
	run := func(in, name string, args ...string) (string, error) { stdin = in; return "", nil }
	if err := RaiseDrain(run, "/run/netns/x"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdin, "tcp flags & (syn | ack) == syn counter drop") || strings.Contains(stdin, "meta l4proto tcp counter drop") {
		t.Fatalf("drain ruleset:\n%s", stdin)
	}
	if !strings.Contains(stdin, "flush table inet "+Table) {
		t.Fatal("must replace the table atomically")
	}
}

// CRIU's own packets (the FIN of a half-closed connection it restores) pass
// before anything is dropped, in both directions.
func TestShieldLetsCRIUThrough(t *testing.T) {
	for _, chain := range []string{"chain in {", "chain out {"} {
		i := strings.Index(ruleset, chain)
		rest := ruleset[i:]
		accept, drop := strings.Index(rest, "meta mark 0xc114 accept"), strings.Index(rest, "meta l4proto tcp counter drop")
		if accept < 0 || drop < 0 || accept > drop {
			t.Errorf("%s: CRIU's mark is not accepted before the drop", chain)
		}
	}
}

// The UDP hold: one atomic nft transaction per container, the server's
// ports, only datagrams that would open a new flow, and an expiry.
func TestHoldUDPReplies(t *testing.T) {
	var calls []string
	var stdin string
	run := func(in, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		stdin = in
		return "", nil
	}
	until := time.Unix(1791363480, 0)
	if err := HoldUDPReplies(run, "/run/netns/x", "server", []uint16{19132, 19133}, until); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "nsenter --net=/run/netns/x nft -f -" {
		t.Fatalf("calls: %v", calls)
	}
	table := udpHoldTable("server")
	for _, want := range []string{
		"flush table inet " + table,
		"udp sport { 19132, 19133 } ct state new meta time < 1791363480 counter drop",
		"hook output priority 0",
	} {
		if !strings.Contains(stdin, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, stdin)
		}
	}
	if udpHoldTable("server") == udpHoldTable("sidecar") {
		t.Error("containers share a hold table")
	}
	calls = nil
	if err := HoldUDPReplies(run, "/run/netns/x", "server", nil, until); err != nil || calls != nil {
		t.Fatalf("no ports: %v %v", calls, err)
	}
}

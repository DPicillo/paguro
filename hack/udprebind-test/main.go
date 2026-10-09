// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Command paguro-udprebind-test moves the NAT bindings of a UDP server's
// clients to a new pod IP the way every agent does in Phantom mode
// (internal/ctguard, rebind.go; internal/agent, udprebind.go), in the
// network namespace it runs in. A test and debugging tool for the
// namespace model (internal/phantom/testdata/udp-rebind.sh).
//
//	paguro-udprebind-test ports    -netns PATH -ip OLDIP          (UDP server ports of a pod, comma-separated)
//	paguro-udprebind-test snapshot -old IP -ports P[,Q]           (the entries that would move)
//	paguro-udprebind-test move     -old IP -new IP -ports P[,Q] [-after FILE] [-for 20s]
//
// move takes the snapshot at once (the commit), waits until FILE exists
// (the target reported the new IP), moves the bindings and keeps them in
// place with conntrack events and polling for the -for duration.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"paguro.dev/paguro/internal/ctguard"
	"paguro.dev/paguro/internal/phantom"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: paguro-udprebind-test ports|snapshot|move [flags] (see source header)")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	nsPath := fs.String("netns", "", "pod network namespace (ports)")
	ip := fs.String("ip", "", "pod IP (ports)")
	oldIP := fs.String("old", "", "old pod IP")
	newIP := fs.String("new", "", "new pod IP")
	portList := fs.String("ports", "", "UDP server ports, comma-separated")
	after := fs.String("after", "", "move: wait for this file before moving")
	dur := fs.Duration("for", 20*time.Second, "move: how long to keep the moved bindings in place")
	_ = fs.Parse(args)

	switch cmd {
	case "ports":
		ports, err := phantom.UDPServerPorts(*nsPath, netip.MustParseAddr(*ip))
		check(err)
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = strconv.Itoa(int(p))
		}
		fmt.Println(strings.Join(parts, ","))
	case "snapshot":
		entries, err := ctguard.SnapshotRebind(netip.MustParseAddr(*oldIP), parsePorts(*portList), nil)
		check(err)
		for _, e := range entries {
			fmt.Println(e)
		}
	case "move":
		move(netip.MustParseAddr(*oldIP), netip.MustParseAddr(*newIP), parsePorts(*portList), *after, *dur)
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}
}

func move(old, new netip.Addr, ports []uint16, after string, dur time.Duration) {
	start := time.Now()
	clients, err := ctguard.SnapshotRebind(old, ports, nil)
	check(err)
	logf(start, "snapshot: %d client(s) of %s on %v", len(clients), old, ports)
	for _, e := range clients {
		logf(start, "  %s", e)
	}
	for after != "" {
		if _, err := os.Stat(after); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	want := ctguard.Retarget(clients, new)
	set := ctguard.RetargetedSet(want)
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	go func() {
		err := ctguard.Watch(ctx, set, func(e ctguard.Entry, err error) {
			logf(start, "event repair %s err=%v", e, err)
		})
		if err != nil {
			logf(start, "watch: %v", err)
		}
	}()
	for first := true; ctx.Err() == nil; first = false {
		fixed, err := ctguard.EnsureRetargeted(set.All())
		if first || len(fixed) > 0 || err != nil {
			logf(start, "ensure: %d (re)installed err=%v", len(fixed), err)
			for _, e := range fixed {
				logf(start, "  %s", e)
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	logf(start, "done")
}

func logf(start time.Time, format string, a ...any) {
	fmt.Printf("%7.3f "+format+"\n", append([]any{time.Since(start).Seconds()}, a...)...)
}

func parsePorts(s string) []uint16 {
	var out []uint16
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		check(err)
		out = append(out, uint16(n))
	}
	return out
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"errors"
	"net/netip"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A pod's socket to a ClusterIP is aborted by its own tuple – the
// ClusterIP, not the address the DNAT chose – and the application sees the
// connection end at once (what a node does after a cold start of the
// replacement: the connection's other end is gone).
func TestKillFlowsBehindDNAT(t *testing.T) {
	needRoot(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	e := newNsEnv(t)
	client, server := e.ns("kc"), e.ns("ks")
	e.veth(client, "eth0", server, "eth0")
	e.in(client, "ip", "addr", "add", "10.82.0.2/24", "dev", "eth0")
	e.in(server, "ip", "addr", "add", "10.82.0.3/24", "dev", "eth0")
	// kube-proxy's DNAT of a ClusterIP, in the client's namespace here.
	e.in(client, "ip", "route", "add", "10.96.0.0/16", "dev", "eth0")
	e.in(client, "nft", "add table ip nat; add chain ip nat out { type nat hook output priority -100; }; add rule ip nat out ip daddr 10.96.0.10 tcp dport 80 dnat to 10.82.0.3:8080")
	l, _ := listenIn(t, e.path(server), "tcp4", "0.0.0.0:8080")
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close() // never answers: the client waits for data
		}
	}()
	conn, err := dialIn(e.path(client), "tcp4", "10.82.0.2:40100", "10.96.0.10:80", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The tuple after the DNAT finds no socket.
	if n, _ := KillFlows(e.path(client), []Flow{{Proto: TCP, Local: netip.MustParseAddrPort("10.82.0.2:40100"), Remote: netip.MustParseAddrPort("10.82.0.3:8080")}}); n != 0 {
		t.Fatal("aborted by the tuple after the DNAT")
	}
	read := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		read <- err
	}()
	n, err := KillFlows(e.path(client), []Flow{{Proto: TCP, Local: netip.MustParseAddrPort("10.82.0.2:40100"), Remote: netip.MustParseAddrPort("10.96.0.10:80")}})
	if errors.Is(err, unix.EOPNOTSUPP) {
		// SOCK_DESTROY needs CONFIG_INET_DIAG_DESTROY (missing in WSL2's kernel).
		t.Skipf("kernel cannot destroy sockets: %v", err)
	}
	if n != 1 || err != nil {
		t.Fatalf("KillFlows: n=%d err=%v", n, err)
	}
	select {
	case err := <-read:
		if !errors.Is(err, syscall.ECONNABORTED) {
			t.Fatalf("read: %v, want ECONNABORTED", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiting client was not woken")
	}
}

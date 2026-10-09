// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Only unanswered attempts that a NAT sent to the old address go: not
// connections, not attempts addressed to the old address itself, not other
// backends, not UDP.
func TestUnansweredSYNFilter(t *testing.T) {
	old := netip.MustParseAddr("192.168.91.19")
	ct := func(proto uint8, state uint8, origDst, replySrc string) *netlink.ConntrackFlow {
		c := &netlink.ConntrackFlow{
			Forward: netlink.IPTuple{Protocol: proto, SrcIP: net.ParseIP("192.168.90.243"), SrcPort: 41000,
				DstIP: net.ParseIP(origDst), DstPort: 25565},
			Reverse: netlink.IPTuple{Protocol: proto, SrcIP: net.ParseIP(replySrc), SrcPort: 25565,
				DstIP: net.ParseIP("192.168.90.243"), DstPort: 41000},
		}
		if proto == unix.IPPROTO_TCP {
			c.ProtoInfo = &netlink.ProtoInfoTCP{State: state}
		}
		c.TimeOut = 117 // three seconds after the last SYN
		return c
	}
	f := synFilter{old: old, timeout: 120}
	fresh := ct(unix.IPPROTO_TCP, tcpConntrackSynSent, "10.100.210.102", "192.168.91.19")
	fresh.TimeOut = 120
	cases := []struct {
		name string
		c    *netlink.ConntrackFlow
		want bool
	}{
		{"ClusterIP attempt to the old address", ct(unix.IPPROTO_TCP, tcpConntrackSynSent, "10.100.210.102", "192.168.91.19"), true},
		{"answered (SYN_RECV)", ct(unix.IPPROTO_TCP, 2, "10.100.210.102", "192.168.91.19"), false},
		{"established", ct(unix.IPPROTO_TCP, 3, "10.100.210.102", "192.168.91.19"), false},
		{"addressed to the old address itself", ct(unix.IPPROTO_TCP, tcpConntrackSynSent, "192.168.91.19", "192.168.91.19"), false},
		{"another backend", ct(unix.IPPROTO_TCP, tcpConntrackSynSent, "10.100.210.102", "192.168.71.129"), false},
		{"UDP", ct(unix.IPPROTO_UDP, 0, "10.100.210.102", "192.168.91.19"), false},
		{"a SYN just sent (a handshake in flight)", fresh, false},
	}
	for _, c := range cases {
		if got := f.MatchConntrackFlow(c.c); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// A client connects to a Service while the pod is frozen: the proxy's DNAT
// sends it to the old address, where its SYN is lost. The proxy then learns
// the replacement – the attempt's retransmissions stay with the old address
// (negative control) until its conntrack entry is deleted; the next one
// reaches the replacement.
func TestUnansweredSYNHandedBack(t *testing.T) {
	needRoot(t)
	e := newNsEnv(t)
	c, node, srv, frozen := e.ns("yc"), e.ns("yn"), e.ns("ys"), e.ns("yf")
	e.veth(c, "eth0", node, "vc")
	e.veth(srv, "eth0", node, "vs")
	e.veth(frozen, "eth0", node, "vz")
	e.in(c, "ip", "addr", "add", "10.81.1.2/24", "dev", "eth0")
	e.in(c, "ip", "route", "add", "default", "via", "10.81.1.1")
	e.in(srv, "ip", "addr", "add", "10.81.2.2/24", "dev", "eth0")
	e.in(srv, "ip", "route", "add", "default", "via", "10.81.2.1")
	e.in(node, "ip", "addr", "add", "10.81.1.1/24", "dev", "vc")
	e.in(node, "ip", "addr", "add", "10.81.2.1/24", "dev", "vs")
	e.in(node, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	// The old address: the frozen source behind its shield. The SYN leaves
	// the node (its conntrack entry is confirmed) and is dropped there.
	e.in(frozen, "ip", "addr", "add", "10.81.0.99/24", "dev", "eth0")
	e.in(frozen, "ip", "route", "add", "default", "via", "10.81.0.1")
	e.in(frozen, "nft", "add table inet shield")
	e.in(frozen, "nft", "add chain inet shield in { type filter hook input priority -400; policy accept; meta l4proto tcp drop; }")
	e.in(node, "ip", "addr", "add", "10.81.0.1/24", "dev", "vz")
	dnat := func(to string) {
		script := "table ip svc\nflush table ip svc\ntable ip svc {\n chain pre {\n  type nat hook prerouting priority dstnat; policy accept;\n" +
			"  ip daddr 10.96.0.10 tcp dport 25565 dnat to " + to + "\n }\n}\n"
		cmd := exec.Command("ip", "netns", "exec", node, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
	}
	dnat("10.81.0.99:25565")
	l, _ := listenIn(t, e.path(srv), "tcp4", "0.0.0.0:25565")
	defer l.Close()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		conn, err := dialIn(e.path(c), "tcp4", "", "10.96.0.10:25565", 20*time.Second)
		if err == nil {
			conn.Close()
		}
		done <- err
	}()
	time.Sleep(1500 * time.Millisecond)
	dnat("10.81.2.2:25565") // the proxy knows the replacement now
	select {
	case err := <-done:
		t.Fatalf("negative control: connected (%v) after %v without the hand-back – the retransmissions should stay with the old address",
			err, time.Since(start))
	case <-time.After(3 * time.Second):
	}
	deleted := 0
	deadline := time.After(10 * time.Second)
	for {
		var n int
		if err := inNetns(e.path(node), func() (err error) { n, err = DropUnansweredSYNs(netip.MustParseAddr("10.81.0.99")); return }); err != nil {
			t.Fatal(err)
		}
		deleted += n
		select {
		case err := <-done:
			if err != nil || deleted == 0 {
				t.Fatalf("after the hand-back: err=%v deleted=%d", err, deleted)
			}
			t.Logf("connected %v after the first SYN, %d entries handed back", time.Since(start).Round(time.Millisecond), deleted)
			return
		case <-deadline:
			t.Fatalf("not connected after the hand-back (deleted %d)", deleted)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

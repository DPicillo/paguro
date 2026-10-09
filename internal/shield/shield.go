// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package shield protects a pod's TCP connections during the migration.
//
// The problem: between the freeze on the source and the restore on the
// target there are two moments in which a kernel sees a client's segment but
// has no matching socket:
//
//   - On the source, when the frozen pod is torn down: the socket is closed
//     and the kernel wants to send FIN/RST.
//   - On the target, as soon as the sandbox carries the old IP but CRIU has
//     not yet restored the sockets: every client retransmit would be
//     answered with RST.
//
// A single RST terminates the connection on the client for good. The shield
// is an nftables table in the pod's network namespace that drops TCP in both
// directions. Dropping is harmless – the client retries with exponential
// backoff, and the first retransmit after the restore gets through.
//
// UDP has the same problem in another form: a datagram that reaches the
// target before its socket is restored is answered with ICMP "port
// unreachable", and a client on a connected UDP socket gets ECONNREFUSED –
// which game clients treat as a lost server (measured: one per migration
// and connected client). The shield lets UDP pass (on the source a frozen
// socket queues it, which keeps a rollback lossless) but drops the
// unreachable errors the pod would send.
package shield

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Table is the nftables table (family inet) of the shield.
const Table = "paguro_shield"

// criuMark is the socket mark of CRIU's own packets (SOCCR_MARK).
const criuMark = "0xc114"

// ruleset drops TCP in both directions and the pod's ICMP unreachable
// errors. Priority -400 comes before conntrack
// (-200) and before CRIU's own network lock, so that nothing slips through,
// even when CRIU removes its lock again at the end.
//
// CRIU's own packets pass (mark 0xc114, SOCCR_MARK – CRIU's network lock
// lets them through the same way): restoring a connection the application
// had half-closed, CRIU sends the FIN again on a raw socket. Measured: a
// Minecraft Bedrock server held such a connection, and every restore under
// the shield failed ("Unable to send a fin packet ... Operation not
// permitted") and cold-started.
//
// The script is applied by `nft -f` as ONE transaction: create the table if
// missing, flush it, then (re)declare the chains. Raising an already raised
// shield therefore replaces it atomically. An earlier version deleted the
// table and created it again in two steps; when the agent had already
// shielded a new sandbox and the restore wrapper raised the shield a second
// time, a client retransmit hit the few-millisecond gap and was answered with
// RST (measured: retransmit 57.3139, RST 57.3147, wrapper done 57.3236).
const ruleset = `table inet ` + Table + `
flush table inet ` + Table + `
table inet ` + Table + ` {
	chain in {
		type filter hook input priority -400; policy accept;
		meta mark ` + criuMark + ` accept
		meta l4proto tcp counter drop
	}
	chain out {
		type filter hook output priority -400; policy accept;
		meta mark ` + criuMark + ` accept
		meta l4proto tcp counter drop
		icmp type destination-unreachable counter drop
		icmpv6 type destination-unreachable counter drop
	}
}
`

// drainRuleset only drops new connection requests (SYN without ACK): the
// handshakes in progress complete and the application accepts them before
// the pod is paused. CRIU refuses to dump a listening socket with
// connections waiting in its accept queue ("In-flight connection"); with
// the full shield up, a handshake that arrived just before the freeze could
// never complete. Same table: Raise replaces it atomically.
const drainRuleset = `table inet ` + Table + `
flush table inet ` + Table + `
table inet ` + Table + ` {
	chain in {
		type filter hook input priority -400; policy accept;
		tcp flags & (syn | ack) == syn counter drop
	}
}
`

// RaiseDrain lets no new TCP connection into the pod (see drainRuleset).
// Lower removes it, Raise replaces it with the full shield.
func RaiseDrain(run Runner, netnsPath string) error {
	if netnsPath == "" {
		return fmt.Errorf("shield: no network namespace path")
	}
	_, err := run(drainRuleset, "nsenter", "--net="+netnsPath, "nft", "-f", "-")
	return err
}

// Runner executes programs; it is replaceable for tests and for the agent,
// which enters the host mount namespace via nsenter.
type Runner func(stdin string, name string, args ...string) (string, error)

// Exec is the default Runner.
func Exec(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// Raise raises the shield in the network namespace netnsPath. Idempotent and
// atomic: an existing shield is replaced without a gap.
func Raise(run Runner, netnsPath string) error {
	if netnsPath == "" {
		return fmt.Errorf("shield: no network namespace path")
	}
	_, err := run(ruleset, "nsenter", "--net="+netnsPath, "nft", "-f", "-")
	return err
}

// Lower removes the shield. If it is missing, that is not an error.
func Lower(run Runner, netnsPath string) error {
	if netnsPath == "" {
		return nil
	}
	out, err := run("", "nsenter", "--net="+netnsPath, "nft", "delete", "table", "inet", Table)
	if err != nil && (strings.Contains(out, "No such file") || strings.Contains(out, "does not exist")) {
		return nil
	}
	return err
}

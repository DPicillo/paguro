// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package shield

import (
	"fmt"
	"hash/crc32"
	"strings"
	"time"
)

// UDPHoldWindow is how long after a restore with a new pod IP a UDP server
// answers a peer only once that peer has written to the new address.
const UDPHoldWindow = 30 * time.Second

// HoldUDPReplies keeps a restored UDP server (an unconnected socket on one
// of ports: game servers, QUIC, DNS) from writing first to its peers until
// until; replies to a peer that has written to the pod since the restore
// pass. Only for a restore with a new pod IP.
//
// Why: clients reach such a server through a Service, and their node's
// conntrack holds the Service's NAT binding to the OLD address. When the old
// endpoint goes, kube-proxy deletes that binding, and the client's next
// datagram is bound to NEW with its own source port – unless the restored
// server has written to the client in between. Its datagram (NEW:port to
// client:p) matches no binding at the client's node and creates a conntrack
// entry of its own, which occupies the tuple the client's re-bound flow
// needs; nf_nat then gives the client another source port, and the server
// sees a stranger instead of its player. Measured with Minecraft Bedrock on
// Flannel: every player of the session timed out 9–10 s after a 0.4 s
// freeze. With the hold the server is silent until kube-proxy has re-bound
// the flow (about 2 s), and the session continues.
//
// In Phantom mode the agents move those bindings to NEW themselves, keeping
// the masquerade port of clients behind a NodePort, before the restore
// (internal/agent/udprebind.go): kube-proxy's fresh binding would give them
// a random port with MASQUERADE --random-fully. The hold still matters: a
// datagram the server sends to a client whose binding has not moved yet
// would occupy the moved binding's tuple in the same way.
//
// The rule expires by itself (nftables "meta time"): after the window, the
// server may again send to peers that have not written first. One table per
// container, so that the containers of a pod do not replace each other's
// rule; re-applying is atomic.
func HoldUDPReplies(run Runner, netnsPath, container string, ports []uint16, until time.Time) error {
	if netnsPath == "" || len(ports) == 0 {
		return nil
	}
	_, err := run(udpHoldRuleset(container, ports, until), "nsenter", "--net="+netnsPath, "nft", "-f", "-")
	return err
}

// udpHoldTable names a container's hold table (a hash keeps the name a
// plain nftables identifier whatever the container is called).
func udpHoldTable(container string) string {
	return fmt.Sprintf("paguro_udp_hold_%08x", crc32.ChecksumIEEE([]byte(container)))
}

// udpHoldRuleset drops the server's datagrams that would open a new
// conntrack entry (the peer has not written since the restore). Priority 0
// comes after conntrack (-200), so ct state is known; the pod's own
// conntrack starts empty in the new network namespace.
func udpHoldRuleset(container string, ports []uint16, until time.Time) string {
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = fmt.Sprint(p)
	}
	t := udpHoldTable(container)
	return fmt.Sprintf(`table inet %[1]s
flush table inet %[1]s
table inet %[1]s {
	chain out {
		type filter hook output priority 0; policy accept;
		udp sport { %[2]s } ct state new meta time < %[3]d counter drop
	}
}
`, t, strings.Join(list, ", "), until.Unix())
}

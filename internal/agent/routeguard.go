// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

// Route guard (Calico, kept IP): no routing loop for the moved address.
//
// A kept address usually lies in an IPAM block of another node, so every
// node routes it by a /32 that Felix programs from the pod's workload
// endpoint. During the hand-over that information is briefly inconsistent:
// the replacement's endpoint is published – the block's owner and the other
// nodes route the address to the target – before Felix on the target has
// its local route; the target still routes the address by the block route
// back to the owner. The packets bounced between the two until their TTL
// ran out, and the ICMP "time exceeded" failed new connections at once with
// EHOSTUNREACH (measured: 5–6 of ~970 connections per migration, from the
// target's tunnel address).
//
// While the address moves, the source and the target node drop forwarded
// packets for it that neither come from nor go to a pod interface – transit
// traffic, the only kind a loop consists of. The client's retransmission
// gets through once the routes agree. Traffic of pods on these nodes and
// the nodes' own traffic are untouched. The elements expire by themselves
// (guardTTL) should the agent not remove them.
const (
	guardTable = "paguro_route_guard"
	// guardTTL bounds a guard whose agent did not remove it.
	guardTTL = 2 * time.Minute
	// guardLinger keeps the guard after the restore until every node's
	// Felix has the new route.
	guardLinger = 5 * time.Second
	// calicoIfacePrefix is Felix's default interface prefix for pods.
	calicoIfacePrefix = "cali"
)

func guardRuleset() string {
	return fmt.Sprintf(`add table inet %[1]s
add set inet %[1]s v4 { type ipv4_addr; flags timeout; }
add set inet %[1]s v6 { type ipv6_addr; flags timeout; }
add chain inet %[1]s transit { type filter hook forward priority -150; policy accept; }
flush chain inet %[1]s transit
add rule inet %[1]s transit ip daddr @v4 iifname != "%[2]s*" oifname != "%[2]s*" counter drop
add rule inet %[1]s transit ip6 daddr @v6 iifname != "%[2]s*" oifname != "%[2]s*" counter drop
`, guardTable, calicoIfacePrefix)
}

func guardElement(op string, ip netip.Addr) string {
	set, timeout := "v4", ""
	if ip.Is6() {
		set = "v6"
	}
	if op == "add" {
		timeout = fmt.Sprintf(" timeout %ds", int(guardTTL.Seconds()))
	}
	return fmt.Sprintf("%s element inet %s %s { %s%s }\n", op, guardTable, set, ip, timeout)
}

// needsRouteGuard: Calico moves the kept address by a /32 per node.
func needsRouteGuard(m *v1.Migration) bool {
	return m.Status.IPPreserved && m.Status.NetworkAdapter == netadapter.NameCalico
}

// guardRoute guards the migrated address on this node until guardLinger
// after the restore (or the end of the migration). Best effort.
func (a *Agent) guardRoute(m *v1.Migration, log *slog.Logger) {
	ip, err := netip.ParseAddr(m.Status.SourcePodIP)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.Host.Run(ctx, []byte(guardRuleset()+guardElement("add", ip)), "nft", "-f", "-"); err != nil {
		log.Warn("guarding the moved address against routing loops", "err", err)
		return
	}
	log.Info("route guard up", "ip", ip)
	go func() {
		key := client.ObjectKeyFromObject(m)
		deadline := time.Now().Add(guardTTL)
		for !a.restoredOrOver(key) && time.Now().Before(deadline) {
			time.Sleep(200 * time.Millisecond)
		}
		time.Sleep(guardLinger)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := a.Host.Run(ctx, []byte(guardElement("delete", ip)), "nft", "-f", "-"); err != nil {
			log.Info("route guard already gone", "ip", ip, "err", err)
			return
		}
		log.Info("route guard down", "ip", ip)
	}()
}

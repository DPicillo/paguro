// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Phantom mode, part 5: connection attempts that went to the old address while
// the pod moved (phantom/synflush.go). From the restore until shortly after
// the migration ended, every node deletes the conntrack entries of such
// attempts that got no answer, so that their next SYN retransmission is
// load-balanced again – to the replacement once the proxies know it as
// ready – instead of hanging until the client gives up.

package agent

import (
	"context"
	"net/netip"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/phantom"
)

// Variables for the tests.
var (
	// synInterval: how often the attempts are looked for. A SYN is
	// retransmitted after 1, 2, 4, ... s; the entry goes a second after the
	// last one at the earliest, so the next retransmission is free.
	synInterval = 500 * time.Millisecond
	// synAfter: how long after the migration succeeded – the proxies'
	// last endpoint updates (the replacement ready, the bridge gone).
	synAfter = 10 * time.Second
	// synMax bounds the window from the restore on.
	synMax = 5 * time.Minute
)

// handBackSYNs starts the hand-back on this node once per migration, when
// the replacement has been restored. Caller holds pm.mu.
func (pm *phantomManager) handBackSYNs(m *v1.Migration) {
	if m.Status.Target.RestoredAt == nil || pm.synBack[m.UID] || synWindowOver(m, time.Now()) {
		return
	}
	old, err := netip.ParseAddr(m.Status.SourcePodIP)
	if err != nil {
		return
	}
	if pm.synBack == nil {
		pm.synBack = map[types.UID]bool{}
	}
	pm.synBack[m.UID] = true
	go pm.synLoop(client.ObjectKeyFromObject(m), m.UID, old)
}

// synWindowOver: the migration ended other than by success (nothing serves
// for the old address's Services in its place), succeeded more than
// synAfter ago, or was restored more than synMax ago.
func synWindowOver(m *v1.Migration, now time.Time) bool {
	st := &m.Status
	switch {
	case st.Phase == v1.PhaseSucceeded:
		return st.CompletedAt == nil || now.Sub(st.CompletedAt.Time) > synAfter
	case st.Phase.Terminal():
		return true
	case st.Target.RestoredAt != nil:
		return now.Sub(st.Target.RestoredAt.Time) > synMax
	}
	return false
}

func (pm *phantomManager) synLoop(key types.NamespacedName, uid types.UID, old netip.Addr) {
	ctx := context.Background()
	log := pm.log.With("migration", key.String())
	total := 0
	tick := time.NewTicker(synInterval)
	defer tick.Stop()
	for range tick.C {
		n, err := phantom.DropUnansweredSYNs(old)
		if err != nil {
			log.Warn("phantom: connection attempts to the old address", "err", err)
		} else if n > 0 {
			total += n
			log.Info("phantom: connection attempts to the old address handed back to the Service", "old", old, "count", n)
		}
		m := &v1.Migration{}
		if err := pm.a.Client.Get(ctx, key, m); err != nil || m.UID != uid || synWindowOver(m, time.Now()) {
			if total > 0 {
				log.Info("phantom: hand-back of connection attempts ended", "old", old, "total", total)
			}
			return
		}
	}
}

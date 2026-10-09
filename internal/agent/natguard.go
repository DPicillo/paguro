// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/ctguard"
)

// guardNAT keeps the NAT bindings recorded at the freeze in place
// (internal/ctguard): every 100 ms it re-installs entries the CNI flushed
// or that came back with another binding, until 5 s after the restore (or
// the end of the migration), at most for natGuardMax.
func (a *Agent) guardNAT(m *v1.Migration, entries []ctguard.Entry, log *slog.Logger) {
	if len(entries) == 0 {
		return
	}
	set := &ctguard.Set{}
	set.Add(entries)
	a.guardNATSet(m, set, log)
}

// guardNATSet guards the entries of set, which may grow meanwhile.
func (a *Agent) guardNATSet(m *v1.Migration, set *ctguard.Set, log *slog.Logger) {
	entries := set.All()
	log.Info("guarding the NAT bindings of the pod's connections", "entries", len(entries))
	key := client.ObjectKeyFromObject(m)
	deadline := time.Now().Add(natGuardMax)
	// Repairs the moment the kernel reports an entry gone; the polling
	// below catches what the events miss.
	wctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() {
		err := ctguard.Watch(wctx, set, func(e ctguard.Entry, err error) {
			if err != nil {
				log.Warn("re-installing a NAT binding", "entry", e.String(), "err", err)
				return
			}
			log.Info("NAT binding re-installed at once after a conntrack flush", "entry", e.String())
		})
		if err != nil {
			log.Warn("watching conntrack events – NAT bindings are re-installed by polling only", "err", err)
		}
	}()
	var doneAt time.Time
	for time.Now().Before(deadline) {
		if fixed, err := ctguard.Ensure(set.All()); err != nil {
			log.Warn("re-installing NAT bindings", "err", err)
		} else if len(fixed) > 0 {
			log.Info("NAT bindings re-installed after a conntrack flush", "entries", len(fixed), "first", fixed[0].String())
		}
		if doneAt.IsZero() {
			if a.restoredOrOver(key) {
				doneAt = time.Now()
			}
		} else if time.Since(doneAt) > 5*time.Second {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

const natGuardMax = 3 * time.Minute

// releaseHold ends the source's hold on the sticky CIDR 5 s after the
// restore (or the end of the migration): by then the target's endpoint, which
// takes precedence over the CIDR, is known on every node. Gives up after
// holdMax – Cilium drops the pending request on its own.
func (a *Agent) releaseHold(m *v1.Migration, pool, owner, ip, taken string, log *slog.Logger) {
	key := client.ObjectKeyFromObject(m)
	deadline := time.Now().Add(holdMax)
	for !a.restoredOrOver(key) {
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(5 * time.Second)
	if err := a.Cilium.Unhold(context.Background(), pool, owner, ip, taken); err != nil {
		log.Warn("releasing the hold on the sticky CIDR (Cilium drops it within 5 minutes)", "pool", pool, "err", err)
		return
	}
	log.Info("hold on the sticky CIDR released", "pool", pool)
}

func (a *Agent) restoredOrOver(key client.ObjectKey) bool {
	cur := &v1.Migration{}
	err := a.Client.Get(context.Background(), key, cur)
	if apierrors.IsNotFound(err) {
		return true
	}
	return err == nil && (cur.Status.Target.RestoredAt != nil || cur.Status.Phase.Terminal())
}

// holdMax: Cilium expires a pending request after 5 minutes.
const holdMax = 5 * time.Minute

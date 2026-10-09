// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"net/netip"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
)

// MigrationPools returns the sticky pools that non-terminal Migrations still
// need: the source pool (source pod may already be deleted while the
// replacement is not up yet) and the replacement's new generation (exists
// only after rotation, but must never be collected once it does). Used as
// PoolGC.InUse.
func MigrationPools(c client.Reader) func(context.Context) (map[string]bool, error) {
	return func(ctx context.Context) (map[string]bool, error) {
		var list v1alpha1.MigrationList
		if err := c.List(ctx, &list); err != nil {
			return nil, err
		}
		out := map[string]bool{}
		add := func(p string) {
			if netadapter.IsStickyPool(p) {
				out[p] = true
			}
		}
		for i := range list.Items {
			m := &list.Items[i]
			if m.Status.Phase.Terminal() {
				continue
			}
			add(m.Status.Network.SourcePool)
			add(m.Status.Network.TargetPool)
			if src, err := webhook.SourcePodOf(m); err == nil {
				add(src.Annotations[netadapter.AnnotationCiliumIPPool])
			}
		}
		return out, nil
	}
}

// MigrationIPs returns the pod IPs that running migrations keep (sticky
// IPs with IP preservation): the allocator must not hand them out while a
// pool generation is being rotated.
func MigrationIPs(c client.Reader) func(context.Context) (map[netip.Addr]bool, error) {
	return func(ctx context.Context) (map[netip.Addr]bool, error) {
		var list v1alpha1.MigrationList
		if err := c.List(ctx, &list); err != nil {
			return nil, err
		}
		out := map[netip.Addr]bool{}
		for i := range list.Items {
			m := &list.Items[i]
			if m.Status.Phase.Terminal() || !m.Status.IPPreserved {
				continue
			}
			if ip, err := netip.ParseAddr(m.Status.SourcePodIP); err == nil {
				out[ip] = true
			}
		}
		return out, nil
	}
}

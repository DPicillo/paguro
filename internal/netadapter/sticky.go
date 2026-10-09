// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package netadapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"paguro.dev/paguro/pkg/names"
	"strings"
	"time"
)

// Pool is the view of a CiliumPodIPPool relevant to Paguro.
type Pool struct {
	Name    string
	CIDRs   []string
	Created time.Time
}

// ErrPoolExists reports that a pool with this name already exists
// (someone else has just reserved the IP).
var ErrPoolExists = errors.New("pool already exists")

// PoolStore abstracts the pool objects in the cluster (replaceable for tests).
type PoolStore interface {
	// List returns all pools with prefix StickyPoolPrefix.
	List(ctx context.Context) ([]Pool, error)
	// Create creates a /32 pool; ErrPoolExists on name collision.
	Create(ctx context.Context, name string, ip netip.Addr) error
	// Delete removes a pool; a missing pool is not an error.
	Delete(ctx context.Context, name string) error
	// Exists reports whether a pool object with this name exists.
	Exists(ctx context.Context, name string) (bool, error)
}

// PoolName builds the sticky pool name for an IP.
func PoolName(ip netip.Addr) string {
	return StickyPoolPrefix + strings.ReplaceAll(ip.String(), ".", "-")
}

// GenerationPoolName is the pool a migration's replacement uses:
// paguro-<ip-dashed>-<5 chars of the migration UID>. A fresh pool object per
// migration means the Cilium operator allocates the /32 to the target node
// as a new pool instead of having to release it from the source node first.
func GenerationPoolName(ip netip.Addr, migrationUID string) string {
	return PoolName(ip) + "-" + names.UIDSuffix(migrationUID)
}

// StickyAllocator allocates individual IPv4 addresses from a range and
// rotates pool generations at cutover. An IP is in use as long as any
// paguro-* pool (any generation) lists it in its CIDRs. The lock
// serialises allocation and rotation in this process, so the short gap
// between deleting the old and creating the new generation can never be
// mistaken for a free IP. The controller runs as a single replica.
type StickyAllocator struct {
	// sem is the lock (capacity 1). Unlike a mutex, waiting for it ends
	// with the context: a rotation can hold it for seconds while the old
	// pool vanishes, and the webhook must answer within its timeout.
	sem    chan struct{}
	prefix netip.Prefix
	store  PoolStore
	// Next candidate; spreads allocations across the range so that freshly
	// released IPs are not reused immediately.
	next netip.Addr
	// Reserved returns IPs that are taken although no pool lists them –
	// a migration's IP between the deletion of its old pool generation
	// and the creation of the new one, rotated by another replica. Nil:
	// none.
	Reserved func(ctx context.Context) (map[netip.Addr]bool, error)
}

// NewStickyAllocator validates the range (IPv4 only, at least /30).
func NewStickyAllocator(cidr string, store PoolStore) (*StickyAllocator, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("sticky CIDR: %w", err)
	}
	p = p.Masked()
	if !p.Addr().Is4() {
		return nil, fmt.Errorf("sticky CIDR %s: only IPv4 is supported", cidr)
	}
	if p.Bits() > 30 {
		return nil, fmt.Errorf("sticky CIDR %s: too small, need at least /30", cidr)
	}
	return &StickyAllocator{sem: make(chan struct{}, 1), prefix: p, store: store, next: p.Addr().Next()}, nil
}

func (a *StickyAllocator) lock(ctx context.Context) error {
	select {
	case a.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("sticky IP allocator busy: %w", ctx.Err())
	}
}

func (a *StickyAllocator) unlock() { <-a.sem }

// Allocate reserves the next free IP and returns the pool name and IP.
func (a *StickyAllocator) Allocate(ctx context.Context) (string, netip.Addr, error) {
	if err := a.lock(ctx); err != nil {
		return "", netip.Addr{}, err
	}
	defer a.unlock()

	pools, err := a.store.List(ctx)
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("listing sticky pools: %w", err)
	}
	used := make(map[netip.Addr]bool, len(pools))
	if a.Reserved != nil {
		reserved, err := a.Reserved(ctx)
		if err != nil {
			return "", netip.Addr{}, fmt.Errorf("listing migrating IPs: %w", err)
		}
		for ip := range reserved {
			used[ip] = true
		}
	}
	for _, p := range pools {
		for _, c := range p.CIDRs {
			if pfx, err := netip.ParsePrefix(c); err == nil {
				used[pfx.Addr()] = true
			}
		}
	}

	first, last := a.prefix.Addr().Next(), broadcast(a.prefix).Prev()
	ip := a.next
	if !a.prefix.Contains(ip) || ip.Less(first) || last.Less(ip) {
		ip = first
	}
	size := 1 << (32 - a.prefix.Bits())
	for range size - 2 {
		cand := ip
		ip = cand.Next()
		if last.Less(ip) {
			ip = first
		}
		if used[cand] {
			continue
		}
		name := PoolName(cand)
		switch err := a.store.Create(ctx, name, cand); {
		case err == nil:
			a.next = ip
			return name, cand, nil
		case errors.Is(err, ErrPoolExists):
			used[cand] = true // lost the race, next IP
		default:
			return "", netip.Addr{}, fmt.Errorf("creating pool %s: %w", name, err)
		}
	}
	return "", netip.Addr{}, fmt.Errorf("sticky CIDR %s exhausted", a.prefix)
}

// rotateWait bounds how long Rotate waits for the old pool object to vanish.
var rotateWait = 5 * time.Second

// Prepare creates newPool with the same /32 while the source's pool still
// exists: two generations of one address side by side. The Cilium operator
// allocates CIDRs per pool (tested with 1.20: it handed the /32 of the new
// generation to the target node while the source node held it in the old
// one), and every node routes the address by the source's endpoint, which
// takes precedence over any node's CIDR. Idempotent.
func (a *StickyAllocator) Prepare(ctx context.Context, newPool string, ip netip.Addr) error {
	if !IsStickyPool(newPool) {
		return fmt.Errorf("refusing to create non-paguro pool %q", newPool)
	}
	if err := a.lock(ctx); err != nil {
		return err
	}
	defer a.unlock()
	if err := a.store.Create(ctx, newPool, ip); err != nil && !errors.Is(err, ErrPoolExists) {
		return fmt.Errorf("creating pool %s: %w", newPool, err)
	}
	return nil
}

// Discard deletes a sticky pool (a prepared generation of a migration that
// rolled back). A non-paguro pool is never deleted.
func (a *StickyAllocator) Discard(ctx context.Context, pool string) error {
	if !IsStickyPool(pool) {
		return nil
	}
	if err := a.lock(ctx); err != nil {
		return err
	}
	defer a.unlock()
	return a.store.Delete(ctx, pool)
}

// Rotate replaces the pool generation of a sticky IP: delete oldPool, then
// make sure newPool with the same /32 exists. When newPool was prepared
// during pre-copy, the old one is only deleted. Otherwise the old order
// stays: wait until oldPool is gone, then create newPool – the fallback for
// a migration whose preparation did not happen. Idempotent: a missing old
// pool or an already existing new pool is fine. A non-paguro oldPool is
// never deleted.
func (a *StickyAllocator) Rotate(ctx context.Context, oldPool, newPool string, ip netip.Addr) error {
	if !IsStickyPool(newPool) {
		return fmt.Errorf("refusing to create non-paguro pool %q", newPool)
	}
	if err := a.lock(ctx); err != nil {
		return err
	}
	defer a.unlock()
	prepared, err := a.store.Exists(ctx, newPool)
	if err != nil {
		return err
	}
	if prepared {
		if oldPool != newPool && IsStickyPool(oldPool) {
			if err := a.store.Delete(ctx, oldPool); err != nil {
				return fmt.Errorf("deleting pool %s: %w", oldPool, err)
			}
		}
		return nil
	}
	if oldPool != newPool && IsStickyPool(oldPool) {
		if err := a.store.Delete(ctx, oldPool); err != nil {
			return fmt.Errorf("deleting pool %s: %w", oldPool, err)
		}
		deadline := time.Now().Add(rotateWait)
		for {
			exists, err := a.store.Exists(ctx, oldPool)
			if err != nil {
				return err
			}
			if !exists {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("pool %s still exists %s after delete", oldPool, rotateWait)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	if err := a.store.Create(ctx, newPool, ip); err != nil && !errors.Is(err, ErrPoolExists) {
		return fmt.Errorf("creating pool %s: %w", newPool, err)
	}
	return nil
}

func broadcast(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	hostBits := 32 - p.Bits()
	for i := 3; i >= 0 && hostBits > 0; i-- {
		n := min(hostBits, 8)
		b[i] |= byte(1<<n - 1)
		hostBits -= n
	}
	return netip.AddrFrom4(b)
}

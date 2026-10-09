// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package webhook contains the mutating admission webhook for pods:
// intercepting an owner's replacement pod (turned into a restore target)
// and allocating sticky IPs for migratable pods under Cilium.
package webhook

import (
	"context"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"paguro.dev/paguro/api/v1alpha1"
)

// Interceptor is the state the controller and the webhook share about
// replacement pods: the controller arms the interception of a migration's
// replacement (Register), the webhook turns the first new pod of the owner
// into the restore target (Consume) – exactly one pod per migration.
type Interceptor interface {
	// Register arms the interception for mig's owner. A consumed migration
	// is armed again only with force (the mutated pod never appeared).
	Register(ctx context.Context, mig *v1alpha1.Migration, force bool) error
	// ConsumedAt returns when the replacement pod was intercepted.
	ConsumedAt(mig *v1alpha1.Migration) (time.Time, bool)
	// Forget disarms (rollback, terminal state).
	Forget(ctx context.Context, mig *v1alpha1.Migration) error
	// Pending returns the migration waiting for a pod of owner.
	Pending(ctx context.Context, owner types.UID) (*v1alpha1.Migration, bool)
	// Consume runs mutate for the owner's waiting migration and claims it
	// for pod only if mutate succeeded.
	Consume(ctx context.Context, owner types.UID, pod string, mutate func(*v1alpha1.Migration) error) (*v1alpha1.Migration, bool, error)
}

// Registry is an Interceptor in memory – for a single controller process
// (tests). The controller uses APIRegistry, which every replica shares.
type Registry struct {
	mu       sync.Mutex
	byOwner  map[types.UID]*v1alpha1.Migration
	consumed map[types.UID]time.Time // Migration UID → time of mutation
	now      func() time.Time
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		byOwner:  map[types.UID]*v1alpha1.Migration{},
		consumed: map[types.UID]time.Time{},
		now:      time.Now,
	}
}

// WithClock replaces the time source (tests).
func (r *Registry) WithClock(now func() time.Time) *Registry {
	r.now = now
	return r
}

// Register registers a Migration for the owner (idempotent). An already
// consumed Migration is not registered again unless force=true
// (the controller knows that no pod was created despite the mutation).
func (r *Registry) Register(_ context.Context, mig *v1alpha1.Migration, force bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, done := r.consumed[mig.UID]; done && !force {
		return nil
	}
	delete(r.consumed, mig.UID)
	r.byOwner[types.UID(mig.Status.Cutover.ReplacementOwnerUID)] = mig.DeepCopy()
	return nil
}

// Pending reports whether a Migration is currently waiting for the owner.
func (r *Registry) Pending(_ context.Context, ownerUID types.UID) (*v1alpha1.Migration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.byOwner[ownerUID]
	if !ok {
		return nil, false
	}
	return m.DeepCopy(), true
}

// Consume runs mutate for the owner's waiting Migration and removes the
// entry only if mutate succeeded. All of this happens under the mutex so
// that two concurrent admission requests do not both get the same
// restore.
func (r *Registry) Consume(_ context.Context, ownerUID types.UID, _ string, mutate func(*v1alpha1.Migration) error) (*v1alpha1.Migration, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.byOwner[ownerUID]
	if !ok {
		return nil, false, nil
	}
	if err := mutate(m.DeepCopy()); err != nil {
		return m.DeepCopy(), true, err
	}
	delete(r.byOwner, ownerUID)
	r.consumed[m.UID] = r.now()
	return m.DeepCopy(), true, nil
}

// ConsumedAt returns the time at which the replacement pod was mutated.
func (r *Registry) ConsumedAt(mig *v1alpha1.Migration) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.consumed[mig.UID]
	return t, ok
}

// Forget removes all traces of a Migration (on terminal state).
func (r *Registry) Forget(_ context.Context, mig *v1alpha1.Migration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.consumed, mig.UID)
	for owner, m := range r.byOwner {
		if m.UID == mig.UID {
			delete(r.byOwner, owner)
		}
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

// APIRegistry keeps the interception state in the Migration objects
// (status.cutover), so that every controller replica's webhook sees the
// same state: several replicas keep the webhook reachable while one of them
// restarts – during a `helm upgrade` for instance, when a single replica
// would let new pods through unmutated (the webhook fails open).
//
// The controller arms a migration's interception; the first webhook replica
// that admits a new pod of the owner claims it with a status patch whose
// precondition is the object's resourceVersion. A replica that loses the
// race finds the migration claimed and admits its pod as an ordinary one –
// exactly one restore target per migration. Interception is possible only
// while the migration waits for its replacement (pre-copy, frozen, cutting
// over): an abort or a terminal phase disarms it without another write.

import (
	"context"
	"errors"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

// OwnerIndex is the cache index of migrations by the UID of the source
// pod's controller (status.cutover.replacementOwnerUID, set at preflight).
const OwnerIndex = "status.cutover.replacementOwnerUID"

// IndexOwner registers OwnerIndex with the manager's cache.
func IndexOwner(ctx context.Context, fi client.FieldIndexer) error {
	return fi.IndexField(ctx, &v1alpha1.Migration{}, OwnerIndex, func(o client.Object) []string {
		if m, ok := o.(*v1alpha1.Migration); ok && m.Status.Cutover.ReplacementOwnerUID != "" {
			return []string{m.Status.Cutover.ReplacementOwnerUID}
		}
		return nil
	})
}

// APIRegistry is the Interceptor of the controller.
type APIRegistry struct {
	// Client reads from the cache (OwnerIndex) and writes the status.
	Client client.Client
	// Reader reads from the API server: the cache may not have seen the
	// controller's last write yet.
	Reader client.Reader
	Now    func() time.Time
}

var _ Interceptor = (*APIRegistry)(nil)

func (r *APIRegistry) now() metav1.MicroTime {
	if r.Now != nil {
		return metav1.NewMicroTime(r.Now())
	}
	return metav1.NowMicro()
}

// waiting: the migration waits for its replacement pod and no pod has
// claimed it.
func waiting(m *v1alpha1.Migration) bool {
	switch m.Status.Phase {
	case v1alpha1.PhasePreCopy, v1alpha1.PhaseFrozen, v1alpha1.PhaseCuttingOver:
	default:
		return false
	}
	c := m.Status.Cutover
	return c.InterceptArmedAt != nil && c.InterceptedAt == nil
}

// Register arms mig in place (status patch, optimistic lock); mig carries
// the new resourceVersion afterwards.
func (r *APIRegistry) Register(ctx context.Context, mig *v1alpha1.Migration, force bool) error {
	c := mig.Status.Cutover
	if c.InterceptArmedAt != nil && (c.InterceptedAt == nil || !force) {
		return nil // armed, or consumed and not to be re-armed
	}
	base := mig.DeepCopy()
	now := r.now()
	mig.Status.Cutover.InterceptArmedAt = &now
	mig.Status.Cutover.InterceptedAt = nil
	mig.Status.Cutover.InterceptedPod = ""
	return r.Client.Status().Patch(ctx, mig, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

// ConsumedAt: when a pod claimed the migration.
func (r *APIRegistry) ConsumedAt(mig *v1alpha1.Migration) (time.Time, bool) {
	if t := mig.Status.Cutover.InterceptedAt; t != nil {
		return t.Time, true
	}
	return time.Time{}, false
}

// Forget is a no-op: aborting and terminal phases are never interceptable.
func (r *APIRegistry) Forget(context.Context, *v1alpha1.Migration) error { return nil }

// Pending returns the migration waiting for a pod of owner (read live).
func (r *APIRegistry) Pending(ctx context.Context, owner types.UID) (*v1alpha1.Migration, bool) {
	m, err := r.waitingFor(ctx, owner)
	return m, err == nil && m != nil
}

// waitingFor finds the migration waiting for a pod of owner. Candidates
// come from the cache; each is read live, because the cache may lag behind
// the controller's arming write – it is only a few objects, and none for
// pods whose owner no migration is moving.
func (r *APIRegistry) waitingFor(ctx context.Context, owner types.UID) (*v1alpha1.Migration, error) {
	var list v1alpha1.MigrationList
	if err := r.Client.List(ctx, &list, client.MatchingFields{OwnerIndex: string(owner)}); err != nil {
		return nil, err
	}
	for i := range list.Items {
		c := &list.Items[i]
		if c.Status.Phase.Terminal() {
			continue
		}
		live := &v1alpha1.Migration{}
		if err := r.Reader.Get(ctx, client.ObjectKeyFromObject(c), live); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		if string(live.Status.Cutover.ReplacementOwnerUID) == string(owner) && waiting(live) {
			return live, nil
		}
	}
	return nil, nil
}

// Consume claims the owner's waiting migration for pod after mutate
// succeeded. A replica that loses the race sees the claim on its retry and
// reports nothing waiting.
func (r *APIRegistry) Consume(ctx context.Context, owner types.UID, pod string, mutate func(*v1alpha1.Migration) error) (*v1alpha1.Migration, bool, error) {
	for attempt := 0; attempt < 5; attempt++ {
		m, err := r.waitingFor(ctx, owner)
		if err != nil {
			return nil, false, err
		}
		if m == nil {
			return nil, false, nil
		}
		if err := mutate(m.DeepCopy()); err != nil {
			return m, true, err
		}
		base := m.DeepCopy()
		now := r.now()
		m.Status.Cutover.InterceptedAt = &now
		m.Status.Cutover.InterceptedPod = pod
		err = r.Client.Status().Patch(ctx, m, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
		if err == nil {
			return m, true, nil
		}
		if !apierrors.IsConflict(err) {
			return m, true, err
		}
	}
	return nil, true, errors.New("the migration kept changing while claiming its replacement pod")
}

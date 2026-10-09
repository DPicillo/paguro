// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

type rotateCall struct {
	old, new, node string
	ip             netip.Addr
}

type fakeRotator struct {
	calls     []rotateCall
	prepared  []rotateCall
	discarded []string
	fail      int // fail the first n calls
	// reannounced records Reannounce calls; replacementLingers keeps the
	// replacement's endpoint alive.
	reannounced        []string
	replacementLingers bool
}

func (f *fakeRotator) PreparePool(_ context.Context, newPool string, ip netip.Addr, node string) error {
	f.prepared = append(f.prepared, rotateCall{"", newPool, node, ip})
	return nil
}

func (f *fakeRotator) DiscardPool(_ context.Context, pool string) error {
	f.discarded = append(f.discarded, pool)
	return nil
}

func (f *fakeRotator) Reannounce(_ context.Context, namespace, endpoint, replacedBy string) (bool, error) {
	f.reannounced = append(f.reannounced, namespace+"/"+endpoint+"<"+replacedBy)
	return !f.replacementLingers, nil
}

func (f *fakeRotator) RotatePool(_ context.Context, old, new string, ip netip.Addr, node string) error {
	f.calls = append(f.calls, rotateCall{old, new, node, ip})
	if f.fail > 0 {
		f.fail--
		return errors.New("api unavailable")
	}
	return nil
}

func stickyPool(name string) podOpt {
	return func(p *corev1.Pod) {
		p.Annotations = map[string]string{netadapter.AnnotationCiliumIPPool: name}
		p.Status.PodIP = "10.250.0.2"
	}
}

func TestPoolRotationAtFrozenEarly(t *testing.T) {
	rot := &fakeRotator{}
	e := newEnv(t, netadapter.Cilium{}, testPod(fromDeployment, stickyPool("paguro-10-250-0-2")), v1alpha1.MigrationSpec{})
	e.r.Pools = rot
	m := e.reconcileUntil(v1alpha1.PhasePreCopy)
	nw := m.Status.Network
	if nw.SourcePool != "paguro-10-250-0-2" || nw.TargetPool != "paguro-10-250-0-2-migui" || !m.Status.IPPreserved {
		t.Fatalf("network status: %+v", nw)
	}
	// The replacement's generation exists during pre-copy, next to the
	// source's: the operator can hand the /32 to the target before the freeze.
	e.reconcile()
	m = e.mig()
	wantPrep := rotateCall{"", "paguro-10-250-0-2-migui", "node-b", netip.MustParseAddr("10.250.0.2")}
	if len(rot.prepared) != 1 || rot.prepared[0] != wantPrep || m.Status.Network.PoolPreparedAt == nil {
		t.Fatalf("prepared %+v (preparedAt %v), want [%+v]", rot.prepared, m.Status.Network.PoolPreparedAt, wantPrep)
	}
	e.warmUp()
	repl := e.interceptReplacement()
	if repl.Annotations[netadapter.AnnotationCiliumIPPool] != "paguro-10-250-0-2-migui" {
		t.Errorf("replacement pool %q", repl.Annotations[netadapter.AnnotationCiliumIPPool])
	}
	e.reconcile()
	if len(rot.calls) != 0 {
		t.Fatal("pool must not be rotated before Frozen")
	}

	e.freeze()
	m = e.reconcileUntil(v1alpha1.PhaseRestoring)
	want := rotateCall{"paguro-10-250-0-2", "paguro-10-250-0-2-migui", "node-b", netip.MustParseAddr("10.250.0.2")}
	if len(rot.calls) != 1 || rot.calls[0] != want {
		t.Fatalf("rotation calls %+v, want [%+v]", rot.calls, want)
	}
	if m.Status.Network.PoolRotatedAt == nil || m.Status.Cutover.SourceDeletedAt == nil {
		t.Error("rotation not recorded")
	}
	e.reconcile()
	if len(rot.calls) != 1 {
		t.Error("rotation must happen exactly once")
	}
	assertEvent(t, e.rec, "PoolRotated")
}

func TestPoolRotationRetriedAndOnDelete(t *testing.T) {
	rot := &fakeRotator{fail: 1}
	sts := func(p *corev1.Pod) {
		p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "db", UID: "sts-uid", Controller: ptr.To(true)}}
	}
	// Old-style pool name without generation suffix on a StatefulSet pod.
	e := newEnv(t, netadapter.Cilium{}, testPod(sts, stickyPool("paguro-10-250-0-2")), v1alpha1.MigrationSpec{})
	e.r.Pools = rot
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.freeze()
	m := e.reconcileUntil(v1alpha1.PhaseCuttingOver)
	if m.Status.Network.PoolRotatedAt != nil {
		t.Fatal("first rotation failed, must not be recorded")
	}
	e.reconcile()
	if m = e.mig(); m.Status.Network.PoolRotatedAt == nil || len(rot.calls) != 2 {
		t.Fatalf("rotation not retried: calls=%d", len(rot.calls))
	}
	if rot.calls[1].old != "paguro-10-250-0-2" || rot.calls[1].new != "paguro-10-250-0-2-migui" {
		t.Errorf("call %+v", rot.calls[1])
	}
	assertEvent(t, e.rec, "PoolRotationFailed")
}

func TestNoPoolRotationOnRollback(t *testing.T) {
	rot := &fakeRotator{}
	e := newEnv(t, netadapter.Cilium{}, testPod(fromDeployment, stickyPool("paguro-10-250-0-2")), v1alpha1.MigrationSpec{})
	e.r.Pools = rot
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.warmUp()
	e.agent(func(st *v1alpha1.MigrationStatus) { st.Source.Error = "boom"; st.Source.ThawedAt = e.at(0) })
	e.reconcileUntil(v1alpha1.PhaseRolledBack)
	e.reconcile()
	if len(rot.calls) != 0 {
		t.Errorf("rollback must not rotate pools: %+v", rot.calls)
	}
	if len(rot.discarded) != 1 || rot.discarded[0] != "paguro-10-250-0-2-migui" {
		t.Errorf("the prepared generation must be discarded on rollback: %v", rot.discarded)
	}
}

func TestMigrationPoolsKeepsReferencedPools(t *testing.T) {
	e := newEnv(t, netadapter.Cilium{}, testPod(fromDeployment, stickyPool("paguro-10-250-0-2")), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	done := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: ns, UID: "old-uid"},
		Spec:       v1alpha1.MigrationSpec{PodName: "x"},
	}
	if err := e.c.Create(context.Background(), done); err != nil {
		t.Fatal(err)
	}
	done.Status = v1alpha1.MigrationStatus{Phase: v1alpha1.PhaseSucceeded,
		Network: v1alpha1.NetworkStatus{SourcePool: "paguro-10-250-0-9", TargetPool: "paguro-10-250-0-9-olduu"}}
	if err := e.c.Status().Update(context.Background(), done); err != nil {
		t.Fatal(err)
	}

	inUse, err := MigrationPools(e.c)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !inUse["paguro-10-250-0-2"] || !inUse["paguro-10-250-0-2-migui"] {
		t.Errorf("active migration's pools must be kept: %v", inUse)
	}
	if inUse["paguro-10-250-0-9"] || inUse["paguro-10-250-0-9-olduu"] {
		t.Errorf("terminal migration's pools must not be pinned: %v", inUse)
	}
}

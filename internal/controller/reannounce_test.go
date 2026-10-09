// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

// Rolled back after an early hand-over: the source's endpoint is announced
// again once the replacement's endpoint is gone – once.
func TestReannounceAfterRollback(t *testing.T) {
	mig := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Spec:       v1alpha1.MigrationSpec{PodName: "web-1"},
		Status: v1alpha1.MigrationStatus{Phase: v1alpha1.PhaseRolledBack, TargetPodName: "web-5d-pabcde",
			Network: v1alpha1.NetworkStatus{EarlyHandOver: true}},
	}
	r, cl := bridgeEnv(t, mig)
	rec := events.NewFakeRecorder(10)
	r.Recorder = rec
	changed := metav1.NewMicroTime(r.Clock.Now())
	mig.Status.PhaseChangedAt = &changed
	rot := &fakeRotator{replacementLingers: true}
	r.Pools = rot
	ctx := context.Background()

	done, res, err := r.reannounce(ctx, mig)
	if err != nil || done || res.RequeueAfter == 0 {
		t.Fatalf("replacement's endpoint still there: done=%v res=%+v err=%v", done, res, err)
	}
	rot.replacementLingers = false
	if done, _, err = r.reannounce(ctx, mig); err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	want := ns + "/web-1<web-5d-pabcde"
	if len(rot.reannounced) != 2 || rot.reannounced[1] != want {
		t.Fatalf("calls %v, want two of %q", rot.reannounced, want)
	}
	cur := &v1alpha1.Migration{}
	if err := cl.Get(ctx, client.ObjectKeyFromObject(mig), cur); err != nil || cur.Status.Network.ReannouncedAt == nil {
		t.Fatalf("reannouncedAt not recorded: %v", err)
	}
	if done, _, _ = r.reannounce(ctx, cur); !done || len(rot.reannounced) != 2 {
		t.Error("announced twice")
	}
}

// A stale replacement endpoint does not keep the source on the fallback
// route for good; without an early hand-over nothing happens.
func TestReannounceBounds(t *testing.T) {
	mig := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Spec:       v1alpha1.MigrationSpec{PodName: "web-1"},
		Status: v1alpha1.MigrationStatus{Phase: v1alpha1.PhaseRolledBack, TargetPodName: "web-5d-pabcde",
			Network: v1alpha1.NetworkStatus{EarlyHandOver: true}},
	}
	r, _ := bridgeEnv(t, mig)
	r.Recorder = events.NewFakeRecorder(10)
	old := metav1.NewMicroTime(r.Clock.Now().Add(-reannounceMax - time.Second))
	mig.Status.PhaseChangedAt = &old
	rot := &fakeRotator{}
	r.Pools = rot
	if done, _, err := r.reannounce(context.Background(), mig); err != nil || !done || rot.reannounced[0] != ns+"/web-1<" {
		t.Fatalf("done=%v err=%v calls=%v", done, err, rot.reannounced)
	}
	committed := mig.DeepCopy()
	committed.Status.Network.ReannouncedAt = nil
	committed.Status.Cutover.SourceDeletedAt = &old
	if done, _, _ := r.reannounce(context.Background(), committed); !done || len(rot.reannounced) != 1 {
		t.Error("after the commit the source is gone: nothing to announce")
	}
}

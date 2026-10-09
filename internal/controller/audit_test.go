// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
)

func TestMutationAudit(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	pod := func(name string, migratable bool, rc *string) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: k8stypes.UID("uid-" + name)}}
		if migratable {
			p.Labels = map[string]string{v1alpha1.LabelMigratable: "true"}
		}
		p.Spec.RuntimeClassName = rc
		return p
	}
	objs := []client.Object{
		pod("unmutated", true, nil),
		pod("mutated", true, ptr.To(v1alpha1.RuntimeClassName)),
		pod("own-class", true, ptr.To("gvisor")), // left alone by design
		pod("plain", false, nil),
	}
	excluded := pod("system", true, nil)
	excluded.Namespace = "kube-system" // the webhook does not see it: no warning
	objs = append(objs, excluded)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	rec := events.NewFakeRecorder(10)
	a := &MutationAudit{Client: cl, Recorder: rec, Metrics: NewMetrics(nil), reported: map[k8stypes.UID]bool{},
		Exclude: map[string]bool{"kube-system": true}}

	a.scan(context.Background())
	a.scan(context.Background()) // reported once per pod
	if n := len(rec.Events); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
	if got := testutil.ToFloat64(a.Metrics.Unmutated); got != 1 {
		t.Fatalf("gauge = %v, want 1", got)
	}
}

func TestTruncateNote(t *testing.T) {
	if got := truncateNote("short", 10); got != "short" {
		t.Fatal(got)
	}
	got := truncateNote("ääääää", 7) // 2-byte runes: never cut one in half
	if len(got) > 7 || got != "ää…" {
		t.Fatalf("%q (%d bytes)", got, len(got))
	}
}

// strictRecorder fails on a typed nil in the related parameter, like the
// real events recorder (it calls GetObjectKind on it and panics).
type strictRecorder struct{ t *testing.T }

func (s strictRecorder) Eventf(regarding, related runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	if related != nil && reflect.ValueOf(related).IsNil() {
		s.t.Fatalf("related is a typed nil %T (reason %s)", related, reason)
	}
}

func TestEmitWithoutPod(t *testing.T) {
	r := &MigrationReconciler{Recorder: strictRecorder{t}}
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "ns"}} // no pod known yet
	r.emit(mig, v1alpha1.PhasePreflight, "checking")
}

func TestVolumeMoveMsWithPreAttach(t *testing.T) {
	at := func(ms int) *metav1.MicroTime {
		m := metav1.NewMicroTime(time.Date(2026, 10, 3, 14, 4, 5, 963_000_000, time.UTC).Add(time.Duration(ms) * time.Millisecond))
		return &m
	}
	st := &v1alpha1.MigrationStatus{}
	st.Cutover.SourceDeletedAt = at(0)
	// Without pre-attach: detach, then attach.
	st.Volumes = []v1alpha1.VolumeStatus{{Kind: VolumePVCRWO, DetachedAt: at(3200), AttachedAt: at(16300)}}
	if got := volumeMoveMs(st); got != 16300 {
		t.Errorf("without pre-attach: %d ms, want 16300", got)
	}
	// Pre-attached: the target waits for the source's detach.
	st.Volumes = []v1alpha1.VolumeStatus{{Kind: VolumePVCRWO, AttachedAt: at(252), DetachedAt: at(11567)}}
	if got := volumeMoveMs(st); got != 11567 {
		t.Errorf("pre-attached: %d ms, want 11567 (the detach)", got)
	}
}

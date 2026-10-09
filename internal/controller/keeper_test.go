// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

func TestBackendKeeper(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	pod := testPod()
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "echo", ContainerPort: 7000, Protocol: corev1.ProtocolTCP}}
	svc := func(name string, sel map[string]string, ports ...corev1.ServicePort) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: corev1.ServiceSpec{Selector: sel, Ports: ports}}
	}
	tcp := corev1.ProtocolTCP
	objs := []client.Object{
		svc("np", map[string]string{"app": "web"},
			corev1.ServicePort{Name: "named", Port: 80, TargetPort: intstr.FromString("echo"), Protocol: tcp},
			corev1.ServicePort{Name: "number", Port: 81, TargetPort: intstr.FromInt32(8080), Protocol: tcp},
			corev1.ServicePort{Name: "same", Port: 9000, Protocol: tcp},
			corev1.ServicePort{Name: "unknown", Port: 82, TargetPort: intstr.FromString("nope"), Protocol: tcp}),
		// A second Service on the same target port: listed once.
		svc("cluster", map[string]string{"app": "web"}, corev1.ServicePort{Port: 7000, TargetPort: intstr.FromInt32(7000), Protocol: tcp}),
		svc("other", map[string]string{"app": "db"}, corev1.ServicePort{Port: 5432, Protocol: tcp}),
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	clk := clocktesting.NewFakeClock(time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
	r := &MigrationReconciler{Client: cl, APIReader: cl, Clock: clk}
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{NetworkAdapter: netadapter.NamePhantom, SourcePodIP: "10.0.1.5", SourceNode: "node-a",
			// A connection from before an earlier migration still uses 10.0.9.9.
			Source: v1alpha1.SourceStatus{Phantom: &v1alpha1.SourcePhantom{Flows: []v1alpha1.PhantomFlow{
				{Proto: "tcp", Local: "10.0.1.5:7000", Remote: "10.0.2.1:4000", Class: "in-cluster"},
				{Proto: "tcp", Local: "10.0.9.9:7000", Remote: "10.0.2.2:4001", Class: "in-cluster"},
			}}}}}
	ctx := context.Background()

	for i := 0; i < 2; i++ { // idempotent
		if err := r.ensureBackendKeeper(ctx, mig, pod); err != nil {
			t.Fatal(err)
		}
	}
	ks := &corev1.Service{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: keeperName(mig)}, ks); err != nil {
		t.Fatal(err)
	}
	if len(ks.Spec.Selector) != 0 || len(ks.OwnerReferences) != 1 {
		t.Errorf("keeper service: selector %v owners %v", ks.Spec.Selector, ks.OwnerReferences)
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: keeperName(mig)}, slice); err != nil {
		t.Fatal(err)
	}
	if slice.Labels[discoveryv1.LabelServiceName] != keeperName(mig) || slice.Labels[discoveryv1.LabelManagedBy] != keeperManagedBy ||
		len(slice.Endpoints) != 2 || slice.Endpoints[0].Addresses[0] != "10.0.1.5" || slice.Endpoints[1].Addresses[0] != "10.0.9.9" {
		t.Errorf("slice %+v", slice)
	}
	got := map[int32]bool{}
	for _, p := range slice.Ports {
		got[*p.Port] = true
	}
	if len(slice.Ports) != 3 || !got[7000] || !got[8080] || !got[9000] {
		t.Errorf("ports %v (want 7000, 8080, 9000 once each)", got)
	}

	// Lifetime.
	now := metav1.NewMicroTime(clk.Now())
	mig.Status.Phase = v1alpha1.PhaseSucceeded
	mig.Status.Target.Phantom = &v1alpha1.TargetPhantom{ProgrammedAt: &now}
	if due, _ := r.keeperDue(mig); due {
		t.Error("Phantom mode: kept while connections live")
	}
	mig.Status.Target.Phantom.ReleasedAt = &now
	if due, _ := r.keeperDue(mig); !due {
		t.Error("Phantom mode: removed once released")
	}
	kept := mig.DeepCopy()
	kept.Status.NetworkAdapter, kept.Status.IPPreserved, kept.Status.CompletedAt = netadapter.NameCilium, true, &now
	if due, after := r.keeperDue(kept); due || after != keeperLingerKeptIP {
		t.Errorf("kept IP: due=%v after=%v", due, after)
	}
	clk.Step(keeperLingerKeptIP)
	if due, _ := r.keeperDue(kept); !due {
		t.Error("kept IP: removed after the linger time")
	}
	failed := mig.DeepCopy()
	failed.Status.Phase = v1alpha1.PhaseFailed
	if due, _ := r.keeperDue(failed); !due {
		t.Error("failed migration: removed")
	}

	// An old address leaves the cluster's routes: dropped from the keeper;
	// with nothing left, the keeper goes.
	at := metav1.NewMicroTime(clk.Now())
	mig.Status.PhantomUnroutable = map[string]metav1.MicroTime{"10.0.9.9": at}
	if err := r.pruneKeeper(ctx, mig); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: keeperName(mig)}, slice); err != nil ||
		len(slice.Endpoints) != 1 || slice.Endpoints[0].Addresses[0] != "10.0.1.5" {
		t.Fatalf("after pruning: err=%v endpoints %+v", err, slice.Endpoints)
	}
	mig.Status.PhantomUnroutable["10.0.1.5"] = at
	if err := r.pruneKeeper(ctx, mig); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: keeperName(mig)}, ks); err == nil {
		t.Error("keeper without endpoints left")
	}
	if err := r.pruneKeeper(ctx, mig); err != nil { // keeper gone
		t.Fatal(err)
	}

	if err := r.ensureBackendKeeper(ctx, mig, pod); err != nil {
		t.Fatal(err)
	}
	if err := r.deleteBackendKeeper(ctx, mig); err != nil {
		t.Fatal(err)
	}
	if err := r.deleteBackendKeeper(ctx, mig); err != nil { // already gone
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: keeperName(mig)}, ks); err == nil {
		t.Error("keeper service left")
	}
}

func TestSourceGracePeriod(t *testing.T) {
	m := &v1alpha1.Migration{}
	m.Status.Cutover.Mode = v1alpha1.CutoverEarly
	if g := sourceGracePeriod(m); g != sourceGracePeriodNewIP {
		t.Errorf("new IP, early: %d", g)
	}
	m.Status.IPPreserved = true
	if g := sourceGracePeriod(m); g != 0 {
		t.Errorf("kept IP: %d", g)
	}
	m.Status.IPPreserved = false
	m.Status.Cutover.Mode = v1alpha1.CutoverOnDelete // StatefulSet: same name
	if g := sourceGracePeriod(m); g != 0 {
		t.Errorf("on-delete: %d", g)
	}
}

// With a kept IP the bridge keeps the address in the pod's own Services; a
// keeper's deletion would make Cilium destroy the clients' UDP sockets.
func TestNoKeeperForKeptIP(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	pod := testPod()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "np", Namespace: ns},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}}},
	}).Build()
	r := &MigrationReconciler{Client: cl, APIReader: cl, Clock: clocktesting.NewFakeClock(time.Now())}
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{IPPreserved: true, SourcePodIP: "10.250.0.7"}}
	if err := r.ensureBackendKeeper(context.Background(), mig, pod); err != nil {
		t.Fatal(err)
	}
	err := cl.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: keeperName(mig)}, &corev1.Service{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("keeper created for a kept IP: %v", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/utils/ptr"

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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
)

func bridgeEnv(t *testing.T, mig *v1alpha1.Migration) (*MigrationReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	tcp := corev1.ProtocolTCP
	svc := func(name string, sel map[string]string, ports ...corev1.ServicePort) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: corev1.ServiceSpec{Selector: sel, Ports: ports}}
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1alpha1.Migration{}).WithObjects(
		mig,
		svc("np", map[string]string{"app": "web"},
			corev1.ServicePort{Name: "named", Port: 80, TargetPort: intstr.FromString("echo"), Protocol: tcp},
			corev1.ServicePort{Name: "number", Port: 81, TargetPort: intstr.FromInt32(8080), Protocol: tcp},
			corev1.ServicePort{Name: "unknown", Port: 82, TargetPort: intstr.FromString("nope"), Protocol: tcp}),
		svc("cluster", map[string]string{"app": "web"}, corev1.ServicePort{Port: 7000, Protocol: tcp}),
		svc("other", map[string]string{"app": "db"}, corev1.ServicePort{Port: 5432, Protocol: tcp}),
	).Build()
	clk := clocktesting.NewFakeClock(time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC))
	// Cilium, where touching the slices helps (bridge.go).
	cilium := func() netadapter.Adapter { return netadapter.Cilium{} }
	return &MigrationReconciler{Client: cl, APIReader: cl, Clock: clk, Adapter: cilium}, cl
}

func bridgeSource() *corev1.Pod {
	pod := testPod()
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "echo", ContainerPort: 7000, Protocol: corev1.ProtocolTCP}}
	return pod
}

// Kept IP: the Services that select the pod keep the IP as a ready endpoint
// across the hand-over – under their own names and port names.
func TestEndpointBridgeKeptIP(t *testing.T) {
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{IPPreserved: true, SourcePodIP: "10.250.0.9", TargetNode: "node-b"}}
	r, cl := bridgeEnv(t, mig)
	ctx := context.Background()
	if err := r.ensureEndpointBridge(ctx, mig, bridgeSource(), nil); err != nil {
		t.Fatal(err)
	}
	if len(mig.Status.Cutover.EndpointBridge) != 2 || mig.Status.Cutover.EndpointBridgeAt == nil {
		t.Fatalf("bridge status %+v", mig.Status.Cutover)
	}
	np := &discoveryv1.EndpointSlice{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "np")}, np); err != nil {
		t.Fatal(err)
	}
	if np.Labels[discoveryv1.LabelServiceName] != "np" || np.Labels[discoveryv1.LabelManagedBy] != keeperManagedBy {
		t.Errorf("labels %v", np.Labels)
	}
	ports := map[string]int32{}
	for _, p := range np.Ports {
		ports[*p.Name] = *p.Port
	}
	if len(ports) != 2 || ports["named"] != 7000 || ports["number"] != 8080 {
		t.Errorf("ports %v (named target port resolved, unresolvable one left out)", ports)
	}
	ep := np.Endpoints[0]
	if ep.Addresses[0] != "10.250.0.9" || !*ep.Conditions.Ready || *ep.NodeName != "node-b" {
		t.Errorf("endpoint %+v", ep)
	}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "other")}, &discoveryv1.EndpointSlice{}); !apierrors.IsNotFound(err) {
		t.Errorf("a Service that does not select the pod must not get a bridge: %v", err)
	}
	// Once per migration.
	before := mig.Status.Cutover.EndpointBridgeAt
	if err := r.ensureEndpointBridge(ctx, mig, bridgeSource(), nil); err != nil || mig.Status.Cutover.EndpointBridgeAt != before {
		t.Errorf("second call: %v", err)
	}
	if err := r.deleteEndpointBridge(ctx, mig); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "np")}, &discoveryv1.EndpointSlice{}); !apierrors.IsNotFound(err) {
		t.Errorf("bridge not deleted: %v", err)
	}
}

// New IP: the replacement's address, once it has one.
func TestEndpointBridgeNewIP(t *testing.T) {
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{SourcePodIP: "10.0.1.5", TargetNode: "node-b"}}
	r, cl := bridgeEnv(t, mig)
	ctx := context.Background()
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1-pmigui", Namespace: ns}}
	if err := r.ensureEndpointBridge(ctx, mig, bridgeSource(), target); err != nil || mig.Status.Cutover.EndpointBridgeAt != nil {
		t.Fatalf("without an address nothing may be bridged yet: %v %+v", err, mig.Status.Cutover)
	}
	target.Status.PodIP = "10.0.3.7"
	if err := r.ensureEndpointBridge(ctx, mig, bridgeSource(), target); err != nil {
		t.Fatal(err)
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "cluster")}, slice); err != nil {
		t.Fatal(err)
	}
	if ep := slice.Endpoints[0]; ep.Addresses[0] != "10.0.3.7" || ep.TargetRef == nil || ep.TargetRef.Name != "web-1-pmigui" {
		t.Errorf("endpoint %+v", ep)
	}
	if len(slice.Ports) != 1 || *slice.Ports[0].Port != 7000 || *slice.Ports[0].Name != "" {
		t.Errorf("unnamed port %+v", slice.Ports)
	}
}

// The bridge is deleted only while the Services' own slices are being
// touched: Cilium keeps the address only if an event of a slice that still
// lists it is in the deletion's batch.
func TestBridgeDeletionCoveredByTouches(t *testing.T) {
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{IPPreserved: true, SourcePodIP: "10.250.0.9", TargetNode: "node-b"}}
	r, cl := bridgeEnv(t, mig)
	r.bridgeTimes = &bridgeTimes{bridgeLead: 40 * time.Millisecond, coverAfter: 40 * time.Millisecond,
		touchInterval: 5 * time.Millisecond, coverMax: time.Minute}
	ctx := context.Background()
	own := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "np-abcde", Namespace: ns,
		Labels: map[string]string{discoveryv1.LabelServiceName: "np"}}, AddressType: discoveryv1.AddressTypeIPv4}
	if err := cl.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	if err := r.ensureEndpointBridge(ctx, mig, bridgeSource(), nil); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var ops []string
	r.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			mu.Lock()
			ops = append(ops, "touch "+obj.GetName())
			mu.Unlock()
			return c.Patch(ctx, obj, p, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			mu.Lock()
			ops = append(ops, "delete "+obj.GetName())
			mu.Unlock()
			return c.Delete(ctx, obj, opts...)
		},
	})
	if err := r.deleteEndpointBridge(ctx, mig); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	del := slices.Index(ops, "delete "+bridgeSliceName(mig, "np"))
	if del < 0 {
		t.Fatalf("bridge not deleted: %v", ops)
	}
	before := slices.Index(ops, "touch np-abcde")
	after := slices.Index(ops[del:], "touch np-abcde")
	if before < 0 || before > del || after < 0 {
		t.Fatalf("own slice must be touched before and after the deletion: %v", ops)
	}
	if n := len(ops); n > 200 {
		t.Errorf("%d operations: touching must stop", n)
	}
}

// The bridge is touched until the Services' own slices no longer list the
// source pod, and a little beyond.
func TestCoverSourceLeaving(t *testing.T) {
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{IPPreserved: true, SourcePodIP: "10.250.0.9", TargetNode: "node-b", SourcePodUID: "src-uid"}}
	r, cl := bridgeEnv(t, mig)
	r.bridgeTimes = testCoverTimes()
	ctx := context.Background()
	own := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "np-abcde", Namespace: ns,
		Labels: map[string]string{discoveryv1.LabelServiceName: "np"}}, AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.250.0.9"}, TargetRef: &corev1.ObjectReference{Kind: "Pod", UID: "src-uid"}}}}
	if err := cl.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	if err := r.ensureEndpointBridge(ctx, mig, bridgeSource(), nil); err != nil {
		t.Fatal(err)
	}
	touched := func() string {
		b := &discoveryv1.EndpointSlice{}
		_ = cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "np")}, b)
		return b.Annotations["paguro.dev/touched"]
	}
	done := r.coverSourceLeaving(ctx, mig)
	time.Sleep(50 * time.Millisecond)
	first := touched()
	time.Sleep(50 * time.Millisecond)
	if first == "" || touched() == first {
		t.Fatal("bridge not touched while the source is still listed")
	}
	// A replacement under the same name: the kept address, not ready yet.
	own.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"10.250.0.9"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
		TargetRef: &corev1.ObjectReference{Kind: "Pod", UID: "replacement-uid"}}}
	if err := cl.Update(ctx, own); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	first = touched()
	time.Sleep(50 * time.Millisecond)
	if touched() == first {
		t.Fatal("bridge not touched while the kept address is listed not ready")
	}
	own.Endpoints[0].Conditions.Ready = ptr.To(true)
	if err := cl.Update(ctx, own); err != nil {
		t.Fatal(err)
	}
	waitCover(t, done)
	last := touched()
	time.Sleep(50 * time.Millisecond)
	if touched() != last {
		t.Fatal("still touching after the replacement became ready")
	}
}

// testCoverTimes: the touches of the tests, fast.
func testCoverTimes() *bridgeTimes {
	return &bridgeTimes{coverAfter: 30 * time.Millisecond, touchInterval: 5 * time.Millisecond,
		coverMax: time.Minute, bridgeLead: 40 * time.Millisecond}
}

// waitCover waits for coverSourceLeaving to end.
func waitCover(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("touching did not end")
	}
}

// A migration with a new IP (Phantom mode) gets the bridge too, with the
// replacement's address: the frozen source stops serving once it fails its
// readiness probe, and the replacement's own endpoint is not ready until it
// passes its own (EKS: new connections refused for 19 s). The bridge is
// touched while the replacement's own slice lists the new address as not
// ready.
func TestEndpointBridgeNewIPMigration(t *testing.T) {
	src, err := webhook.EncodeSourcePod(bridgeSource())
	if err != nil {
		t.Fatal(err)
	}
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234",
		Annotations: map[string]string{webhook.AnnotationSourcePod: src}},
		Status: v1alpha1.MigrationStatus{SourcePodIP: "10.0.1.5", TargetNode: "node-b", SourcePodUID: "src-uid", NetworkAdapter: "phantom"}}
	deleted := metav1.NewMicroTime(time.Date(2026, 10, 3, 11, 59, 58, 0, time.UTC))
	mig.Status.Cutover.SourceDeletedAt = &deleted // the owner re-creates the replacement only now
	r, cl := bridgeEnv(t, mig)
	r.bridgeTimes = testCoverTimes()
	ctx := context.Background()
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1-pmigui", Namespace: ns, UID: "tgt-uid",
		Annotations: map[string]string{v1alpha1.AnnotationRestoreID: "abcde-1234"}}, Status: corev1.PodStatus{PodIP: "10.0.3.7"}}
	if err := cl.Create(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := cl.Status().Update(ctx, target); err != nil {
		t.Fatal(err)
	}
	// The replacement's own endpoint, not ready yet.
	own := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "np-abcde", Namespace: ns,
		Labels: map[string]string{discoveryv1.LabelServiceName: "np"}}, AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.3.7"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", UID: "tgt-uid"}}}}
	if err := cl.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	// Restoring: the bridge comes up with the replacement's address, and
	// is touched from then on.
	done := r.bridgeLate(ctx, mig)
	if mig.Status.Cutover.EndpointBridgeAt == nil || len(mig.Status.Cutover.EndpointBridge) != 2 || done == nil {
		t.Fatalf("no bridge for a migration with a new IP: %+v", mig.Status.Cutover)
	}
	if again := r.bridgeLate(ctx, mig); again != nil {
		t.Fatal("touched twice")
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "np")}, slice); err != nil {
		t.Fatal(err)
	}
	if ep := slice.Endpoints[0]; ep.Addresses[0] != "10.0.3.7" || !*ep.Conditions.Ready {
		t.Fatalf("bridge endpoint %+v", ep)
	}

	touched := func() string {
		b := &discoveryv1.EndpointSlice{}
		_ = cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "np")}, b)
		return b.Annotations["paguro.dev/touched"]
	}
	time.Sleep(50 * time.Millisecond)
	first := touched()
	time.Sleep(50 * time.Millisecond)
	if first == "" || touched() == first {
		t.Fatal("bridge not touched while the new address is listed not ready")
	}
	own.Endpoints[0].Conditions.Ready = ptr.To(true)
	if err := cl.Update(ctx, own); err != nil {
		t.Fatal(err)
	}
	waitCover(t, done)
	last := touched()
	time.Sleep(50 * time.Millisecond)
	if touched() != last {
		t.Fatal("still touching after the replacement became ready")
	}
}

// Only Cilium's reflector batches slice events: elsewhere (kube-proxy) the
// bridge is neither touched while the source leaves nor around its
// deletion, and the deletion does not wait.
func TestBridgeNotTouchedWithoutCilium(t *testing.T) {
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"},
		Status: v1alpha1.MigrationStatus{IPPreserved: true, SourcePodIP: "10.250.0.9", TargetNode: "node-b", SourcePodUID: "src-uid"}}
	r, cl := bridgeEnv(t, mig)
	r.Adapter = func() netadapter.Adapter { return netadapter.Generic{} }
	ctx := context.Background()
	own := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "np-abcde", Namespace: ns,
		Labels: map[string]string{discoveryv1.LabelServiceName: "np"}}, AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.250.0.9"}, TargetRef: &corev1.ObjectReference{Kind: "Pod", UID: "src-uid"}}}}
	if err := cl.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	if err := r.ensureEndpointBridge(ctx, mig, bridgeSource(), nil); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	patches := 0
	r.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			mu.Lock()
			patches++
			mu.Unlock()
			return c.Patch(ctx, obj, p, opts...)
		},
	})
	waitCover(t, r.coverSourceLeaving(ctx, mig))
	start := time.Now()
	if err := r.deleteEndpointBridge(ctx, mig); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Errorf("the deletion took %v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if patches != 0 {
		t.Errorf("%d touches without Cilium", patches)
	}
	if err := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: bridgeSliceName(mig, "np")}, &discoveryv1.EndpointSlice{}); !apierrors.IsNotFound(err) {
		t.Errorf("bridge not deleted: %v", err)
	}
}

// The touches of all migrations are capped; the slices take turns.
func TestTouchesCapped(t *testing.T) {
	mig := &v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: ns, UID: "abcde-1234"}}
	r, cl := bridgeEnv(t, mig)
	r.bridgeTimes = &bridgeTimes{touchInterval: time.Millisecond, coverMax: time.Minute}
	r.touchLimit = rate.NewLimiter(0, 3) // three touches, then none
	var mu sync.Mutex
	touched := map[string]int{}
	r.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			mu.Lock()
			touched[obj.GetName()]++
			mu.Unlock()
			return nil
		},
	})
	stop := r.touchEvery(ns, []string{"a", "b"})
	time.Sleep(50 * time.Millisecond)
	stop()
	mu.Lock()
	defer mu.Unlock()
	if touched["a"]+touched["b"] != 3 || touched["a"] == 0 || touched["b"] == 0 {
		t.Errorf("touches %v, want three, both slices", touched)
	}
}

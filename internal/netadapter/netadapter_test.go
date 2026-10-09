// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package netadapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// memStore is an in-memory PoolStore; "foreign" simulates pools that
// someone else creates between List and Create.
type memStore struct {
	mu      sync.Mutex
	pools   map[string]Pool
	foreign map[string]bool
}

func newMemStore() *memStore { return &memStore{pools: map[string]Pool{}, foreign: map[string]bool{}} }

func (m *memStore) List(context.Context) ([]Pool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Pool
	for _, p := range m.pools {
		out = append(out, p)
	}
	return out, nil
}

func (m *memStore) Create(_ context.Context, name string, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pools[name]; ok || m.foreign[name] {
		return ErrPoolExists
	}
	m.pools[name] = Pool{Name: name, CIDRs: []string{ip.String() + "/32"}, Created: time.Now()}
	return nil
}

func (m *memStore) Exists(_ context.Context, name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.pools[name]
	return ok, nil
}

func (m *memStore) Delete(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pools, name)
	return nil
}

func TestAllocatorSkipsNetworkBroadcastAndUsed(t *testing.T) {
	store := newMemStore()
	store.pools["paguro-10-0-0-1"] = Pool{Name: "paguro-10-0-0-1", CIDRs: []string{"10.0.0.1/32"}}
	a, err := NewStickyAllocator("10.0.0.0/29", store)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for range 5 {
		name, ip, err := a.Allocate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if name != PoolName(ip) {
			t.Fatalf("name %s does not match ip %s", name, ip)
		}
		got = append(got, ip.String())
	}
	want := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, _, err := a.Allocate(context.Background()); err == nil {
		t.Fatal("expected exhaustion (.0 network and .7 broadcast must never be used)")
	}

	// After release the gap is found (wrap-around).
	_ = store.Delete(context.Background(), "paguro-10-0-0-3")
	if _, ip, err := a.Allocate(context.Background()); err != nil || ip.String() != "10.0.0.3" {
		t.Fatalf("want 10.0.0.3 after release, got %v (%v)", ip, err)
	}
}

func TestAllocatorRetriesOnAlreadyExists(t *testing.T) {
	store := newMemStore()
	store.foreign["paguro-10-1-0-1"] = true // another replica was faster
	a, _ := NewStickyAllocator("10.1.0.0/24", store)
	name, ip, err := a.Allocate(context.Background())
	if err != nil || ip.String() != "10.1.0.2" || name != "paguro-10-1-0-2" {
		t.Fatalf("got %s %v %v", name, ip, err)
	}
}

func TestAllocatorConcurrentUnique(t *testing.T) {
	store := newMemStore()
	a, _ := NewStickyAllocator("10.250.0.0/16", store)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ip, err := a.Allocate(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[ip.String()] {
				t.Errorf("duplicate %s", ip)
			}
			seen[ip.String()] = true
		}()
	}
	wg.Wait()
}

func TestAllocatorRejectsBadCIDR(t *testing.T) {
	for _, c := range []string{"fd00::/64", "10.0.0.0/31", "nonsense"} {
		if _, err := NewStickyAllocator(c, newMemStore()); err == nil {
			t.Errorf("%s: expected error", c)
		}
	}
}

func TestBroadcast(t *testing.T) {
	for cidr, want := range map[string]string{"10.250.0.0/16": "10.250.255.255", "192.168.1.0/24": "192.168.1.255", "10.0.0.8/29": "10.0.0.15"} {
		if got := broadcast(netip.MustParsePrefix(cidr)).String(); got != want {
			t.Errorf("%s: got %s want %s", cidr, got, want)
		}
	}
}

func TestAdapters(t *testing.T) {
	sticky := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationCiliumIPPool: "paguro-10-250-0-7"}}}
	plain := &corev1.Pod{}
	defaultPool := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationCiliumIPPool: "default"}}}

	if ok, _ := (Cilium{}).CanPreserve(sticky); !ok {
		t.Error("cilium must preserve sticky pod")
	}
	for _, p := range []*corev1.Pod{plain, defaultPool} {
		if ok, reason := (Cilium{}).CanPreserve(p); ok || reason == "" {
			t.Error("cilium must refuse pods without paguro pool, with reason")
		}
	}
	if ok, _ := (Calico{}).CanPreserve(plain); !ok {
		t.Error("calico always preserves")
	}
	if ok, _ := (Generic{}).CanPreserve(sticky); ok {
		t.Error("generic never preserves")
	}

	target := &corev1.Pod{}
	if err := (Calico{}).MutateRestoreTarget(target, RestoreContext{Source: plain, SourceIP: "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	if got := target.Annotations[AnnotationCalicoIPAddrs]; got != `["10.0.0.5"]` {
		t.Errorf("calico ipAddrs = %s", got)
	}
	target = &corev1.Pod{}
	if err := (Cilium{}).MutateRestoreTarget(target, RestoreContext{Source: sticky, SourceIP: "10.250.0.7"}); err != nil {
		t.Fatal(err)
	}
	if target.Annotations[AnnotationCiliumIPPool] != "paguro-10-250-0-7" || target.Annotations["paguro.dev/sticky-ip"] != "paguro-10-250-0-7" {
		t.Errorf("cilium annotations = %v", target.Annotations)
	}
	if err := (Cilium{}).MutateRestoreTarget(&corev1.Pod{}, RestoreContext{Source: plain, SourceIP: "1.2.3.4"}); err == nil {
		t.Error("cilium without source pool must fail")
	}
	if ForName("calico").Name() != NameCalico || ForName("").Name() != NameGeneric || ForName("cilium").Name() != NameCilium {
		t.Error("ForName mapping wrong")
	}
}

func crd(name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("apiextensions.k8s.io/v1")
	u.SetKind("CustomResourceDefinition")
	u.SetName(name)
	return u
}

func TestDetect(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	for _, tt := range []struct {
		crds []string
		want string
	}{
		{nil, NameGeneric},
		{[]string{crdCalicoIPPool}, NameCalico},
		{[]string{crdCalicoIPPool, crdCiliumPodIPPool}, NameCilium},
	} {
		b := fake.NewClientBuilder().WithScheme(scheme)
		for _, c := range tt.crds {
			b = b.WithObjects(crd(c))
		}
		a, err := Detect(context.Background(), b.Build())
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != tt.want {
			t.Errorf("crds %v: got %s want %s", tt.crds, a.Name(), tt.want)
		}
	}
}

func TestPoolGC(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	store := newMemStore()
	for name, age := range map[string]time.Duration{
		"paguro-a": time.Hour,        // referenced by a pod
		"paguro-b": time.Hour,        // needed by a Migration
		"paguro-c": time.Minute,      // too young
		"paguro-d": 10 * time.Minute, // orphaned → deleted
	} {
		store.pools[name] = Pool{Name: name, Created: now.Add(-age)}
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "p", Namespace: "ns", Annotations: map[string]string{AnnotationCiliumIPPool: "paguro-a"}}}).Build()
	gc := &PoolGC{
		Store: store, Reader: reader, MinAge: 5 * time.Minute, Now: func() time.Time { return now },
		InUse: func(context.Context) (map[string]bool, error) { return map[string]bool{"paguro-b": true}, nil },
	}
	n, err := gc.RunOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("deleted %d (%v), want 1", n, err)
	}
	if _, ok := store.pools["paguro-d"]; ok {
		t.Error("paguro-d should be gone")
	}
	if len(store.pools) != 3 {
		t.Errorf("remaining %v", store.pools)
	}

	gc.InUse = func(context.Context) (map[string]bool, error) { return nil, errors.New("boom") }
	if _, err := gc.RunOnce(context.Background()); err == nil {
		t.Error("InUse error must abort GC (better keep pools than delete needed ones)")
	}
}

func TestCiliumUsesNewPoolGeneration(t *testing.T) {
	src := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationCiliumIPPool: "paguro-10-250-0-7"}}}
	target := &corev1.Pod{}
	err := (Cilium{}).MutateRestoreTarget(target, RestoreContext{Source: src, SourceIP: "10.250.0.7", TargetPool: "paguro-10-250-0-7-ab12c"})
	if err != nil {
		t.Fatal(err)
	}
	if target.Annotations[AnnotationCiliumIPPool] != "paguro-10-250-0-7-ab12c" || target.Annotations["paguro.dev/sticky-ip"] != "paguro-10-250-0-7-ab12c" {
		t.Errorf("replacement must use the new generation: %v", target.Annotations)
	}
}

func TestGenerationPoolName(t *testing.T) {
	ip := netip.MustParseAddr("10.250.0.2")
	if got := GenerationPoolName(ip, "73a7185a-2eb3-4139"); got != "paguro-10-250-0-2-73a71" {
		t.Errorf("got %s", got)
	}
	if !IsStickyPool("paguro-10-250-0-2-73a71") || !IsStickyPool("paguro-10-250-0-2") {
		t.Error("both name styles must be sticky pools")
	}
}

// orderStore records operations and fails if overlapping pools would coexist
// (unless overlap is allowed: a generation prepared during pre-copy).
type orderStore struct {
	*memStore
	ops          []string
	t            *testing.T
	allowOverlap bool
}

func (o *orderStore) Create(ctx context.Context, name string, ip netip.Addr) error {
	for _, p := range o.pools {
		if o.allowOverlap {
			break
		}
		for _, c := range p.CIDRs {
			if c == ip.String()+"/32" && p.Name != name {
				o.t.Errorf("creating %s while %s still holds %s", name, p.Name, c)
			}
		}
	}
	o.ops = append(o.ops, "create "+name)
	return o.memStore.Create(ctx, name, ip)
}

func (o *orderStore) Delete(ctx context.Context, name string) error {
	o.ops = append(o.ops, "delete "+name)
	return o.memStore.Delete(ctx, name)
}

func TestRotateDeletesBeforeCreate(t *testing.T) {
	ip := netip.MustParseAddr("10.250.0.2")
	for _, old := range []string{"paguro-10-250-0-2", "paguro-10-250-0-2-zzzzz"} { // old style and generation style
		store := &orderStore{memStore: newMemStore(), t: t}
		store.pools[old] = Pool{Name: old, CIDRs: []string{"10.250.0.2/32"}}
		a, _ := NewStickyAllocator("10.250.0.0/16", store)
		if err := a.Rotate(context.Background(), old, "paguro-10-250-0-2-abcde", ip); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(store.ops) != fmt.Sprint([]string{"delete " + old, "create paguro-10-250-0-2-abcde"}) {
			t.Errorf("ops %v", store.ops)
		}
		// Idempotent: second call neither fails nor duplicates.
		if err := a.Rotate(context.Background(), old, "paguro-10-250-0-2-abcde", ip); err != nil {
			t.Fatal(err)
		}
		if len(store.pools) != 1 {
			t.Errorf("pools %v", store.pools)
		}
		// The rotated IP stays reserved for the allocator.
		if _, got, _ := a.Allocate(context.Background()); got == ip {
			t.Error("allocator handed out the rotated IP")
		}
	}

	// Never delete foreign pools; missing old pool is fine.
	store := &orderStore{memStore: newMemStore(), t: t}
	a, _ := NewStickyAllocator("10.250.0.0/16", store)
	if err := a.Rotate(context.Background(), "team-pool", "paguro-10-250-0-2-abcde", ip); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(store.ops) != "[create paguro-10-250-0-2-abcde]" {
		t.Errorf("foreign pool touched: %v", store.ops)
	}
	if err := a.Rotate(context.Background(), "", "default", ip); err == nil {
		t.Error("creating a non-paguro pool must be refused")
	}
}

// A replacement built from a copy of the source pod carries Calico's record
// of the source sandbox; the Calico mutation must drop it, otherwise Calico
// CNI releases the source's IP while the source is still running.
func TestCalicoClearsCopiedPodState(t *testing.T) {
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		AnnotationCalicoPodIP:       "10.0.0.5/32",
		AnnotationCalicoPodIPs:      "10.0.0.5/32",
		AnnotationCalicoContainerID: "abc123",
		"keep":                      "me",
	}}}
	if err := (Calico{}).MutateRestoreTarget(target, RestoreContext{SourceIP: "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{AnnotationCalicoPodIP, AnnotationCalicoPodIPs, AnnotationCalicoContainerID} {
		if _, ok := target.Annotations[k]; ok {
			t.Errorf("stale annotation %s kept", k)
		}
	}
	if target.Annotations[AnnotationCalicoIPAddrs] != `["10.0.0.5"]` || target.Annotations["keep"] != "me" {
		t.Errorf("unexpected annotations: %v", target.Annotations)
	}
	// nil annotations: no panic
	ClearCalicoPodState(&corev1.Pod{})
}

// An IP a running migration keeps is never handed out, even without a pool
// (another replica rotates its pool generation right now).
func TestStickyAllocatorReserved(t *testing.T) {
	a, err := NewStickyAllocator("10.9.0.0/29", newMemStore())
	if err != nil {
		t.Fatal(err)
	}
	a.Reserved = func(context.Context) (map[netip.Addr]bool, error) {
		return map[netip.Addr]bool{netip.MustParseAddr("10.9.0.1"): true}, nil
	}
	_, ip, err := a.Allocate(context.Background())
	if err != nil || ip == netip.MustParseAddr("10.9.0.1") {
		t.Fatalf("allocated %v, %v", ip, err)
	}
}

func TestVerifiesSource(t *testing.T) {
	for name, want := range map[string]bool{
		"antrea": true, "cilium": true, "ovn-kubernetes": true, "calico": true, "canal": true,
		"calico+multus": true, "flannel": false, "aws-vpc-cni": false,
	} {
		if got := (CNIInfo{Name: name}).VerifiesSource(); got != want {
			t.Errorf("%s: VerifiesSource = %v, want %v", name, got, want)
		}
	}
}

// Prepared during pre-copy: the cutover only deletes the source's
// generation – no waiting for it to vanish on the freeze path.
func TestRotateAfterPrepare(t *testing.T) {
	ip := netip.MustParseAddr("10.250.0.2")
	store := &orderStore{memStore: newMemStore(), t: t, allowOverlap: true}
	store.pools["paguro-10-250-0-2"] = Pool{Name: "paguro-10-250-0-2", CIDRs: []string{"10.250.0.2/32"}}
	a, _ := NewStickyAllocator("10.250.0.0/16", store)
	if err := a.Prepare(context.Background(), "paguro-10-250-0-2-abcde", ip); err != nil {
		t.Fatal(err)
	}
	if err := a.Rotate(context.Background(), "paguro-10-250-0-2", "paguro-10-250-0-2-abcde", ip); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(store.ops) != fmt.Sprint([]string{"create paguro-10-250-0-2-abcde", "delete paguro-10-250-0-2"}) {
		t.Errorf("ops %v", store.ops)
	}
	if err := a.Discard(context.Background(), "default"); err != nil || len(store.ops) != 2 {
		t.Errorf("a non-paguro pool must never be deleted: ops %v err %v", store.ops, err)
	}
}

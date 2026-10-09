// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package netadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Preferred API versions of CiliumPodIPPool, in this order.
var ciliumPoolVersions = []string{"v2alpha1", "v2"}

const (
	ciliumGroup        = "cilium.io"
	ciliumPoolResource = "ciliumpodippools"
	labelManagedBy     = "app.kubernetes.io/managed-by"
)

// CiliumPoolStore implements PoolStore via the dynamic client
// (deliberately without the Cilium Go modules). The API version is
// determined via discovery on first access.
type CiliumPoolStore struct {
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface

	once sync.Once
	gvr  schema.GroupVersionResource
	err  error
}

func (s *CiliumPoolStore) resource() (dynamic.NamespaceableResourceInterface, error) {
	s.once.Do(func() {
		for _, v := range ciliumPoolVersions {
			gv := ciliumGroup + "/" + v
			list, err := s.Discovery.ServerResourcesForGroupVersion(gv)
			if err != nil {
				continue
			}
			for _, r := range list.APIResources {
				if r.Name == ciliumPoolResource {
					s.gvr = schema.GroupVersionResource{Group: ciliumGroup, Version: v, Resource: ciliumPoolResource}
					return
				}
			}
		}
		s.err = fmt.Errorf("cluster serves no %s.%s in versions %v", ciliumPoolResource, ciliumGroup, ciliumPoolVersions)
	})
	if s.err != nil {
		return nil, s.err
	}
	return s.Dynamic.Resource(s.gvr), nil
}

func (s *CiliumPoolStore) List(ctx context.Context) ([]Pool, error) {
	res, err := s.resource()
	if err != nil {
		return nil, err
	}
	// Only Paguro's own pools: a user's pool that happens to be named
	// "paguro-…" must never be garbage-collected.
	list, err := res.List(ctx, metav1.ListOptions{LabelSelector: labelManagedBy + "=paguro"})
	if err != nil {
		return nil, err
	}
	var out []Pool
	for _, item := range list.Items {
		if !IsStickyPool(item.GetName()) {
			continue
		}
		cidrs, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "ipv4", "cidrs")
		out = append(out, Pool{Name: item.GetName(), CIDRs: cidrs, Created: item.GetCreationTimestamp().Time})
	}
	return out, nil
}

func (s *CiliumPoolStore) Create(ctx context.Context, name string, ip netip.Addr) error {
	res, err := s.resource()
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": s.gvr.GroupVersion().String(),
		"kind":       "CiliumPodIPPool",
		"metadata": map[string]any{
			"name":   name,
			"labels": map[string]any{labelManagedBy: "paguro"},
		},
		"spec": map[string]any{
			"ipv4": map[string]any{
				"cidrs":    []any{ip.String() + "/32"},
				"maskSize": int64(32),
			},
		},
	}}
	_, err = res.Create(ctx, u, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return ErrPoolExists
	}
	return err
}

func (s *CiliumPoolStore) Delete(ctx context.Context, name string) error {
	res, err := s.resource()
	if err != nil {
		return err
	}
	err = res.Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (s *CiliumPoolStore) Exists(ctx context.Context, name string) (bool, error) {
	res, err := s.resource()
	if err != nil {
		return false, err
	}
	_, err = res.Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}

var ciliumNodeGVR = schema.GroupVersionResource{Group: ciliumGroup, Version: "v2", Resource: "ciliumnodes"}

// AnnotationNudge on a CiliumNode: touching it makes the operator reconcile
// the node's IPAM pools right away.
const AnnotationNudge = "paguro.dev/nudge"

// NudgeNode patches the nudge annotation of a CiliumNode (named like the
// Kubernetes node).
func (s *CiliumPoolStore) NudgeNode(ctx context.Context, node string) error {
	body := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, AnnotationNudge, time.Now().UTC().Format(time.RFC3339Nano))
	_, err := s.Dynamic.Resource(ciliumNodeGVR).Patch(ctx, node, types.MergePatchType, []byte(body), metav1.PatchOptions{})
	return err
}

// CiliumRotator rotates the sticky pool at cutover and nudges the target
// node (used by the controller).
type CiliumRotator struct {
	Allocator *StickyAllocator
	Store     *CiliumPoolStore
}

// RotatePool deletes oldPool, creates newPool with the same /32 and nudges
// the target node's CiliumNode asynchronously. A failed nudge is not an
// error (the target agent nudges continuously).
func (r *CiliumRotator) RotatePool(ctx context.Context, oldPool, newPool string, ip netip.Addr, targetNode string) error {
	if err := r.Allocator.Rotate(ctx, oldPool, newPool, ip); err != nil {
		return err
	}
	// Nudge in the background: it only speeds up the operator and must not
	// delay the source deletion that follows.
	r.nudge(ctx, targetNode)
	return nil
}

// PreparePool creates the replacement's pool generation during pre-copy and
// nudges the target node's CiliumNode, like RotatePool.
func (r *CiliumRotator) PreparePool(ctx context.Context, newPool string, ip netip.Addr, targetNode string) error {
	if err := r.Allocator.Prepare(ctx, newPool, ip); err != nil {
		return err
	}
	r.nudge(ctx, targetNode)
	return nil
}

// DiscardPool deletes a prepared pool generation (rollback).
func (r *CiliumRotator) DiscardPool(ctx context.Context, pool string) error {
	return r.Allocator.Discard(ctx, pool)
}

func (r *CiliumRotator) nudge(ctx context.Context, targetNode string) {
	log := logf.FromContext(ctx)
	go func() {
		nctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.Store.NudgeNode(nctx, targetNode); err != nil {
			log.Info("nudging CiliumNode failed", "node", targetNode, "error", err.Error())
		}
	}()
}

var ciliumEndpointGVR = schema.GroupVersionResource{Group: ciliumGroup, Version: "v2", Resource: "ciliumendpoints"}

// Reannounce makes every node route the address of endpoint (a pod's
// CiliumEndpoint) to that pod again after replacedBy had taken the address
// over and is gone (a rollback after an early hand-over).
//
// Cilium (1.20, measured) keeps one ipcache entry per address, written by
// the newest CiliumEndpoint that lists it. Deleting that endpoint deletes
// the entry – although the source's endpoint still holds the address – and
// the address falls back to its pool's CIDR entry: the right node, but the
// world identity, which network policies treat as outside the cluster.
// Every change of a CiliumEndpoint that Cilium reads writes the entry
// again; an annotation is not read, the order of the identity's labels is
// – and means nothing else. done is false while replacedBy still exists.
func (r *CiliumRotator) Reannounce(ctx context.Context, namespace, endpoint, replacedBy string) (bool, error) {
	res := r.Store.Dynamic.Resource(ciliumEndpointGVR).Namespace(namespace)
	if replacedBy != "" {
		_, err := res.Get(ctx, replacedBy, metav1.GetOptions{})
		if err == nil {
			return false, nil
		}
		if !apierrors.IsNotFound(err) {
			return false, err
		}
	}
	cep, err := res.Get(ctx, endpoint, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil // no endpoint (pod gone or host network): nothing to announce
	}
	if err != nil {
		return false, err
	}
	labels, _, _ := unstructured.NestedStringSlice(cep.Object, "status", "identity", "labels")
	if len(labels) < 2 {
		return true, fmt.Errorf("CiliumEndpoint %s/%s: %d identity label(s), cannot re-announce", namespace, endpoint, len(labels))
	}
	slices.Reverse(labels)
	body, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": cep.GetResourceVersion()},
		"status":   map[string]any{"identity": map[string]any{"labels": labels}},
	})
	if err != nil {
		return false, err
	}
	if _, err := res.Patch(ctx, endpoint, types.MergePatchType, body, metav1.PatchOptions{}); err != nil {
		return false, err
	}
	return true, nil
}

// PoolGC deletes orphaned sticky pools: no pod references them, no
// running Migration needs them, and they are older than MinAge (freshly
// allocated pools may belong to a pod that is just being admitted).
type PoolGC struct {
	Store  PoolStore
	Reader client.Reader
	// InUse returns additionally required pools (e.g. from running
	// Migrations whose source pod has already been deleted).
	InUse    func(ctx context.Context) (map[string]bool, error)
	Interval time.Duration
	MinAge   time.Duration
	Now      func() time.Time
}

// Start implements manager.Runnable.
func (g *PoolGC) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("sticky-pool-gc")
	t := time.NewTicker(g.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if n, err := g.RunOnce(ctx); err != nil {
				log.Error(err, "garbage collection of sticky IP pools failed")
			} else if n > 0 {
				log.Info("deleted orphaned sticky IP pools", "count", n)
			}
		}
	}
}

// NeedLeaderElection: only the leader cleans up.
func (g *PoolGC) NeedLeaderElection() bool { return true }

// RunOnce performs one GC pass and returns the number of deleted pools.
func (g *PoolGC) RunOnce(ctx context.Context) (int, error) {
	pools, err := g.Store.List(ctx)
	if err != nil {
		return 0, err
	}
	if len(pools) == 0 {
		return 0, nil
	}
	inUse := map[string]bool{}
	if g.InUse != nil {
		if inUse, err = g.InUse(ctx); err != nil {
			return 0, err
		}
	}
	var pods corev1.PodList
	if err := g.Reader.List(ctx, &pods); err != nil {
		return 0, err
	}
	for i := range pods.Items {
		if p := pods.Items[i].Annotations[AnnotationCiliumIPPool]; IsStickyPool(p) {
			inUse[p] = true
		}
	}
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	deleted := 0
	var errs []string
	for _, p := range pools {
		if inUse[p.Name] || now().Sub(p.Created) < g.MinAge {
			continue
		}
		if err := g.Store.Delete(ctx, p.Name); err != nil {
			errs = append(errs, p.Name+": "+err.Error())
			continue
		}
		deleted++
	}
	if len(errs) > 0 {
		return deleted, fmt.Errorf("deleting pools: %s", strings.Join(errs, "; "))
	}
	return deleted, nil
}

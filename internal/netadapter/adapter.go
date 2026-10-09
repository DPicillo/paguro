// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package netadapter encapsulates everything CNI-specific: detecting the CNI
// in the cluster, deciding whether the pod IP and TCP connections can be
// preserved, and the adapter-specific mutation of the replacement pod.
//
// The rest of the controller only knows the Adapter interface; changes to the
// Cilium mechanism (sticky /32 pools) stay confined to this package.
package netadapter

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

// Adapter names as they appear in status.networkAdapter.
const (
	NameCilium  = "cilium"
	NameCalico  = "calico"
	NameGeneric = "generic"
	// NamePhantom is not a CNI adapter but the Phantom network mode (new
	// IP, connections translated by eBPF); it uses the generic replacement.
	NamePhantom = "phantom"
)

// Adapter-specific annotations.
const (
	// Cilium multi-pool IPAM: name of the CiliumPodIPPool for the pod.
	AnnotationCiliumIPPool = "ipam.cilium.io/ip-pool"
	// Calico: fixed IP(s) for the pod (JSON list).
	AnnotationCalicoIPAddrs = "cni.projectcalico.org/ipAddrs"

	// Prefix of all sticky pools managed by Paguro.
	StickyPoolPrefix = "paguro-"
)

// Adapter is the CNI abstraction.
type Adapter interface {
	// Name returns cilium | calico | generic.
	Name() string
	// CanPreserve decides whether the pod IP and existing TCP connections
	// can be preserved when this pod is moved. reason explains a
	// "no" (for the status message and events).
	CanPreserve(pod *corev1.Pod) (ok bool, reason string)
	// MutateRestoreTarget applies the adapter-specific changes to the
	// replacement pod so that it gets the source's IP. Only called
	// when the Migration has ipPreserved=true.
	MutateRestoreTarget(target *corev1.Pod, rc RestoreContext) error
	// NeedsStickyIP: migratable pods need their own movable IP already
	// at creation time (Cilium only).
	NeedsStickyIP() bool
}

// RestoreContext is what an adapter needs to know about the source when it
// mutates the replacement pod.
type RestoreContext struct {
	// Snapshot of the source pod (labels, annotations, spec); may be nil.
	Source *corev1.Pod
	// IP of the source pod.
	SourceIP string
	// Cilium: pool generation the replacement must use (status.network.targetPool).
	// Empty for migrations created before pool rotation existed.
	TargetPool string
}

// ForName returns the adapter for a name from status.networkAdapter.
func ForName(name string) Adapter {
	switch name {
	case NameCilium:
		return Cilium{}
	case NameCalico:
		return Calico{}
	default:
		return Generic{}
	}
}

// CRDs used to detect the CNI.
const (
	crdCiliumPodIPPool = "ciliumpodippools.cilium.io"
	crdCalicoIPPool    = "ippools.crd.projectcalico.org"
)

// Detect detects the CNI from installed CRDs. Cilium takes precedence
// because Calico CRDs are often left behind when migrating from Calico to Cilium.
func Detect(ctx context.Context, r client.Reader) (Adapter, error) {
	for _, c := range []struct {
		crd     string
		adapter Adapter
	}{
		{crdCiliumPodIPPool, Cilium{}},
		{crdCalicoIPPool, Calico{}},
	} {
		ok, err := crdExists(ctx, r, c.crd)
		if err != nil {
			return nil, err
		}
		if ok {
			return c.adapter, nil
		}
	}
	return Generic{}, nil
}

func crdExists(ctx context.Context, r client.Reader, name string) (bool, error) {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("apiextensions.k8s.io/v1")
	u.SetKind("CustomResourceDefinition")
	err := r.Get(ctx, client.ObjectKey{Name: name}, u)
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, fmt.Errorf("checking CRD %s: %w", name, err)
	}
}

// Generic works with any CNI: new IP, TCP is closed cleanly.
type Generic struct{}

func (Generic) Name() string { return NameGeneric }
func (Generic) CanPreserve(*corev1.Pod) (bool, string) {
	return false, "CNI does not support IP preservation (generic adapter)"
}
func (Generic) MutateRestoreTarget(*corev1.Pod, RestoreContext) error { return nil }
func (Generic) NeedsStickyIP() bool                                   { return false }

// Calico writes the result of every CNI ADD back onto the pod. With the
// Kubernetes datastore the WorkloadEndpoint is derived from the pod, so these
// annotations ARE the endpoint's IPs and container ID.
const (
	AnnotationCalicoPodIP       = "cni.projectcalico.org/podIP"
	AnnotationCalicoPodIPs      = "cni.projectcalico.org/podIPs"
	AnnotationCalicoContainerID = "cni.projectcalico.org/containerID"
)

// ClearCalicoPodState removes Calico's per-sandbox annotations from a pod
// built from a copy of the source pod (bare-pod replacement). Left in place,
// Calico treats the new pod as an "existing endpoint" with the source's IP:
// with ipAddrs set, its CNI ADD first releases that IP by address – while
// the source is still running in pre-copy – and without ipAddrs Felix
// routes the source IP to the target node. No-op without these annotations
// (other CNIs).
func ClearCalicoPodState(p *corev1.Pod) {
	delete(p.Annotations, AnnotationCalicoPodIP)
	delete(p.Annotations, AnnotationCalicoPodIPs)
	delete(p.Annotations, AnnotationCalicoContainerID)
}

// Calico: "borrowed IP" via cni.projectcalico.org/ipAddrs.
type Calico struct{}

func (Calico) Name() string                           { return NameCalico }
func (Calico) CanPreserve(*corev1.Pod) (bool, string) { return true, "" }
func (Calico) NeedsStickyIP() bool                    { return false }
func (Calico) MutateRestoreTarget(target *corev1.Pod, rc RestoreContext) error {
	if rc.SourceIP == "" {
		return fmt.Errorf("calico: source pod IP unknown")
	}
	ClearCalicoPodState(target)
	setAnnotation(target, AnnotationCalicoIPAddrs, fmt.Sprintf(`[%q]`, rc.SourceIP))
	return nil
}

// Cilium: every migratable pod has its own CiliumPodIPPool with exactly
// one /32; the replacement pod gets the same pool and thus the same IP.
type Cilium struct{}

func (Cilium) Name() string        { return NameCilium }
func (Cilium) NeedsStickyIP() bool { return true }
func (Cilium) CanPreserve(pod *corev1.Pod) (bool, string) {
	if IsStickyPool(pod.Annotations[AnnotationCiliumIPPool]) {
		return true, ""
	}
	return false, fmt.Sprintf("pod has no sticky Cilium IP pool (annotation %s=%s*); "+
		"label the workload paguro.dev/migratable=true and recreate it", AnnotationCiliumIPPool, StickyPoolPrefix)
}

// MutateRestoreTarget points the replacement at the NEW pool generation. That
// pool does not exist yet during pre-copy (CNI ADD fails with "pool not (yet)
// available", which registers the demand); the controller creates it at
// cutover right after deleting the source pool.
func (Cilium) MutateRestoreTarget(target *corev1.Pod, rc RestoreContext) error {
	pool := rc.TargetPool
	if pool == "" && rc.Source != nil {
		// Migration from before pool rotation: reuse the source pool.
		pool = rc.Source.Annotations[AnnotationCiliumIPPool]
	}
	if !IsStickyPool(pool) {
		return fmt.Errorf("cilium: no sticky IP pool for the replacement")
	}
	setAnnotation(target, AnnotationCiliumIPPool, pool)
	setAnnotation(target, v1alpha1.AnnotationStickyIP, pool)
	return nil
}

// IsStickyPool reports whether a pool name is managed by Paguro.
func IsStickyPool(name string) bool {
	return len(name) > len(StickyPoolPrefix) && name[:len(StickyPoolPrefix)] == StickyPoolPrefix
}

func setAnnotation(p *corev1.Pod, k, v string) {
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[k] = v
}

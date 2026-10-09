// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

// Phantom mode in the controller: whether every node can translate, and
// which prefixes belong to the cluster. A connection whose peer is outside
// these prefixes cannot be preserved – the peer cannot be programmed
// (docs/PHANTOM-MODE.md section 5).

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"paguro.dev/paguro/api/v1alpha1"
)

// PhantomAvailable is the value of the node annotation paguro.dev/phantom
// on nodes whose agent can run Phantom mode.
const PhantomAvailable = "available"

// phantomNodesMissing returns the nodes that cannot take part in Phantom
// mode. Every node counts: a pod on a node without a Phantom-capable agent
// may be a peer of the migrated pod, and its connections could not be
// translated.
func (r *MigrationReconciler) phantomNodesMissing(ctx context.Context) ([]string, error) {
	nodes := &corev1.NodeList{}
	if err := r.List(ctx, nodes); err != nil {
		return nil, err
	}
	var missing []string
	for _, n := range nodes.Items {
		if n.Annotations[v1alpha1.AnnotationNodePhantom] != PhantomAvailable {
			missing = append(missing, n.Name)
		}
	}
	return missing, nil
}

// phantomClusterCIDRs collects the prefixes of the cluster: node pod CIDRs
// and addresses, Service CIDRs, the CNI's IP pools (Cilium, Calico) and
// r.PhantomExtraCIDRs. Missing APIs are skipped.
func (r *MigrationReconciler) phantomClusterCIDRs(ctx context.Context) []string {
	set := map[netip.Prefix]bool{}
	add := func(s string) {
		if p, err := netip.ParsePrefix(s); err == nil {
			set[p.Masked()] = true
		} else if a, err := netip.ParseAddr(s); err == nil {
			set[netip.PrefixFrom(a, a.BitLen())] = true
		}
	}
	nodes := &corev1.NodeList{}
	if err := r.List(ctx, nodes); err == nil {
		for _, n := range nodes.Items {
			for _, c := range n.Spec.PodCIDRs {
				add(c)
			}
			for _, a := range n.Status.Addresses {
				if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
					add(a.Address)
				}
			}
			// VPC-native CNIs: the pods' addresses come from the node's
			// subnets, which its agent reports.
			for _, c := range strings.Split(n.Annotations[v1alpha1.AnnotationNodeSubnets], ",") {
				add(strings.TrimSpace(c))
			}
		}
	}
	scs := &networkingv1.ServiceCIDRList{}
	if err := r.APIReader.List(ctx, scs); err == nil {
		for _, sc := range scs.Items {
			for _, c := range sc.Spec.CIDRs {
				add(c)
			}
		}
	}
	for _, src := range []struct {
		gvk   schema.GroupVersionKind
		paths [][]string
	}{
		{schema.GroupVersionKind{Group: "cilium.io", Version: "v2alpha1", Kind: "CiliumPodIPPoolList"},
			[][]string{{"spec", "ipv4", "cidrs"}, {"spec", "ipv6", "cidrs"}}},
		{schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNodeList"},
			[][]string{{"spec", "ipam", "podCIDRs"}}},
		{schema.GroupVersionKind{Group: "crd.projectcalico.org", Version: "v1", Kind: "IPPoolList"},
			[][]string{{"spec", "cidr"}}},
	} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(src.gvk)
		if err := r.APIReader.List(ctx, list); err != nil {
			continue // CNI not installed or no permission: nothing to add
		}
		for _, item := range list.Items {
			for _, path := range src.paths {
				if v, ok, _ := unstructured.NestedString(item.Object, path...); ok {
					add(v)
				}
				if vs, ok, _ := unstructured.NestedStringSlice(item.Object, path...); ok {
					for _, v := range vs {
						add(v)
					}
				}
			}
		}
	}
	for _, c := range r.PhantomExtraCIDRs {
		add(c)
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return out
}

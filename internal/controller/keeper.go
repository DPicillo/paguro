// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

// Backend keeper: keeps the migrated pod's old address alive as a Service
// backend while connections through a stateful load balancer still use it.
//
// Load balancers that keep a backend per connection (Cilium's eBPF load
// balancer for NodePort/LoadBalancer traffic, Calico's eBPF dataplane,
// kube-proxy in IPVS mode) look up that backend for every packet. When the
// old pod's endpoint leaves the Service, Cilium re-selects a backend for the
// connection and SNATs it with a *new* source port – measured: 48572 became
// 57445, the restored socket did not recognize the connection and the
// client got a reset.
//
// Paguro creates one Service without a selector per migration, whose only
// endpoint is the old address with the target ports of every Service that
// selects the pod; the load balancer keeps the address's backend while the
// keeper references it.
//
// Only in Phantom mode (the address changes). With a kept IP the endpoint
// bridge (bridge.go) keeps the address in the pod's own Services across the
// gap, and a keeper would do harm: Cilium 1.20 keeps backends per Service,
// so deleting the keeper deletes a backend of the address, and Cilium then
// destroys every UDP socket connected to the address
// (reconciler/termination.go) – measured: all of a game server's connected
// clients got ECONNABORTED 30 s after each migration, when the keeper went. The backend – and the
// load balancer's per-connection state – stays valid; Phantom mode translates
// the old address to the new one on the wire. Tested: an external client
// through a Cilium NodePort kept its connection across a Phantom migration and
// after the source pod was gone. Without the keeper it was reset.
//
// Nothing ever connects to the keeper's ClusterIP. It is removed when the
// migrated connections have ended (Phantom mode) or shortly after the
// migration succeeded (kept IP), and with the Migration through its owner
// reference.

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/pkg/names"
)

const (
	// keeperManagedBy: the EndpointSlice controller ignores slices with a
	// managed-by value other than its own.
	keeperManagedBy = "paguro.dev"
	labelKeeperFor  = names.LabelMigrationUID
	// keeperLingerKeptIP is how long the keeper stays after a migration
	// that kept the IP succeeded: until the load balancers have the
	// replacement's endpoint.
	keeperLingerKeptIP = 30 * time.Second
)

func keeperName(mig *v1alpha1.Migration) string {
	return "paguro-keep-" + names.UIDSuffix(string(mig.UID))
}

// ensureBackendKeeper creates the keeper Service and its EndpointSlice for
// the source pod's Services. No-op when no Service selects the pod.
func (r *MigrationReconciler) ensureBackendKeeper(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod) error {
	if pod == nil || mig.Status.SourcePodIP == "" || mig.Status.IPPreserved {
		return nil
	}
	ports, err := r.servicePortsOf(ctx, pod)
	if err != nil || len(ports) == 0 {
		return err
	}
	name := keeperName(mig)
	meta := func() metav1.ObjectMeta {
		return metav1.ObjectMeta{
			Name: name, Namespace: mig.Namespace,
			Labels: map[string]string{labelKeeperFor: string(mig.UID)},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1alpha1.GroupVersion.String(), Kind: "Migration", Name: mig.Name, UID: mig.UID,
			}},
		}
	}
	svc := &corev1.Service{ObjectMeta: meta()}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: meta(), AddressType: discoveryv1.AddressTypeIPv4}
	slice.Labels[discoveryv1.LabelServiceName] = name
	slice.Labels[discoveryv1.LabelManagedBy] = keeperManagedBy
	if strings.Contains(mig.Status.SourcePodIP, ":") {
		slice.AddressType = discoveryv1.AddressTypeIPv6
	}
	for _, a := range keeperAddresses(mig) {
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{a},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		})
	}
	for i, p := range ports {
		pname := fmt.Sprintf("p%d", i)
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name: pname, Port: p.port, TargetPort: intstr.FromInt32(p.port), Protocol: p.proto,
		})
		slice.Ports = append(slice.Ports, discoveryv1.EndpointPort{
			Name: ptr.To(pname), Port: ptr.To(p.port), Protocol: ptr.To(p.proto),
		})
	}
	for _, o := range []client.Object{svc, slice} {
		if err := r.Create(ctx, o); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("backend keeper %s: %w", name, err)
		}
	}
	return nil
}

// keeperAddresses: the source's IP and, in Phantom mode, every local address
// of a migrated connection. After chained migrations a connection can still
// use an earlier IP of the pod – and the load balancer's state still points
// at that one; the keeper of the earlier migration is gone by then.
func keeperAddresses(mig *v1alpha1.Migration) []string {
	out := []string{mig.Status.SourcePodIP}
	if ph := mig.Status.Source.Phantom; ph != nil {
		for _, f := range ph.Flows {
			if ap, err := netip.ParseAddrPort(f.Local); err == nil {
				if a := ap.Addr().String(); !slices.Contains(out, a) {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

type podPort struct {
	port  int32
	proto corev1.Protocol
}

// servicePortsOf returns the distinct target ports (resolved against the
// pod) of every Service in the pod's namespace that selects it.
func (r *MigrationReconciler) servicePortsOf(ctx context.Context, pod *corev1.Pod) ([]podPort, error) {
	svcs := &corev1.ServiceList{}
	if err := r.List(ctx, svcs, client.InNamespace(pod.Namespace)); err != nil {
		return nil, err
	}
	seen := map[podPort]bool{}
	var out []podPort
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if len(svc.Spec.Selector) == 0 || !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(pod.Labels)) {
			continue
		}
		for _, sp := range svc.Spec.Ports {
			port, ok := resolveTargetPort(sp, pod)
			p := podPort{port, sp.Protocol}
			if ok && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// resolveTargetPort maps a Service port to the pod's port number (named
// target ports are looked up in the pod's containers).
func resolveTargetPort(sp corev1.ServicePort, pod *corev1.Pod) (int32, bool) {
	tp := sp.TargetPort
	switch {
	case tp.Type == intstr.Int && tp.IntVal != 0:
		return tp.IntVal, true
	case tp.Type == intstr.Int:
		return sp.Port, true // targetPort omitted: same as port
	}
	for _, c := range pod.Spec.Containers {
		for _, p := range c.Ports {
			if p.Name == tp.StrVal && p.Protocol == sp.Protocol {
				return p.ContainerPort, true
			}
		}
	}
	return 0, false
}

// keeperDue reports whether a terminal migration's keeper can go, and if not
// yet, when to check again.
func (r *MigrationReconciler) keeperDue(mig *v1alpha1.Migration) (bool, time.Duration) {
	st := &mig.Status
	switch {
	case st.Phase != v1alpha1.PhaseSucceeded:
		return true, 0
	case st.NetworkAdapter == netadapter.NamePhantom:
		// Until every migrated connection has ended.
		return st.Target.Phantom == nil || st.Target.Phantom.ReleasedAt != nil, 0
	case st.CompletedAt == nil:
		return true, 0
	default:
		left := keeperLingerKeptIP - r.Clock.Since(st.CompletedAt.Time)
		return left <= 0, left
	}
}

// pruneKeeper drops the old addresses that a node reported as no longer
// routed into the cluster (status.phantomUnroutable) from the keeper: kept
// as a backend, such an address makes Cilium send the connection out of the
// cluster, where it hangs until the client's TCP timeout. Without it the
// load balancer picks the new backend and the client gets a reset at once.
// The keeper goes when nothing is left. kube-proxy keeps such connections
// through conntrack and the agents' routes either way.
func (r *MigrationReconciler) pruneKeeper(ctx context.Context, mig *v1alpha1.Migration) error {
	lost := mig.Status.PhantomUnroutable
	if len(lost) == 0 {
		return nil
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: keeperName(mig)}, slice); err != nil {
		return client.IgnoreNotFound(err)
	}
	var dropped []string
	slice.Endpoints = slices.DeleteFunc(slice.Endpoints, func(ep discoveryv1.Endpoint) bool {
		if len(ep.Addresses) == 0 {
			return false
		}
		if _, gone := lost[ep.Addresses[0]]; gone {
			dropped = append(dropped, ep.Addresses[0])
			return true
		}
		return false
	})
	if len(dropped) == 0 {
		return nil
	}
	var err error
	if len(slice.Endpoints) == 0 {
		err = r.deleteBackendKeeper(ctx, mig)
	} else {
		err = r.Update(ctx, slice)
	}
	if err == nil {
		r.emitTyped(mig, corev1.EventTypeWarning, "BackendKeeper", fmt.Sprintf(
			"%v no longer routed into the cluster (old node gone?): dropped from the backend keeper – "+
				"connections through NodePort/LoadBalancer Services to it are reset instead of hanging", dropped))
	}
	return err
}

// deleteBackendKeeper removes the keeper Service and EndpointSlice.
func (r *MigrationReconciler) deleteBackendKeeper(ctx context.Context, mig *v1alpha1.Migration) error {
	name := keeperName(mig)
	var errs []error
	for _, o := range []client.Object{
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: mig.Namespace}},
		&discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: mig.Namespace}},
	} {
		if err := r.Delete(ctx, o); client.IgnoreNotFound(err) != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("deleting backend keeper %s: %v", name, errs)
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

// Endpoint bridge: keeps a ready address in every Service of the migrated
// pod across the hand-over, so that new connections arriving meanwhile are
// delayed, not refused or stranded.
//
// Measured on Cilium, an in-cluster client opening a fresh connection to the
// ClusterIP every 25 ms:
//   - IP kept: between the source pod's deletion and the replacement becoming
//     ready the Service had no ready endpoint (~1 s). 38 connections failed
//     at once ("Host is unreachable"); a headless Service resolved to no
//     address at all.
//   - Phantom mode: connections chose the old address, and their SYN
//     retransmissions stayed with it – socket-LB fixes the backend at
//     connect(), kube-proxy's conntrack entry keeps it. Not part of the
//     flows harvested at the freeze, they were not translated and hung until
//     the client's timeout (26 of them).
//
// Through a NodePort, by contrast, nothing failed: Cilium chose a backend
// again for the retransmitted SYN.
//
// The bridge is one EndpointSlice per Service that selects the pod, managed
// by Paguro (the EndpointSlice controller ignores it), with the address that
// will serve as ready: the kept IP, or the replacement's new IP.
//
// Cilium (1.20.2, pkg/loadbalancer/reflectors/k8s.go) reads EndpointSlice
// events in batches (a 500 ms ticker). For each slice in a batch it deletes
// the addresses that slice no longer lists – even while another slice of
// the Service still lists them – and then upserts the addresses of all
// slices in the batch; the last state of an address wins. An address given
// up by one slice therefore survives only if an event of a slice that still
// lists it is in the same batch; otherwise the backend is gone until that
// slice changes again (tested: two slices with one address, one deleted →
// no backend; the other one touched → back). And a deleted or no longer
// active backend makes Cilium destroy every UDP socket connected to it
// through socket-LB (reconciler/termination.go): game clients get
// ECONNABORTED. Measured: deleting the bridge and then touching the
// Service's own slice once destroyed the clients' UDP sockets in 1 of 5
// tries – whenever the ticker fell between the two events.
//
// So on Cilium, whenever one slice gives up the address while another one
// keeps it, Paguro touches the one that keeps it every 50 ms – many touches
// per batch
// – for as long as the change can arrive, plus one batch: the bridge from
// the source pod's deletion – or, for a replacement that gets its address
// only after it, from the bridge's creation (bridgeLate) – until the
// Services' own slices no longer list the source and list the bridged
// address as ready (coverSourceLeaving), the Services' own slices from half
// a second before the bridge's deletion until 0.7 s after it
// (deleteEndpointBridge). Every touch is a write to the API server and an
// event for every watcher of EndpointSlices (each node's proxy): the
// touches of all migrations together are capped (touchLimit), and other
// proxies – kube-proxy applies every event as it comes – get none.
//
// The bridge goes up before the source pod leaves the Services and stays
// until the replacement's own endpoint has had time to reach every proxy. Until the
// restore the address's SYNs are dropped – the source is frozen behind its
// shield, the target sandbox is shielded – the client retransmits and is
// served after the restore.
//
// With a new IP, too. The first version left those migrations without a
// bridge, on the assumption that the source's endpoint, terminating, covers
// the gap: proxies fall back to terminating endpoints only while they are
// serving, and the frozen source fails its readiness probe within seconds.
// Measured on EKS (kube-proxy, Phantom mode, a readiness probe with a 30 s
// initial delay on the replacement): every new connection to the Service
// was refused for 19 s. Two limits remain with kube-proxy, which picks one
// of two entries for the same address in different slices at random (map
// order) when neither is terminating: while the replacement's own slice
// lists it not ready, the bridge wins only some of kube-proxy's syncs. The
// replacement's readiness probe therefore starts without its initial delay
// (webhook.FastReadiness), and a connection attempt that went to the old
// address is handed back to the Service by the nodes' agents
// (agent/phantomsyn.go).

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
	"paguro.dev/paguro/pkg/names"
)

const (
	labelBridge = "paguro.dev/endpoint-bridge"
	// bridgeLinger: how long the bridge stays after the replacement is ready
	// – until its own endpoint has reached every proxy and gateway.
	bridgeLinger = 10 * time.Second
	// bridgeMax bounds the bridge of a replacement that never becomes ready.
	bridgeMax = 5 * time.Minute
)

// bridgeAddress is the address that serves after the hand-over: the kept IP,
// or the replacement's new IP once its sandbox has one.
func bridgeAddress(mig *v1alpha1.Migration, target *corev1.Pod) string {
	if mig.Status.IPPreserved {
		return mig.Status.SourcePodIP
	}
	if target != nil {
		return target.Status.PodIP
	}
	return ""
}

// ensureEndpointBridge creates the bridge for the Services that select the
// source pod. Once per migration (status.cutover.endpointBridgeAt); without a
// serving address yet (new IP, replacement without sandbox) it is retried.
func (r *MigrationReconciler) ensureEndpointBridge(ctx context.Context, mig *v1alpha1.Migration, source, target *corev1.Pod) error {
	if mig.Status.Cutover.EndpointBridgeAt != nil || source == nil {
		return nil
	}
	addr := bridgeAddress(mig, target)
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil // no serving address yet
	}
	svcs := &corev1.ServiceList{}
	if err := r.List(ctx, svcs, client.InNamespace(mig.Namespace)); err != nil {
		return err
	}
	var bridges []*discoveryv1.EndpointSlice
	var names []string
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if len(svc.Spec.Selector) == 0 || !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(source.Labels)) {
			continue
		}
		slice := bridgeSlice(mig, svc, source, target, ip)
		if len(slice.Ports) == 0 {
			continue
		}
		bridges = append(bridges, slice)
		names = append(names, slice.Name)
	}
	// The names first: a slice whose creation is not recorded would never
	// be deleted and keep the address ready in its Service – also after the
	// address went to another pod.
	if len(names) > 0 && !slices.Equal(mig.Status.Cutover.EndpointBridge, names) {
		if err := r.patchStatusUnlocked(ctx, mig, func(st *v1alpha1.MigrationStatus) {
			st.Cutover.EndpointBridge = names
		}); err != nil {
			return err
		}
	}
	// All at once: this can be on the cutover's critical path.
	errs := make([]error, len(bridges))
	var wg sync.WaitGroup
	for i, slice := range bridges {
		wg.Go(func() {
			if err := r.Create(ctx, slice); err != nil && !apierrors.IsAlreadyExists(err) {
				errs[i] = fmt.Errorf("endpoint bridge for service %s: %w", slice.Labels[discoveryv1.LabelServiceName], err)
			}
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	now := r.now()
	return r.patchStatusUnlocked(ctx, mig, func(st *v1alpha1.MigrationStatus) {
		st.Cutover.EndpointBridgeAt = &now
	})
}

// bridgeEndpoints creates the bridge from the source pod's snapshot (labels
// and ports, independent of the live source) and the replacement, if any.
// Failures are reported; the migration goes on without the bridge. Returns
// whether this call created it.
func (r *MigrationReconciler) bridgeEndpoints(ctx context.Context, mig *v1alpha1.Migration) bool {
	if mig.Status.Cutover.EndpointBridgeAt != nil {
		return false
	}
	source, err := webhook.SourcePodOf(mig)
	if err != nil {
		return false
	}
	target, _ := r.findTargetPod(ctx, mig)
	if err := r.ensureEndpointBridge(ctx, mig, source, target); err != nil {
		r.emitTyped(mig, corev1.EventTypeWarning, "EndpointBridge",
			"new connections during the hand-over may fail: "+err.Error())
		return false
	}
	return mig.Status.Cutover.EndpointBridgeAt != nil
}

// bridgeLate bridges a replacement that got its address only after the
// source's deletion (new IP, an owner that re-creates it then): the usual
// case with a new IP. The bridge comes up now – and is touched from now on
// while the replacement's own slice lists the new address as not ready,
// as the cutover touches a bridge that existed before the deletion. done
// is closed when the touching ends (nil without a new bridge).
func (r *MigrationReconciler) bridgeLate(ctx context.Context, mig *v1alpha1.Migration) (done <-chan struct{}) {
	if !r.bridgeEndpoints(ctx, mig) || mig.Status.Cutover.SourceDeletedAt == nil {
		return nil
	}
	return r.coverSourceLeaving(ctx, mig)
}

// bridgeSlice builds the bridge EndpointSlice of one Service: its port names
// (proxies match slices to Service ports by name) with the target ports
// resolved against the pod, and the serving address as ready.
func bridgeSlice(mig *v1alpha1.Migration, svc *corev1.Service, source, target *corev1.Pod, ip netip.Addr) *discoveryv1.EndpointSlice {
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bridgeSliceName(mig, svc.Name),
			Namespace: mig.Namespace,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: svc.Name,
				discoveryv1.LabelManagedBy:   keeperManagedBy,
				labelKeeperFor:               string(mig.UID),
				labelBridge:                  "true",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: v1alpha1.GroupVersion.String(), Kind: "Migration", Name: mig.Name, UID: mig.UID,
			}},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	if ip.Is6() {
		slice.AddressType = discoveryv1.AddressTypeIPv6
	}
	ep := discoveryv1.Endpoint{
		Addresses: []string{ip.String()},
		Conditions: discoveryv1.EndpointConditions{
			Ready: ptr.To(true), Serving: ptr.To(true), Terminating: ptr.To(false),
		},
		NodeName: ptr.To(mig.Status.TargetNode),
	}
	if target != nil {
		ep.TargetRef = &corev1.ObjectReference{Kind: "Pod", Namespace: target.Namespace, Name: target.Name, UID: target.UID}
	}
	slice.Endpoints = []discoveryv1.Endpoint{ep}
	for _, sp := range svc.Spec.Ports {
		if port, ok := resolveTargetPort(sp, source); ok {
			slice.Ports = append(slice.Ports, discoveryv1.EndpointPort{
				Name: ptr.To(sp.Name), Port: ptr.To(port), Protocol: ptr.To(sp.Protocol),
			})
		}
	}
	return slice
}

func bridgeSliceName(mig *v1alpha1.Migration, svc string) string {
	name := "paguro-bridge-" + names.UIDSuffix(string(mig.UID)) + "-" + svc
	if len(name) > 253 {
		name = name[:253]
	}
	return name
}

// touchLimit caps the touches of all migrations together (patches per
// second): with many migrations at once – a drain of several nodes – each
// slice is touched less often instead of the API server taking ever more
// writes. 100 per second still touch 50 slices once per reflector batch.
var touchLimit = rate.NewLimiter(100, 20)

func (r *MigrationReconciler) limiter() *rate.Limiter {
	if r.touchLimit != nil {
		return r.touchLimit
	}
	return touchLimit
}

// touchesHelp reports whether touching slices helps: only Cilium's
// reflector reads EndpointSlice events in batches (see the package
// comment). kube-proxy and the other proxies apply every event as it comes;
// there a touch would only load the API server and every watcher.
func (r *MigrationReconciler) touchesHelp(ctx context.Context, mig *v1alpha1.Migration) bool {
	if r.Adapter != nil && r.Adapter().Name() == netadapter.NameCilium {
		return true
	}
	return r.nodeCNI(ctx, mig.Status.TargetNode).Name == netadapter.CNICilium
}

// touchSlices patches an annotation on EndpointSlices so that Cilium reads
// them again (see the package comment above), starting with slices[first]
// (the slices take turns when the cap leaves too few touches). Best effort.
func (r *MigrationReconciler) touchSlices(ctx context.Context, namespace string, slices []string, first int) {
	body := []byte(fmt.Sprintf(`{"metadata":{"annotations":{"paguro.dev/touched":%q}}}`, time.Now().UTC().Format(time.RFC3339Nano)))
	lim := r.limiter()
	for i := range slices {
		if !lim.Allow() {
			return
		}
		s := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: slices[(first+i)%len(slices)], Namespace: namespace}}
		_ = r.Patch(ctx, s, client.RawPatch(types.MergePatchType, body))
	}
}

// bridgeTimes is the timing of the touches.
type bridgeTimes struct {
	// touchInterval: many touches per reflector batch (500 ms).
	touchInterval time.Duration
	// coverAfter: touching goes on this long after the change it covers –
	// more than one batch.
	coverAfter time.Duration
	// coverMax bounds coverSourceLeaving (a source pod held by finalizers).
	coverMax time.Duration
	// bridgeLead: the Services' own slices are touched this long before
	// the bridge is deleted – the deletion's batch already contains their
	// events.
	bridgeLead time.Duration
}

var defaultBridgeTimes = bridgeTimes{
	touchInterval: 50 * time.Millisecond,
	coverAfter:    700 * time.Millisecond,
	coverMax:      time.Minute,
	bridgeLead:    500 * time.Millisecond,
}

func (r *MigrationReconciler) times() bridgeTimes {
	if r.bridgeTimes != nil {
		return *r.bridgeTimes
	}
	return defaultBridgeTimes
}

// touchEvery touches slices every touchInterval until stop is called.
func (r *MigrationReconciler) touchEvery(namespace string, slices []string) (stop func()) {
	bt := r.times()
	ctx, cancel := context.WithTimeout(context.Background(), bt.coverMax)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := 0; ctx.Err() == nil; n++ {
			r.touchSlices(ctx, namespace, slices, n)
			select {
			case <-ctx.Done():
			case <-time.After(bt.touchInterval):
			}
		}
	}()
	return func() { cancel(); <-done }
}

// coverSourceLeaving keeps the bridge winning while the source pod leaves
// the Services' own slices: they drop the kept IP only when kubelet has
// removed the pod, a moment Paguro does not control. Touches the bridge
// until no slice of the bridged Services lists the source any more, and
// coverAfter beyond. Only where touches help (touchesHelp). done is closed
// when the touching ends.
func (r *MigrationReconciler) coverSourceLeaving(ctx context.Context, mig *v1alpha1.Migration) (done <-chan struct{}) {
	ch := make(chan struct{})
	bridge := mig.Status.Cutover.EndpointBridge
	if len(bridge) == 0 || mig.Status.SourcePodUID == "" || !r.touchesHelp(ctx, mig) {
		close(ch)
		return ch
	}
	ns, source := mig.Namespace, types.UID(mig.Status.SourcePodUID)
	bt := r.times()
	stop := r.touchEvery(ns, bridge)
	go func() {
		defer close(ch)
		defer stop()
		ctx, cancel := context.WithTimeout(context.Background(), bt.coverMax)
		defer cancel()
		// The bridged address: the kept IP, or the replacement's new one,
		// which its own slice lists as not ready until it is.
		svcs, ip := r.bridgedServices(ctx, ns, bridge)
		for ctx.Err() == nil && r.slicesUnsettled(ctx, ns, svcs, source, ip) {
			time.Sleep(bt.touchInterval)
		}
		time.Sleep(bt.coverAfter)
	}()
	return ch
}

// bridgedServices returns the Services the bridge slices belong to and the
// address they bridge.
func (r *MigrationReconciler) bridgedServices(ctx context.Context, namespace string, bridge []string) (svcs []string, addr string) {
	for _, name := range bridge {
		slice := &discoveryv1.EndpointSlice{}
		if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, slice); err == nil {
			svcs = append(svcs, slice.Labels[discoveryv1.LabelServiceName])
			if len(slice.Endpoints) > 0 && len(slice.Endpoints[0].Addresses) > 0 {
				addr = slice.Endpoints[0].Addresses[0]
			}
		}
	}
	return svcs, addr
}

// slicesUnsettled reports whether a slice of the Services other than a
// bridge still lists the source pod, or lists the bridged address ip as not
// ready (errors count as unsettled). A replacement under the source's name
// (StatefulSet, GameServer) appears in the Services' slices with the kept
// address, not ready, while it restores: every change of such a slice
// would deactivate the backend – and make Cilium destroy the clients' UDP
// sockets – unless the bridge is touched in the same batch (measured: 2 of
// 4 game clients through the ClusterIP got ECONNABORTED at the restore).
func (r *MigrationReconciler) slicesUnsettled(ctx context.Context, namespace string, svcs []string, pod types.UID, ip string) bool {
	for _, svc := range svcs {
		list := &discoveryv1.EndpointSliceList{}
		if err := r.APIReader.List(ctx, list, client.InNamespace(namespace), client.MatchingLabels{discoveryv1.LabelServiceName: svc}); err != nil {
			return true
		}
		for _, s := range list.Items {
			if s.Labels[labelBridge] != "" {
				continue
			}
			for _, ep := range s.Endpoints {
				if ep.TargetRef != nil && ep.TargetRef.UID == pod {
					return true
				}
				if ip != "" && slices.Contains(ep.Addresses, ip) && (ep.Conditions.Ready == nil || !*ep.Conditions.Ready) {
					return true
				}
			}
		}
	}
	return false
}

// bridgeDue reports whether a terminal migration's bridge can go: at once
// unless it succeeded; then once the replacement has been ready for
// bridgeLinger (its own endpoint has spread), at the latest bridgeMax after
// the end.
func (r *MigrationReconciler) bridgeDue(ctx context.Context, mig *v1alpha1.Migration) (bool, time.Duration) {
	st := &mig.Status
	if len(st.Cutover.EndpointBridge) == 0 {
		return true, 0
	}
	if st.Phase != v1alpha1.PhaseSucceeded || st.CompletedAt == nil {
		return true, 0
	}
	if r.Clock.Since(st.CompletedAt.Time) > bridgeMax {
		return true, 0
	}
	pod := &corev1.Pod{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: st.TargetPodName}, pod); err != nil {
		return apierrors.IsNotFound(err), time.Second
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			left := bridgeLinger - r.Clock.Since(c.LastTransitionTime.Time)
			return left <= 0, max(left, time.Second)
		}
	}
	return false, time.Second
}

// deleteEndpointBridge removes the bridge's EndpointSlices – where touches
// help, while the Services' own slices are touched every touchInterval,
// from bridgeLead before the deletion until coverAfter after it (see the
// package comment); that blocks for about a second.
func (r *MigrationReconciler) deleteEndpointBridge(ctx context.Context, mig *v1alpha1.Migration) error {
	if len(mig.Status.Cutover.EndpointBridge) == 0 {
		return nil
	}
	touch := r.touchesHelp(ctx, mig)
	var bridges []*discoveryv1.EndpointSlice
	var others []string
	for _, name := range mig.Status.Cutover.EndpointBridge {
		slice := &discoveryv1.EndpointSlice{}
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: name}, slice)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		bridges = append(bridges, slice)
		if !touch {
			continue
		}
		list := &discoveryv1.EndpointSliceList{}
		if err := r.APIReader.List(ctx, list, client.InNamespace(mig.Namespace),
			client.MatchingLabels{discoveryv1.LabelServiceName: slice.Labels[discoveryv1.LabelServiceName]}); err != nil {
			return err
		}
		for _, s := range list.Items {
			if s.Labels[labelBridge] == "" {
				others = append(others, s.Name)
			}
		}
	}
	if len(bridges) > 0 {
		bt := r.times()
		stop := func() {}
		if touch {
			stop = r.touchEvery(mig.Namespace, others)
			sleepCtx(ctx, bt.bridgeLead)
		}
		var errs []error
		for _, slice := range bridges {
			if err := r.Delete(ctx, slice); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("deleting endpoint bridge %s: %w", slice.Name, err))
			}
		}
		if touch {
			sleepCtx(ctx, bt.coverAfter)
		}
		stop()
		if err := errors.Join(errs...); err != nil {
			return err
		}
	}
	return r.patchStatusUnlocked(ctx, mig, func(st *v1alpha1.MigrationStatus) { st.Cutover.EndpointBridge = nil })
}

// sleepCtx waits d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

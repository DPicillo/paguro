// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

func TestDecideNetwork(t *testing.T) {
	const (
		calicoCNI = "calico;calico/calico-ipam"
		canalCNI  = "canal;calico/host-local"
	)
	node := func(name, cni, phantom string) *corev1.Node {
		n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{}},
			Spec:   corev1.NodeSpec{PodCIDRs: []string{"10.1.0.0/24"}},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.10"}}}}
		if cni != "" {
			n.Annotations[v1alpha1.AnnotationNodeCNI] = cni
		}
		if phantom != "" {
			n.Annotations[v1alpha1.AnnotationNodePhantom] = phantom
		}
		return n
	}
	cases := []struct {
		name        string
		cni         [2]string
		phantom     [2]string
		phantomAuto bool
		spec        v1alpha1.NetworkMode
		podNetwork  string
		wantAdapter string
		wantKeep    bool
		wantErr     string
		wantWarn    string
		sticky      bool
		translated  bool // restored by an earlier Phantom migration
	}{
		{name: "calico keeps the IP", cni: [2]string{calicoCNI, calicoCNI}, phantomAuto: true,
			wantAdapter: netadapter.NameCalico, wantKeep: true},
		{name: "canal cannot move IPs: Phantom", cni: [2]string{canalCNI, canalCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable}, phantomAuto: true,
			wantAdapter: netadapter.NamePhantom, wantWarn: "Phantom mode"},
		{name: "one node without Phantom: generic", cni: [2]string{canalCNI, canalCNI}, phantom: [2]string{PhantomAvailable, ""}, phantomAuto: true,
			wantAdapter: netadapter.NameGeneric, wantWarn: "will be closed"},
		{name: "Phantom auto disabled: generic", cni: [2]string{canalCNI, canalCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable},
			wantAdapter: netadapter.NameGeneric},
		{name: "pod opts into Phantom", cni: [2]string{calicoCNI, calicoCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable}, podNetwork: "phantom",
			wantAdapter: netadapter.NamePhantom},
		{name: "Preserve on canal is rejected", cni: [2]string{calicoCNI, canalCNI}, spec: v1alpha1.NetworkPreserve,
			wantErr: "cannot move a pod IP"},
		{name: "explicit Generic", cni: [2]string{calicoCNI, calicoCNI}, spec: v1alpha1.NetworkGeneric,
			wantAdapter: netadapter.NameGeneric},
		{name: "explicit Phantom warns about nodes without it", cni: [2]string{calicoCNI, calicoCNI}, phantom: [2]string{PhantomAvailable, ""}, spec: v1alpha1.NetworkPhantom,
			wantAdapter: netadapter.NamePhantom, wantWarn: "nodes without a Phantom-capable agent"},
		{name: "Phantom on a sticky IP is rejected", cni: [2]string{calicoCNI, calicoCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable},
			spec: v1alpha1.NetworkPhantom, sticky: true, wantErr: "sticky IP"},
		{name: "Auto never picks Phantom for a sticky pod", cni: [2]string{canalCNI, canalCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable}, phantomAuto: true,
			sticky: true, wantAdapter: netadapter.NameGeneric, wantWarn: "will be closed"},
		{name: "a sticky pod annotated phantom is rejected too", cni: [2]string{calicoCNI, calicoCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable},
			podNetwork: "phantom", sticky: true, wantErr: "sticky IP"},
		{name: "after a Phantom migration Auto stays Phantom although Calico could keep the IP", cni: [2]string{calicoCNI, calicoCNI},
			phantom: [2]string{PhantomAvailable, PhantomAvailable}, phantomAuto: true, translated: true, wantAdapter: netadapter.NamePhantom},
		{name: "after a Phantom migration Preserve is rejected", cni: [2]string{calicoCNI, calicoCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable},
			spec: v1alpha1.NetworkPreserve, translated: true, wantErr: "earlier Phantom migration"},
		// Unknown values are rejected, not read as Auto (which would keep
		// the IP here, although the pod asked for a new one).
		{name: "an unknown annotation value is rejected", cni: [2]string{calicoCNI, calicoCNI}, phantom: [2]string{PhantomAvailable, PhantomAvailable}, phantomAuto: true,
			podNetwork: "keep", wantErr: `pod annotation paguro.dev/network: unknown network mode "keep" (want auto, preserve, phantom or generic)`},
		{name: "annotation values in any case", cni: [2]string{calicoCNI, calicoCNI}, podNetwork: "Generic",
			wantAdapter: netadapter.NameGeneric},
		{name: "an unknown stored spec.network is rejected", cni: [2]string{calicoCNI, calicoCNI}, spec: "Keep",
			wantErr: `spec.network: unknown network mode "Keep"`},
		{name: "an explicit spec.network does not read the annotation", cni: [2]string{calicoCNI, calicoCNI}, spec: v1alpha1.NetworkGeneric,
			podNetwork: "keep", wantAdapter: netadapter.NameGeneric},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = clientgoscheme.AddToScheme(scheme)
			_ = v1alpha1.AddToScheme(scheme)
			objs := []client.Object{node("node-a", c.cni[0], c.phantom[0]), node("node-b", c.cni[1], c.phantom[1])}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			r := &MigrationReconciler{Client: cl, APIReader: cl, PhantomAuto: c.phantomAuto,
				Adapter: func() netadapter.Adapter { return netadapter.Calico{} }}
			pod := testPod()
			pod.Annotations = map[string]string{}
			if c.podNetwork != "" {
				pod.Annotations[v1alpha1.AnnotationNetwork] = c.podNetwork
			}
			if c.sticky {
				pod.Annotations[v1alpha1.AnnotationStickyIP] = "paguro-10-250-0-2"
			}
			if c.translated {
				pod.Annotations[v1alpha1.AnnotationTCP] = "translate"
			}
			mig := &v1alpha1.Migration{Spec: v1alpha1.MigrationSpec{Network: c.spec}}
			res := preflightResult{targetNode: "node-b"}
			err := r.decideNetwork(context.Background(), mig, pod, &res)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want error %q, got %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.adapter != c.wantAdapter || res.preserved != c.wantKeep {
				t.Fatalf("adapter %q keep %v, want %q keep %v (warnings %v)", res.adapter, res.preserved, c.wantAdapter, c.wantKeep, res.warnings)
			}
			if c.wantWarn != "" && !strings.Contains(strings.Join(res.warnings, "\n"), c.wantWarn) {
				t.Errorf("warnings %v lack %q", res.warnings, c.wantWarn)
			}
			if res.adapter == netadapter.NamePhantom && len(res.network.PhantomClusterCIDRs) == 0 {
				t.Error("Phantom mode without cluster prefixes")
			}
			if want := netadapter.ParseCNIAnnotation(c.cni[0]).Name; res.network.CNI != want {
				t.Errorf("status.network.cni %q, want %q", res.network.CNI, want)
			}
		})
	}
}

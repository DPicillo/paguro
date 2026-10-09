// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

func gameServerPod(p *corev1.Pod) {
	p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "agones.dev/v1", Kind: "GameServer", Name: "web-1",
		UID: "gs-uid", Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)}}
	p.Labels["agones.dev/role"] = "gameserver"
	p.Labels["agones.dev/gameserver"] = "web-1"
	p.Spec.Volumes = nil
	p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 7777, HostPort: 7938, Protocol: corev1.ProtocolUDP}}
}

func gameServer(state string) *unstructured.Unstructured {
	gs := newGameServer(ns, "web-1")
	gs.SetUID("gs-uid")
	_ = unstructured.SetNestedField(gs.Object, state, "status", "state")
	_ = unstructured.SetNestedField(gs.Object, "node-a", "status", "nodeName")
	_ = unstructured.SetNestedField(gs.Object, "10.42.0.97", "status", "address")
	return gs
}

var guardPolicy = &admissionregistrationv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: AgonesGuardPolicy}}

func (e *env) gameServer() *unstructured.Unstructured {
	e.t.Helper()
	gs := newGameServer(ns, "web-1")
	if err := e.c.Get(context.Background(), client.ObjectKeyFromObject(gs), gs); err != nil {
		e.t.Fatal(err)
	}
	return gs
}

// A GameServer's pod is replaced under its own name while the GameServer is
// held (annotation, guarded by the chart's admission policy); afterwards
// the GameServer points at the target node and the hold is gone.
func TestGameServerKeepsItsPod(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(gameServerPod), v1alpha1.MigrationSpec{}, gameServer("Allocated"), guardPolicy)
	// Record the order of what happens to the GameServer and the pods.
	var steps []string
	e.r.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if u, ok := obj.(*unstructured.Unstructured); ok && u.GetKind() == "GameServer" {
				b, _ := patch.Data(obj)
				if strings.Contains(string(b), `"paguro.dev/migrating":null`) {
					steps = append(steps, "release")
				} else {
					steps = append(steps, "hold")
				}
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1.Pod); ok {
				steps = append(steps, "delete source")
			}
			return c.Delete(ctx, obj, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Pod); ok {
				steps = append(steps, "create replacement")
			}
			return c.Create(ctx, obj, opts...)
		},
	})

	m := e.reconcileUntil(v1alpha1.PhasePreCopy)
	if m.Status.Cutover.Mode != v1alpha1.CutoverSameName || m.Status.OwnerKind != "GameServer" || m.Status.Network.CommitGate {
		t.Fatalf("want same-name without commit gate: %+v %+v", m.Status.Cutover, m.Status.Network)
	}
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseRestoring)

	if strings.Join(steps, ", ") != "hold, delete source, create replacement, release" {
		t.Fatalf("order: %v", steps)
	}
	p := e.targetPod()
	if p.Name != "web-1" || p.UID == "src-uid" || p.Spec.NodeName != "node-b" || p.Labels["agones.dev/role"] != "gameserver" ||
		len(p.OwnerReferences) != 1 || p.OwnerReferences[0].UID != "gs-uid" || p.Annotations[v1alpha1.AnnotationRestoreID] != "mig-uid" {
		t.Fatalf("replacement: %s %s node=%s labels=%v owners=%v", p.Name, p.UID, p.Spec.NodeName, p.Labels, p.OwnerReferences)
	}
	gs := e.gameServer()
	node, _, _ := unstructured.NestedString(gs.Object, "status", "nodeName")
	addr, _, _ := unstructured.NestedString(gs.Object, "status", "address")
	state, _, _ := unstructured.NestedString(gs.Object, "status", "state")
	if node != "node-b" || addr != "10.42.0.98" || state != "Allocated" || gs.GetAnnotations()[v1alpha1.AnnotationMigrating] != "" {
		t.Fatalf("GameServer: node=%s address=%s state=%s annotations=%v", node, addr, state, gs.GetAnnotations())
	}
}

// Without the guard policy, or for a GameServer that is not running, the
// pod stays where it is.
func TestGameServerPreflight(t *testing.T) {
	for name, c := range map[string]struct {
		extra []client.Object
		want  string
	}{
		"no guard": {[]client.Object{gameServer("Allocated")}, "Agones integration not installed"},
		"shutdown": {[]client.Object{gameServer("Shutdown"), guardPolicy}, "is Shutdown"},
		"missing":  {[]client.Object{guardPolicy}, "GameServer web-1 not found"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, netadapter.Generic{}, testPod(gameServerPod), v1alpha1.MigrationSpec{}, c.extra...)
			m := e.reconcileUntil(v1alpha1.PhaseFailed)
			if !strings.Contains(m.Status.Message, c.want) || !e.sourceExists() {
				t.Fatalf("message %q lacks %q (source exists: %v)", m.Status.Message, c.want, e.sourceExists())
			}
		})
	}
}

// A migration that ends after the hold but before a replacement exists
// hands the GameServer back to Agones.
func TestGameServerHoldLiftedOnFailure(t *testing.T) {
	gs := gameServer("Allocated")
	gs.SetAnnotations(map[string]string{v1alpha1.AnnotationMigrating: "mig-uid"})
	e := newEnv(t, netadapter.Generic{}, testPod(gameServerPod), v1alpha1.MigrationSpec{}, gs, guardPolicy)
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Phase = v1alpha1.PhaseFailed
		st.Cutover.Mode = v1alpha1.CutoverSameName
		st.OwnerKind, st.OwnerName = "GameServer", "web-1"
	})
	e.reconcile()
	if held := e.gameServer().GetAnnotations()[v1alpha1.AnnotationMigrating]; held != "" {
		t.Fatalf("hold left on the GameServer: %q", held)
	}
}

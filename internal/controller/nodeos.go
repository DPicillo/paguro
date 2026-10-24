// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"encoding/json"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"paguro.dev/paguro/api/v1alpha1"
)

// OSBottlerocket is LabelNodeOS's value on Bottlerocket nodes.
const OSBottlerocket = "bottlerocket"

// NodeOSLabeler labels the nodes whose operating system needs an agent of
// its own, so that the chart's DaemonSets can tell them apart without any
// setting: Bottlerocket starts privileged containers as control_t, and its
// agent runs as super_t instead (paguro-agent-bottlerocket). Kubelet
// reports the operating system only in the node's status, which no
// DaemonSet can select on. The agents' admission policy for the
// controller allows exactly this label to change.
type NodeOSLabeler struct {
	Client client.Client
}

// SetupWithManager reconciles a node when it appears and when its operating
// system or the label changes – not on every status heartbeat.
func (l *NodeOSLabeler) SetupWithManager(mgr ctrl.Manager) error {
	changed := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			o, ok1 := e.ObjectOld.(*corev1.Node)
			n, ok2 := e.ObjectNew.(*corev1.Node)
			return ok1 && ok2 && (o.Status.NodeInfo.OSImage != n.Status.NodeInfo.OSImage ||
				o.Labels[v1alpha1.LabelNodeOS] != n.Labels[v1alpha1.LabelNodeOS])
		},
		DeleteFunc: func(event.DeleteEvent) bool { return false },
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("node-os").
		For(&corev1.Node{}, builder.WithPredicates(changed)).
		Complete(l)
}

// nodeOS is the label value a node should carry ("" for none).
func nodeOS(n *corev1.Node) string {
	if strings.HasPrefix(n.Status.NodeInfo.OSImage, "Bottlerocket") {
		return OSBottlerocket
	}
	return ""
}

// Reconcile implements reconcile.Reconciler.
func (l *NodeOSLabeler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	n := &corev1.Node{}
	if err := l.Client.Get(ctx, req.NamespacedName, n); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	want, have := nodeOS(n), n.Labels[v1alpha1.LabelNodeOS]
	if want == have || (want == "" && have != OSBottlerocket) {
		return ctrl.Result{}, nil // right already, or someone else's value
	}
	var value any = want
	if want == "" {
		value = nil
	}
	b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]any{v1alpha1.LabelNodeOS: value}}})
	if err := l.Client.Patch(ctx, n, client.RawPatch(types.MergePatchType, b)); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	logf.FromContext(ctx).Info("labelled node", "node", n.Name, v1alpha1.LabelNodeOS, want, "osImage", n.Status.NodeInfo.OSImage)
	return ctrl.Result{}, nil
}

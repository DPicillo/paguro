// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

// Mutation audit.
//
// The webhook mutates a pod labeled paguro.dev/migratable=true when it is
// created: RuntimeClass paguro (own time namespace, MPTCP disabled in its
// network namespace) and, under Cilium, a sticky IP. It fails open – a
// Paguro outage must not keep pods from starting – so a pod created while
// the webhook is unreachable, during a Paguro upgrade for instance, starts
// unmutated. Measured: a pod created in the restart window of the
// controller had neither; its Go server's MPTCP listeners made every
// checkpoint fail. The audit makes such pods visible: one warning event per
// pod and the gauge paguro_unmutated_pods.

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"paguro.dev/paguro/api/v1alpha1"
)

const reasonNotMutated = "NotMutated"

// MutationAudit reports migratable pods the webhook did not mutate. It runs
// on the leader.
type MutationAudit struct {
	Client   client.Client
	Recorder events.EventRecorder
	Metrics  *Metrics
	Interval time.Duration
	// Exclude: namespaces the webhook does not see (its namespaceSelector).
	Exclude map[string]bool

	reported map[types.UID]bool
}

// Start implements manager.Runnable.
func (a *MutationAudit) Start(ctx context.Context) error {
	a.reported = map[types.UID]bool{}
	t := time.NewTicker(a.Interval)
	defer t.Stop()
	for {
		a.scan(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (a *MutationAudit) scan(ctx context.Context) {
	pods := &corev1.PodList{}
	if err := a.Client.List(ctx, pods, client.MatchingLabels{v1alpha1.LabelMigratable: "true"}); err != nil {
		logf.FromContext(ctx).Error(err, "mutation audit: listing pods")
		return
	}
	live := map[types.UID]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if a.Exclude[p.Namespace] || !unmutated(p) {
			continue
		}
		live[p.UID] = true
		if !a.reported[p.UID] && a.Recorder != nil {
			a.Recorder.Eventf(p, nil, corev1.EventTypeWarning, reasonNotMutated, eventAction,
				"created while the Paguro webhook was unreachable: no RuntimeClass %q, so no own time namespace "+
					"and MPTCP left enabled (Go >= 1.24 servers then cannot be checkpointed); restart the pod "+
					"to make it fully migratable", v1alpha1.RuntimeClassName)
		}
	}
	a.reported = live
	if a.Metrics != nil {
		a.Metrics.Unmutated.Set(float64(len(live)))
	}
}

// unmutated: labeled migratable, but without any RuntimeClass (an
// explicitly set one is left alone by the webhook, by design), not a
// restore target, not on its way out.
func unmutated(p *corev1.Pod) bool {
	return p.Labels[v1alpha1.LabelMigratable] == "true" && p.Spec.RuntimeClassName == nil &&
		p.Annotations[v1alpha1.AnnotationRestoreID] == "" && p.DeletionTimestamp == nil &&
		p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed
}

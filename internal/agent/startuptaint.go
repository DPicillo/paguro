// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// ClearStartupTaint removes paguro.dev/agent-not-ready from the node, once
// the agent can take migrations (its endpoint is published). Karpenter
// counts a node with a startup taint as not initialized: a drift drains the
// old node only after the replacement is initialized, and the scheduler and
// Paguro's placement keep away from it until then. Without the taint the
// agent merely tends to be ready first – on EC2 about 25 s before the node.
//
// The patch replaces the node's taints only if the node is unchanged since
// it was read (a test of the resourceVersion), so a taint someone else adds
// meanwhile is never lost; the agent's admission policy allows exactly this
// removal and nothing else in the node's spec.
func (a *Agent) ClearStartupTaint(ctx context.Context) error {
	for range 5 {
		n := &corev1.Node{}
		if err := a.APIReader.Get(ctx, client.ObjectKey{Name: a.NodeName}, n); err != nil {
			return err
		}
		keep := []corev1.Taint{}
		for _, t := range n.Spec.Taints {
			if t.Key != v1.TaintAgentNotReady {
				keep = append(keep, t)
			}
		}
		if len(keep) == len(n.Spec.Taints) {
			return nil
		}
		b, err := json.Marshal([]map[string]any{
			{"op": "test", "path": "/metadata/resourceVersion", "value": n.ResourceVersion},
			{"op": "replace", "path": "/spec/taints", "value": keep},
		})
		if err != nil {
			return err
		}
		err = a.Client.Patch(ctx, n, client.RawPatch(types.JSONPatchType, b))
		if err == nil {
			a.Log.Info("ready: removed the startup taint " + v1.TaintAgentNotReady)
			return nil
		}
		// A failed test (the node changed) is refused as invalid.
		if !apierrors.IsConflict(err) && !apierrors.IsInvalid(err) {
			return err
		}
	}
	return fmt.Errorf("startup taint %s: the node kept changing", v1.TaintAgentNotReady)
}

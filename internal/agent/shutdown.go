// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// Drain lets the migrations this node takes part in finish before the agent
// exits (upgrade, uninstall): it marks the node as draining – the
// controller chooses it for no new migration – and waits until none that
// involves the node is running any more, at most timeout. Measured before:
// a helm upgrade during the pre-copy of a Minecraft server rolled the
// migration back (the target agent restarted, the transfer broke off).
//
// Called on the first SIGTERM while the manager and its cache still run;
// the caller stops the manager afterwards. On return the node advertises no
// agent until the next one starts.
func (a *Agent) Drain(ctx context.Context, timeout time.Duration) {
	start := time.Now()
	a.draining.Store(&start)
	if err := a.AnnotateNode(ctx); err != nil {
		a.Log.Warn("marking the node as draining failed – new migrations may still choose it", "err", err)
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	reported := -1
	var failingSince time.Time
	for {
		active, err := a.activeMigrations(wctx)
		if err == nil && len(active) == 0 {
			break
		}
		if err != nil {
			// The cache may not run yet (a signal right at the start).
			if failingSince.IsZero() {
				failingSince = time.Now()
			}
			if time.Since(failingSince) > drainListTimeout {
				a.Log.Warn("draining: the migrations cannot be listed – exiting", "err", err)
				a.withdraw(ctx)
				return
			}
		} else {
			failingSince = time.Time{}
			if len(active) != reported {
				reported = len(active)
				a.Log.Info("draining: waiting for the migrations on this node to end", "migrations", active)
			}
		}
		select {
		case <-wctx.Done():
			a.Log.Warn("drain timeout – exiting while migrations still run (they roll back or are rescued by the next agent)",
				"migrations", active, "timeout", timeout.String())
			a.withdraw(ctx)
			return
		case <-t.C:
		}
	}
	// Clean-ups of the ended migrations (sandbox stop, pre-attached volumes).
	done := make(chan struct{})
	go func() { a.bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-wctx.Done():
	}
	a.Log.Info("drained", "ms", ms(time.Since(start)))
	a.withdraw(ctx)
}

// drainListTimeout: how long Drain retries listing the migrations.
// drainListAttempt bounds one listing: a cache that never started (a
// signal right at the start, or an agent stuck before its manager ran)
// blocks a List until its context ends – the drain would wait out its
// whole timeout instead of giving up after drainListTimeout. Variables for
// the tests.
var (
	drainListTimeout = 30 * time.Second
	drainListAttempt = 5 * time.Second
)

// activeMigrations lists the running migrations with this node as source
// or target.
func (a *Agent) activeMigrations(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, drainListAttempt)
	defer cancel()
	var list v1.MigrationList
	if err := a.Client.List(ctx, &list); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range list.Items {
		if m.Status.Phase.Terminal() || (m.Status.SourceNode != a.NodeName && m.Status.TargetNode != a.NodeName) {
			continue
		}
		out = append(out, m.Namespace+"/"+m.Name)
	}
	return out, nil
}

// withdraw removes the agent's endpoint from the node: until the next agent
// publishes its own, the node is not eligible (instead of a migration
// failing to reach an agent that is gone).
func (a *Agent) withdraw(ctx context.Context) {
	b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{
		v1.AnnotationNodeAgent:         nil,
		v1.AnnotationNodeAgentDraining: nil,
	}}})
	node := &corev1.Node{}
	node.Name = a.NodeName
	a.annotateMu.Lock()
	defer a.annotateMu.Unlock()
	a.withdrawn.Store(true)
	if err := a.Client.Patch(ctx, node, client.RawPatch(types.MergePatchType, b)); err != nil {
		a.Log.Warn("withdrawing the agent endpoint failed", "err", err)
	}
}

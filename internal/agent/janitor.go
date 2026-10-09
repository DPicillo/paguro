// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/shield"
)

// The RST shield drops every TCP packet of a pod while its restore runs. A
// shield left behind makes a running pod unreachable – found after a node
// reboot: a migrated pod keeps its restore annotations, and its re-created
// sandbox was shielded with no restore to lower it (fixed in the wrapper).
// The janitor is the safety net for any other way that could happen
// (wrapper killed mid-restore, agent restart): it lowers the shield of
// every pod on this node whose restore is no longer pending – unless the
// pod is the source of a migration that has not ended (shieldInUse).
//
// A pod that an earlier migration restored keeps that restore's
// annotations, so it qualifies again when it migrates on (the second hop
// of a chain). Its own freeze raises the shield, and "is a container
// paused?" does not protect it: during the final dump CRIU thaws the
// cgroup to seize the tasks, and runc reports the container as running.
// Measured on EKS (Minecraft, 2nd hop): the janitor's tick fell into the
// 1.3 s dump and lowered the source's shield; the dumped sockets came
// alive again, and when the source processes ended their resets reached
// all seven players through the previous hop's translation – every one
// disconnected right after the restore. The first hop of a chain was
// never affected (its source has no restore annotation).

const janitorInterval = 30 * time.Second

// RunShieldJanitor checks this node's pods until ctx ends.
func (a *Agent) RunShieldJanitor(ctx context.Context) {
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pods := &corev1.PodList{}
		if err := a.Client.List(ctx, pods); err != nil {
			continue
		}
		for i := range pods.Items {
			p := &pods.Items[i]
			uid := p.Annotations[v1.AnnotationRestoreID]
			// Never a pod that is being deleted or frozen: a migration's
			// source keeps its shield until it is gone – lowering it would
			// let the frozen kernel sockets retransmit stale data to peers
			// that already talk to the restored copy.
			if uid == "" || p.Spec.NodeName != a.NodeName || p.Status.Phase != corev1.PodRunning ||
				p.DeletionTimestamp != nil || layout.RestorePending(uid) || a.anyPaused(ctx, p) {
				continue
			}
			netns := a.runningNetns(ctx, p)
			if netns == "" {
				continue
			}
			run := a.Host.ShieldRunner(ctx)
			if out, err := run("", "nsenter", "--net="+netns, "nft", "list", "table", "inet", shield.Table); err != nil || !strings.Contains(out, shield.Table) {
				continue
			}
			// Checked last, right before lowering: a freeze that raised the
			// shield after the checks above belongs to a migration that
			// has existed for seconds (pre-copy comes first).
			if a.shieldInUse(ctx, p) {
				continue
			}
			if err := shield.Lower(run, netns); err == nil {
				a.Log.Warn("lowered a shield left behind in a running pod", "pod", p.Namespace+"/"+p.Name, "restore", uid)
			}
		}
	}
}

// shieldInUse reports whether p is the source of a migration that has not
// ended: its shield (or drain shield) is that migration's, not a leftover
// of the restore that created the pod. The source job in memory counts,
// and – for an agent restarted meanwhile – any Migration of the pod that
// is not in a terminal phase. If the Migrations cannot be listed, the
// shield stays: a leftover only costs time, lowering a live one costs the
// pod's connections.
func (a *Agent) shieldInUse(ctx context.Context, p *corev1.Pod) bool {
	isSource := func(m *v1.Migration) bool {
		if m.Namespace != p.Namespace {
			return false
		}
		if m.Status.SourcePodUID != "" {
			return m.Status.SourcePodUID == string(p.UID)
		}
		return m.Spec.PodName == p.Name
	}
	a.mu.Lock()
	for _, st := range a.states {
		if st.source != nil && isSource(st.source.m) {
			a.mu.Unlock()
			return true
		}
	}
	a.mu.Unlock()
	migs := &v1.MigrationList{}
	if err := a.Client.List(ctx, migs, client.InNamespace(p.Namespace)); err != nil {
		return true
	}
	for i := range migs.Items {
		if m := &migs.Items[i]; !m.Status.Phase.Terminal() && isSource(m) {
			return true
		}
	}
	return false
}

// anyPaused reports whether a container of p is frozen (a migration's
// source between freeze and deletion).
func (a *Agent) anyPaused(ctx context.Context, p *corev1.Pod) bool {
	for _, s := range p.Status.ContainerStatuses {
		if _, id, ok := strings.Cut(s.ContainerID, "://"); ok {
			if st, err := a.Host.State(ctx, id); err == nil && st.Status == "paused" {
				return true
			}
		}
	}
	return false
}

// runningNetns returns /proc/<pid>/ns/net of a running container of p.
func (a *Agent) runningNetns(ctx context.Context, p *corev1.Pod) string {
	for _, s := range p.Status.ContainerStatuses {
		if s.State.Running == nil {
			continue
		}
		if _, id, ok := strings.Cut(s.ContainerID, "://"); ok {
			if st, err := a.Host.State(ctx, id); err == nil && st.Pid > 0 {
				return fmt.Sprintf("/proc/%d/ns/net", st.Pid)
			}
		}
	}
	return ""
}

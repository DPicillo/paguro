// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/ctguard"
	"paguro.dev/paguro/internal/images"
	"paguro.dev/paguro/internal/layout"
)

// targetJob executes the target side of a migration.
type targetJob struct {
	a   *Agent
	log *slog.Logger
	m   *v1.Migration
	// poolArrived reports that the sticky /32 is in this node's CiliumNode.
	poolArrived bool
}

// prepare pre-pulls the images, pre-attaches RWO volumes where the storage
// allows it, and reports readiness. Otherwise the image
// pull is a classic outlier in the freeze: a 500 MB image takes several
// seconds over 1 GbE.
func (j *targetJob) prepare(ctx context.Context) error {
	pod := &corev1.Pod{} // the source pod, on another node: not in the cache
	if err := j.a.APIReader.Get(ctx, types.NamespacedName{Namespace: j.m.Namespace, Name: j.m.Spec.PodName}, pod); err != nil {
		return err
	}
	// Exactly the images the source node runs (internal/images): the
	// replacement is pinned to them.
	pinned := images.ForPod(pod)
	imgs := map[string]bool{}
	for _, list := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, c := range list {
			if p, ok := pinned[c.Name]; ok {
				imgs[p] = true
			} else {
				imgs[c.Image] = true
			}
		}
	}
	// Pre-attach runs in parallel with the image pull; both happen before the
	// target reports ready, i.e. before pre-copy and long before the freeze.
	attached := make(chan []preAttached, 1)
	if j.a.PreAttach {
		go func() { attached <- j.preAttach(ctx, pod) }()
	} else {
		attached <- nil
	}
	for img := range imgs {
		start := time.Now()
		// Pinned by digest: present means identical, no registry round trip.
		if strings.Contains(img, "@sha256:") {
			if _, err := j.a.Host.Run(ctx, nil, "crictl", "inspecti", "-q", img); err == nil {
				j.log.Info("image present", "image", img)
				continue
			}
		}
		if _, err := j.a.Host.Run(ctx, nil, "crictl", "pull", img); err != nil {
			return fmt.Errorf("image %s: %w", img, err)
		}
		j.log.Info("image pre-pulled", "image", img, "ms", ms(time.Since(start)))
	}
	if err := os.MkdirAll(layout.Root(string(j.m.UID)), 0o700); err != nil {
		return err
	}
	msg := "ready to receive"
	volumes := []string{}
	if pa := <-attached; len(pa) > 0 {
		msg = fmt.Sprintf("ready to receive, %d volume(s) pre-attached", len(pa))
		for _, p := range pa {
			volumes = append(volumes, p.Volume)
		}
	}
	return j.a.patchStatus(ctx, j.m, map[string]any{"target": map[string]any{
		"ready": true, "endpoint": j.a.transferEndpoint(), "message": msg, "preAttachedVolumes": volumes,
	}})
}

// watchRestore waits until the wrapper has restored (or cold-started) all
// containers and reports the result.
func (j *targetJob) watchRestore(ctx context.Context) error {
	uid := string(j.m.UID)
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	sandboxReported := false
	natGuarded := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		// Report the sandbox as soon as the wrapper has created it: a source
		// that waits for it (FreezeAfterTargetSandbox) freezes on this signal.
		if !sandboxReported {
			if t, ok := sandboxTime(uid); ok {
				// Only a delivered report counts: a source that waits for
				// it would otherwise roll back after targetSandboxTimeout.
				err := j.a.patchStatus(ctx, j.m, map[string]any{"target": map[string]any{"sandboxReadyAt": micro(t)}})
				sandboxReported = err == nil
				if err != nil {
					j.log.Warn("reporting the sandbox failed – retrying", "err", err)
				}
			}
		}
		meta, err := layout.ReadMeta(uid)
		if err != nil || len(meta.Containers) == 0 {
			continue
		}
		// The final metadata carries the freeze time: record this node's
		// NAT bindings of the pod before the CNI flushes them when the
		// pod's endpoint appears here (keep-IP mode, internal/ctguard).
		if !natGuarded && !meta.FrozenAt.IsZero() && j.m.Status.IPPreserved {
			natGuarded = true
			if needsRouteGuard(j.m) {
				go j.a.guardRoute(j.m, j.log)
			}
			if ip, err := netip.ParseAddr(j.m.Status.SourcePodIP); err == nil {
				if entries, err := ctguard.Snapshot(ip); err != nil {
					j.log.Warn("conntrack snapshot failed – NAT bindings are not guarded", "err", err)
				} else {
					go j.a.guardNAT(j.m, entries, j.log)
				}
			}
		}
		var out []v1.TargetContainerStatus
		var last, first time.Time
		done := true
		for _, c := range meta.Containers {
			dir := layout.ContainerDir(uid, c.Name)
			var r layout.Restored
			st := v1.TargetContainerStatus{Name: c.Name}
			if b, err := os.ReadFile(filepath.Join(dir, v1.FileRestored)); err == nil && json.Unmarshal(b, &r) == nil {
				st.Restored = true
			} else if b, err := os.ReadFile(filepath.Join(dir, v1.FileColdStart)); err == nil && json.Unmarshal(b, &r) == nil {
				st.ColdStartReason = r.Reason
			} else {
				done = false
				break
			}
			st.TargetContainerID = r.ContainerID
			st.RestoreMs = r.RestoreMs
			if r.FinishedAt.After(last) {
				last = r.FinishedAt
			}
			if first.IsZero() || r.StartedAt.Before(first) {
				first = r.StartedAt
			}
			out = append(out, st)
		}
		if !done {
			continue
		}
		patch := map[string]any{"containers": out, "restoredAt": micro(last), "message": "restored"}
		if t, ok := sandboxTime(uid); ok {
			patch["sandboxReadyAt"] = micro(t)
		}
		if !first.IsZero() {
			patch["restoreStartedAt"] = micro(first)
		}
		j.log.Info("restore complete", "containers", len(out))
		if j.a.Phantom != nil {
			// Phantom mode: open the inbound rules now, not one watch round
			// trip later. The source's flows are in the cached Migration.
			m := &v1.Migration{}
			if err := j.a.Client.Get(ctx, client.ObjectKeyFromObject(j.m), m); err == nil && m.Status.Source.Phantom != nil {
				j.a.Phantom.restoredNow(m.UID, m.Status.Source.Phantom)
			}
		}
		return j.a.patchStatus(ctx, j.m, map[string]any{"target": patch})
	}
}

// sandboxTime returns when the wrapper created the replacement's sandbox.
func sandboxTime(uid string) (time.Time, bool) {
	b, err := os.ReadFile(filepath.Join(layout.Root(uid), v1.FileSandbox))
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, string(b))
	return t, err == nil
}

// kickSandbox nudges kubelet as long as the replacement pod has no sandbox
// yet. Background: if CNI ADD fails (e.g. because the old IP has not yet been
// released on the source), kubelet only retries after its backoff of
// 10–15 s. Any change to the pod object, by contrast, triggers a new sync
// immediately. An annotation patch every 300 ms therefore makes the IP
// handover as fast as the CNI allows (100 ms interval) – regardless of which
// CNI it is.
func (j *targetJob) kickSandbox(ctx context.Context) {
	start := time.Now()
	for n := 1; ; n++ {
		// 100 ms during the first 30 s (the normal case), 500 ms after that –
		// but never give up: otherwise kubelet's backoff of up to 5 minutes
		// kicks in.
		wait := 100 * time.Millisecond
		if time.Since(start) > 30*time.Second {
			wait = 500 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		pods := &corev1.PodList{}
		if err := j.a.Client.List(ctx, pods, client.InNamespace(j.m.Namespace)); err != nil {
			continue
		}
		var pod *corev1.Pod
		for i := range pods.Items {
			if pods.Items[i].Annotations[v1.AnnotationRestoreID] == string(j.m.UID) {
				pod = &pods.Items[i]
			}
		}
		if pod == nil || pod.Spec.NodeName != j.a.NodeName {
			continue
		}
		for _, c := range pod.Status.Conditions {
			if c.Type == corev1.PodReadyToStartContainers && c.Status == corev1.ConditionTrue {
				j.log.Info("sandbox is up", "kicks", n-1)
				return
			}
		}
		patch := fmt.Sprintf(`{"metadata":{"annotations":{"paguro.dev/kick":"%d"}}}`, n)
		_ = j.a.Client.Patch(ctx, pod, client.RawPatch(types.MergePatchType, []byte(patch)))
		if pool := pod.Annotations["ipam.cilium.io/ip-pool"]; pool != "" && j.a.Cilium != nil {
			j.nudgeCiliumNode(ctx, pool, n)
		}
	}
}

// nudgeCiliumNode speeds up the allocation of the sticky /32 by the Cilium
// operator. Measured: when the source releases the /32, the target waits up
// to 1.5 s – the operator had previously tried the target's request in vain
// and deferred it with exponential backoff (5 ms … 1.3 s). An update event on
// the target's CiliumNode requeues it immediately (Add instead of
// AddRateLimited). As soon as the /32 belongs to the target, the nudging
// stops.
func (j *targetJob) nudgeCiliumNode(ctx context.Context, pool string, n int) {
	if j.poolArrived {
		return
	}
	cn := &unstructured.Unstructured{}
	cn.SetGroupVersionKind(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNode"})
	if err := j.a.Client.Get(ctx, client.ObjectKey{Name: j.a.NodeName}, cn); err != nil {
		return
	}
	allocated, _, _ := unstructured.NestedSlice(cn.Object, "spec", "ipam", "pools", "allocated")
	for _, a := range allocated {
		if m, ok := a.(map[string]any); ok && m["pool"] == pool {
			j.poolArrived = true
			j.log.Info("sticky /32 allocated to the target", "pool", pool, "nudges", n)
			return
		}
	}
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"paguro.dev/nudge":"%d"}}}`, n)
	_ = j.a.Client.Patch(ctx, cn, client.RawPatch(types.MergePatchType, []byte(patch)))
	// Nudge the source node as well. Measured: when a pool moves back and
	// forth within seconds, the operator can miss the source's release and
	// keeps the /32 marked as allocated ("pool empty") until the source's
	// CiliumNode is reconciled again – one nudge freed it within 190 ms.
	if src := j.m.Status.SourceNode; src != "" && src != j.a.NodeName {
		scn := &unstructured.Unstructured{}
		scn.SetGroupVersionKind(cn.GroupVersionKind())
		scn.SetName(src)
		_ = j.a.Client.Patch(ctx, scn, client.RawPatch(types.MergePatchType, []byte(patch)))
	}
}

// cleanupImages removes the (large) images; logs and markers stay in place
// for tracing until the node reboots or is cleaned up.
func cleanupImages(uid string) {
	entries, _ := os.ReadDir(filepath.Join(layout.Root(uid), "containers"))
	for _, e := range entries {
		_ = os.RemoveAll(layout.ImagesDir(uid, e.Name()))
		_ = os.Remove(filepath.Join(layout.ContainerDir(uid, e.Name()), v1.FileRootfsDiff))
	}
	_ = os.RemoveAll(filepath.Join(layout.Root(uid), "emptydir"))
}

// run prepares the target and then watches for the restore until the
// migration ends. Alongside: the replacement is bound at the commit, and
// kubelet is nudged as soon as the replacement pod exists.
func (job *targetJob) run(ctx context.Context) {
	a, m := job.a, job.m
	// Ahead of the image pull: the operator needs its time.
	go job.preallocate(ctx)
	if err := job.prepare(ctx); err != nil {
		job.log.Error("target preparation failed", "err", err)
		_ = a.patchStatus(context.Background(), m, map[string]any{"target": map[string]any{"error": err.Error()}})
		return
	}
	// Shield every new sandbox namespace on this node before CNI runs,
	// until the restore is done (closes the CNI-ADD-to-pause RST window).
	// Only needed when the IP is kept: with a new IP no peer can reach the
	// replacement before Phantom mode (pending rules) or the new address is
	// known.
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	if m.Status.IPPreserved {
		go func() {
			if err := a.watchNetns(wctx, m.Status.SourcePodIP, job.log); err != nil {
				job.log.Warn("netns watcher", "err", err)
			}
		}()
	}
	go job.bindOnCommit(ctx)
	go job.kickSandbox(ctx)
	if err := job.watchRestore(ctx); err != nil && ctx.Err() == nil {
		job.log.Error("restore watch", "err", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/pkg/names"
)

// The commit gate: a Dynamic Resource Allocation (DRA) driver whose only job
// is to hold a replacement pod right before kubelet creates its sandbox.
//
// kubelet prepares a pod's resource claims synchronously, after the pod's
// volumes are mounted and immediately before it creates the sandbox
// (kuberuntime_manager.go: PrepareDynamicResources, then createPodSandbox,
// then the containers – all in one sync). A replacement whose sandbox needs
// the migrated pod's IP can only get it after the freeze. Created by
// kubelet's normal path after the freeze, it paid for kubelet's pickup, the
// volume manager's loops and the 300 ms mount poll (measured ≈ 0.6 s), and a
// failed early attempt for kubelet's once-per-second retry. Held here
// instead, it is through all of that before the freeze; the source freezes
// as soon as the replacement is held (target.sandboxStagedAt), and the
// moment the migration is committed this driver returns and kubelet goes
// straight on to the sandbox and the containers. With an early hand-over
// (network.earlyHandOver) it returns as soon as the source reports that it
// is paused: the sandbox is then created while the final dump runs, and
// only the restore waits for the commit.
//
// The claim is allocated and reserved by Paguro's controller, not by a
// scheduler (the replacement is bound by Paguro); nothing else uses the
// device class. No devices are published and nothing is injected into the
// containers – the claim is only a hook into kubelet's sequence.

// GateDriver is the name of the commit-gate DRA driver and its DeviceClass.
const GateDriver = names.GateDriver

// AnnotationGateRelease on a gate claim releases it regardless of the
// migration (operators, tests).
const AnnotationGateRelease = "paguro.dev/release"

// gateHoldMax bounds a hold below kubelet's 45 s call timeout; an expired
// hold fails the call and kubelet retries the sandbox later.
const gateHoldMax = 40 * time.Second

type commitGate struct {
	a   *Agent
	log *slog.Logger
}

// StartCommitGate registers the gate with kubelet. kubeletDir is kubelet's
// data directory as seen by the agent (e.g. /proc/1/root/var/lib/kubelet).
func (a *Agent) StartCommitGate(ctx context.Context, cs kubernetes.Interface, kubeletDir string) error {
	g := &commitGate{a: a, log: a.Log.With("component", "commit-gate")}
	pluginDir := filepath.Join(kubeletDir, "plugins", GateDriver)
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		return err
	}
	helper, err := kubeletplugin.Start(ctx, g,
		kubeletplugin.DriverName(GateDriver),
		kubeletplugin.NodeName(a.NodeName),
		kubeletplugin.KubeClient(cs),
		// Holds block for up to gateHoldMax: other migrations to this node
		// must not wait behind them.
		kubeletplugin.Serialize(false),
		kubeletplugin.RegistrarDirectoryPath(filepath.Join(kubeletDir, "plugins_registry")),
		kubeletplugin.PluginDataDirectoryPath(pluginDir),
		kubeletplugin.HealthService(false),
	)
	if err != nil {
		return fmt.Errorf("registering the commit gate with kubelet: %w", err)
	}
	go a.confirmCommitGate(ctx, helper, g.log)
	return nil
}

// registrationWait bounds the wait for kubelet's confirmation.
const registrationWait = 2 * time.Minute

// confirmCommitGate announces the gate (node annotation) only once kubelet
// has confirmed its registration: sockets in a directory kubelet does not
// watch looked registered to the agent, the controller chose the gate, and
// every migration to the node rolled back after 20 s (measured: an empty
// kubeletDir after `helm upgrade --reuse-values`).
func (a *Agent) confirmCommitGate(ctx context.Context, helper *kubeletplugin.Helper, log *slog.Logger) {
	deadline := time.Now().Add(registrationWait)
	for ctx.Err() == nil {
		if st := helper.RegistrationStatus(); st != nil {
			if !st.PluginRegistered {
				log.Error("kubelet rejected the commit gate – replacements are released after the final dump", "err", st.Error)
				return
			}
			a.commitGate.Store(true)
			log.Info("commit gate registered with kubelet")
			if err := a.AnnotateNode(ctx); err != nil {
				log.Warn("announcing the commit gate", "err", err)
			}
			return
		}
		if time.Now().After(deadline) {
			log.Error("kubelet did not register the commit gate within " + registrationWait.String() +
				" – is agent.kubeletDir kubelet's data directory? Replacements are released after the final dump")
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (g *commitGate) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	out := make(map[types.UID]kubeletplugin.PrepareResult, len(claims))
	for _, c := range claims {
		out[c.UID] = kubeletplugin.PrepareResult{Err: g.hold(ctx, c)}
	}
	return out, nil
}

// hold returns once the claim's migration is committed (or the claim is
// released by annotation), and at once for a claim whose migration is over
// – kubelet prepares claims again after its own restart.
func (g *commitGate) hold(ctx context.Context, claim *resourceapi.ResourceClaim) error {
	start := time.Now()
	uid := claim.Labels[names.LabelMigrationUID]
	ctx, cancel := context.WithTimeout(ctx, gateHoldMax)
	defer cancel()
	staged := false
	var lastAPI time.Time
	for {
		released, why, err := g.released(ctx, claim, uid, &lastAPI)
		if err != nil {
			return err
		}
		if released {
			if staged {
				g.log.Info("replacement released at the commit gate", "claim", claim.Name, "reason", why, "heldMs", ms(time.Since(start)))
			}
			return nil
		}
		if !staged {
			staged = g.reportStaged(ctx, claim.Namespace, uid)
			if staged {
				g.log.Info("replacement held at the commit gate", "claim", claim.Name, "migration", uid)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("commit gate %s: not released within %s", claim.Name, gateHoldMax)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// released decides from the agent's cache (the migration) and, every
// 100 ms, from the API server (the claim's release annotation).
func (g *commitGate) released(ctx context.Context, claim *resourceapi.ResourceClaim, uid string, lastAPI *time.Time) (bool, string, error) {
	if uid != "" {
		m, err := g.migration(ctx, claim.Namespace, uid)
		if err != nil {
			// Keep holding and ask again (an error here would hand the
			// pod to kubelet's retry backoff).
			g.log.Warn("commit gate: reading the migration failed", "claim", claim.Name, "err", err)
			return false, "", nil
		}
		switch {
		case m == nil:
			// Long over (kubelet prepares again after its own restart).
			return true, "no migration", nil
		case committed(m.Status.Phase) && m.Status.Network.HandOverAfterSourceStop && !handedOver(uid) && !handOverOverdue(m):
			// Calico: the address is free only once the source's sandbox
			// is gone; the source agent says so – or, should its message
			// be lost (agent restarted), the source pod is gone: kubelet
			// removes it only after tearing down its network.
			if time.Since(*lastAPI) >= 250*time.Millisecond {
				*lastAPI = time.Now()
				if g.sourceGone(ctx, m) {
					return true, "source pod gone", nil
				}
			}
			return false, "", nil
		case committed(m.Status.Phase), m.Status.Phase == v1.PhaseSucceeded:
			return true, "committed", nil
		case m.Status.Phase.Terminal() && m.Status.Cutover.SourceDeletedAt != nil:
			// Failed after the commit: the replacement is the only copy
			// (restored if its checkpoint is still there, cold-started
			// otherwise) – it must start.
			return true, "failed after the commit", nil
		case m.Status.Phase.Terminal(), m.Status.Phase == v1.PhaseAborting:
			// Rolled back: the pod is about to be deleted; holding it would
			// only delay that by up to gateHoldMax.
			return false, "", errors.New("migration ended before its commit")
		case m.Status.Network.EarlyHandOver && m.Status.Phase == v1.PhasePreCopy && handedOver(uid):
			// The source is paused (early hand-over): the sandbox may be
			// created while the final dump runs. The restore itself still
			// waits for the commit (READY).
			return true, "source paused", nil
		}
	}
	if time.Since(*lastAPI) >= 100*time.Millisecond {
		*lastAPI = time.Now()
		cur := &resourceapi.ResourceClaim{}
		if err := g.a.APIReader.Get(ctx, client.ObjectKeyFromObject(claim), cur); err == nil && cur.Annotations[AnnotationGateRelease] != "" {
			return true, "annotation", nil
		}
	}
	return false, "", nil
}

// sourceGone reports that the migration's source pod no longer exists.
func (g *commitGate) sourceGone(ctx context.Context, m *v1.Migration) bool {
	pod := &corev1.Pod{}
	err := g.a.APIReader.Get(ctx, client.ObjectKey{Namespace: m.Namespace, Name: m.Spec.PodName}, pod)
	return apierrors.IsNotFound(err) || (err == nil && string(pod.UID) != m.Status.SourcePodUID)
}

// handOverWait bounds the wait for a hand-over after the commit: without it
// (source agent gone) kubelet gets the replacement anyway and retries its
// sandbox until the address is free.
const handOverWait = 15 * time.Second

func handOverOverdue(m *v1.Migration) bool {
	return m.Status.Source.FrozenAt != nil && time.Since(m.Status.Source.FrozenAt.Time) > handOverWait
}

// handedOver reports the source's hand-over message (transfer.go).
func handedOver(uid string) bool {
	return layout.Exists(filepath.Join(layout.Root(uid), names.FileHandOver))
}

// migration finds the migration by UID (nil: none). An error is returned,
// not taken for "none": that would open the gate before the commit.
func (g *commitGate) migration(ctx context.Context, namespace, uid string) (*v1.Migration, error) {
	list := &v1.MigrationList{}
	if err := g.a.Client.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	for i := range list.Items {
		if string(list.Items[i].UID) == uid {
			return &list.Items[i], nil
		}
	}
	return nil, nil
}

// reportStaged records that the replacement is held: the source freezes on
// this report.
func (g *commitGate) reportStaged(ctx context.Context, namespace, uid string) bool {
	if uid == "" {
		return true
	}
	m, err := g.migration(ctx, namespace, uid)
	return err == nil && m != nil && g.a.patchStatus(ctx, m, map[string]any{"target": map[string]any{"sandboxStagedAt": now()}}) == nil
}

func (g *commitGate) UnprepareResourceClaims(_ context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	out := make(map[types.UID]error, len(claims))
	for _, c := range claims {
		out[c.UID] = nil
	}
	return out, nil
}

func (g *commitGate) HandleError(_ context.Context, err error, msg string) {
	g.log.Warn(msg, "err", err)
}

func (g *commitGate) WatchHealthStatus(context.Context, chan<- kubeletplugin.DeviceHealthReport) error {
	return kubeletplugin.ErrHealthNotSupported
}

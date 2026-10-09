// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Source side, part 4: after the commit – the replacement released at the
// commit gate, the source's address and containers let go.

package agent

import (
	"context"
	"log/slog"
	"strings"
	"time"

	v1 "paguro.dev/paguro/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/internal/gate"
)

// releaseReplacement releases a replacement held back by the commit gate
// and binds it to the target node, right after the final dump.
func (j *sourceJob) releaseReplacement(ctx context.Context) {
	start := time.Now()
	cur := &v1.Migration{}
	if err := j.a.Client.Get(ctx, client.ObjectKeyFromObject(j.m), cur); err != nil {
		return
	}
	name := replacementPodName(cur)
	if name == "" || cur.Status.TargetNode == "" {
		return
	}
	pod := &corev1.Pod{}
	if err := j.a.APIReader.Get(ctx, client.ObjectKey{Namespace: cur.Namespace, Name: name}, pod); err != nil ||
		pod.Annotations[v1.AnnotationRestoreID] != string(cur.UID) || pod.Spec.NodeName != "" {
		return
	}
	if err := gate.ReleaseAndBind(ctx, j.a.Client, pod, cur.Status.TargetNode); err != nil {
		j.log.Warn("releasing the replacement after the dump (the target agent retries at the commit)", "err", err)
		return
	}
	j.log.Info("replacement released and bound to the target after the dump", "pod", name, "ms", ms(time.Since(start)))
}

// releaseSourceNetwork lets go of the committed source's address and
// containers, in parallel with the transfer. With a new IP the source keeps
// its sandbox – and its endpoint in the Services, as terminating – until
// the replacement is ready (stopped when the migration ends), unless a
// volume has to move.
func (j *sourceJob) releaseSourceNetwork() {
	m := j.m
	switch {
	case !m.Status.IPPreserved:
		if hasRWOVolume(m) {
			go j.stopFrozenContainers()
		}
	case j.pod.Annotations["ipam.cilium.io/ip-pool"] != "" && j.a.Cilium != nil && j.pod.Status.PodIP != "":
		go j.releaseCiliumAddress(j.pod.Annotations["ipam.cilium.io/ip-pool"])
	default:
		go j.releaseSandboxNetwork()
	}
}

// releaseCiliumAddress releases the sticky IP right after the commit
// (before it, a rollback still needs to own the IP).
func (j *sourceJob) releaseCiliumAddress(pool string) {
	m := j.m
	// After the hand-over of the address: kubelet tears the network down as
	// soon as the containers are gone.
	if hasRWOVolume(m) {
		defer j.stopFrozenContainers()
	}
	start := time.Now()
	// Hold first: the address must stay routed into the cluster until the
	// target has it (CiliumHooks.Hold).
	owner := "paguro-hold/" + string(m.UID)
	taken, err := j.a.Cilium.Hold(context.Background(), pool, owner)
	held := err == nil
	if held {
		go j.a.releaseHold(m, pool, owner, j.pod.Status.PodIP, taken, j.log)
	} else {
		j.log.Warn("holding the sticky CIDR failed – NodePort connections may be reset during the freeze", "err", err)
	}
	if err := j.a.Cilium.EarlyRelease(context.Background(), j.pod.Status.PodIP, pool); err != nil {
		j.log.Warn("early IP release failed – falling back to the default path via CNI DEL", "err", err)
		return
	}
	j.log.Info("sticky IP released early", "ip", j.pod.Status.PodIP, "pool", pool, "held", held, "ms", ms(time.Since(start)))
}

// releaseSandboxNetwork stops the frozen source's pod sandbox right away
// (kept IP on any other CNI). Measured on Calico: the target can only take
// the IP after the source sandbox is torn down, and kubelet does that
// 2.9–4.6 s after the pod deletion (2 s minimum grace even with grace 0,
// then SIGKILL of the frozen containers) – 55–75 % of the freeze. Stopping
// the sandbox ourselves runs CNI DEL immediately. Safe at this point: the
// dump is complete and committed, and the shield in the pod's netns drops
// the FIN/RST of the dying sockets.
func (j *sourceJob) releaseSandboxNetwork() {
	m := j.m
	handOver := func() {
		if !m.Status.Network.HandOverAfterSourceStop {
			return
		}
		// Retried: a target agent restarted right now takes a few seconds;
		// without the message the gate waits for the source pod's removal
		// or its timeout.
		var err error
		for deadline := time.Now().Add(handOverRetry); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if err = j.client.HandOver(context.Background(), string(m.UID)); err == nil {
				return
			}
		}
		j.log.Warn("hand-over not delivered – the replacement leaves the commit gate when the source pod is gone", "err", err)
	}
	// The address first (cnidel.go), then the frozen containers.
	start := time.Now()
	released, err := j.a.releaseNetwork(context.Background(), j.sandboxID)
	if released {
		j.log.Info("source network released (CNI DEL)", "ms", ms(time.Since(start)))
		handOver()
	} else {
		j.log.Warn("releasing the source's network ahead of its sandbox failed – stopping the sandbox", "err", err)
	}
	stopped := j.stopSourceSandbox()
	switch {
	case released:
	case stopped:
		handOver()
	case m.Status.Network.HandOverAfterSourceStop:
		j.log.Warn("source sandbox not stopped – the replacement leaves the commit gate after its timeout")
	}
}

// handOverRetry bounds the retries of the hand-over message.
const handOverRetry = 20 * time.Second

// stopSourceSandbox stops the source pod's sandbox through the CRI (kills the
// frozen containers, then CNI DEL), so the CNI releases the pod IP without
// waiting for kubelet's pod termination.
// stopFrozenContainers ends the frozen source containers once the
// migration is committed and an RWO volume has to move: kubelet unmounts a
// volume only after the pod's containers are gone, and a frozen process
// ignores the SIGTERM of the pod deletion – kubelet waits for the grace
// period (2 s minimum even with grace 0, else up to 30 s with a new IP)
// before its SIGKILL. Measured with a Minecraft world on Cinder: unmount
// 3.0 s after the source deletion, the whole freeze waited for it. The
// sandbox (the network) is left to kubelet or the paths above.
func (j *sourceJob) stopFrozenContainers() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	for _, c := range j.cs {
		if _, err := j.a.Host.Run(ctx, nil, "crictl", "stop", "--timeout", "0", c.id); err != nil {
			j.log.Warn("stopping the frozen source container failed – kubelet stops it after the grace period",
				"container", c.name, "err", err)
			continue
		}
		j.log.Info("frozen source container stopped (its volumes can move)", "container", c.name, "ms", ms(time.Since(start)))
	}
}

// hasRWOVolume: the migration moves a ReadWriteOnce volume (detached from
// the source, attached to the target).
func hasRWOVolume(m *v1.Migration) bool {
	for _, v := range m.Status.Volumes {
		if v.Kind == v1.VolumeKindPVCRWO {
			return true
		}
	}
	return false
}

func (j *sourceJob) stopSourceSandbox() bool {
	return j.a.stopPodSandbox(j.pod.UID, j.sandboxID, j.log)
}

// stopPodSandbox stops a pod's sandbox (sandboxID, or looked up by the pod
// UID when empty) and reports whether every one stopped. Errors are logged:
// kubelet tears it down anyway.
func (a *Agent) stopPodSandbox(podUID types.UID, sandboxID string, log *slog.Logger) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	ids := []string{sandboxID}
	if sandboxID == "" {
		// Exact match on the pod UID (--name would be a regular expression and
		// could match other pods with a similar name).
		out, err := a.Host.Run(ctx, nil, "crictl", "pods", "--label", "io.kubernetes.pod.uid="+string(podUID), "-q")
		if err != nil {
			log.Warn("source sandbox lookup failed – kubelet will tear it down", "err", err)
			return false
		}
		ids = strings.Fields(string(out))
	}
	ok := true
	for _, id := range ids {
		if _, err := a.Host.Run(ctx, nil, "crictl", "stopp", id); err != nil {
			log.Warn("stopping the source sandbox failed – kubelet will tear it down", "sandbox", id, "err", err)
			ok = false
			continue
		}
		log.Info("source sandbox stopped (CNI DEL done)", "sandbox", id, "ms", ms(time.Since(start)))
	}
	return ok
}

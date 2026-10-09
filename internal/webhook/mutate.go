// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"paguro.dev/paguro/pkg/names"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/gate"
	"paguro.dev/paguro/internal/images"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/placement"
)

// AnnotationSourcePod (on the Migration): JSON of the source pod (metadata
// and spec, without status) at preflight time. Needed to recreate bare
// pods, and by adapters that carry over properties of the source
// (e.g. the Cilium pool).
const AnnotationSourcePod = "paguro.dev/source-pod"

// Values for v1alpha1.AnnotationTCP.
const (
	TCPEstablished = names.TCPEstablished
	TCPClose       = names.TCPClose
	TCPTranslate   = names.TCPTranslate
)

// EncodeSourcePod serializes the part of the pod needed to recreate it.
func EncodeSourcePod(pod *corev1.Pod) (string, error) {
	snap := corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			UID:             pod.UID,
			Labels:          pod.Labels,
			Annotations:     pod.Annotations,
			OwnerReferences: pod.OwnerReferences,
		},
		Spec: pod.Spec,
	}
	// The images the node runs (internal/images): the replacement is pinned
	// to them.
	trim := func(in []corev1.ContainerStatus) []corev1.ContainerStatus {
		var out []corev1.ContainerStatus
		for _, s := range in {
			out = append(out, corev1.ContainerStatus{Name: s.Name, Image: s.Image, ImageID: s.ImageID})
		}
		return out
	}
	snap.Status.ContainerStatuses = trim(pod.Status.ContainerStatuses)
	snap.Status.InitContainerStatuses = trim(pod.Status.InitContainerStatuses)
	b, err := json.Marshal(&snap)
	return string(b), err
}

// SourcePodOf reads the stored source pod of a Migration.
func SourcePodOf(mig *v1alpha1.Migration) (*corev1.Pod, error) {
	raw := mig.Annotations[AnnotationSourcePod]
	if raw == "" {
		return nil, fmt.Errorf("migration %s/%s has no %s annotation", mig.Namespace, mig.Name, AnnotationSourcePod)
	}
	var p corev1.Pod
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", AnnotationSourcePod, err)
	}
	return &p, nil
}

// MutateIntoRestoreTarget turns a freshly created pod (replacement from the
// owner or bare pod recreated by the controller) into a restore target:
//
//   - fixed node (bypassing the scheduler; the target was checked in preflight),
//   - RuntimeClass paguro, so paguro-runc performs a restore instead of create,
//   - restore annotations for the wrapper,
//   - classic init containers removed (they already ran on the source;
//     running them again could modify state on PVCs), sidecars stay,
//   - adapter-specific IP takeover, if ipPreserved.
func MutateIntoRestoreTarget(pod *corev1.Pod, mig *v1alpha1.Migration, adapter netadapter.Adapter) error {
	if mig.Status.TargetNode == "" {
		return fmt.Errorf("migration %s has no target node", mig.Name)
	}
	placeOnTarget(pod, mig)
	// Deterministic name instead of generateName: the target agent requests
	// the sticky IP in advance under exactly this owner ("ns/name").
	if pod.Name == "" && pod.GenerateName != "" {
		pod.Name = names.ReplacementName(pod.GenerateName, string(mig.UID))
	}
	rc := v1alpha1.RuntimeClassName
	pod.Spec.RuntimeClassName = &rc
	// fsGroup: kubelet changes group and mode of every file on the volumes
	// when it mounts them (policy Always) – 0600 became 0660, and CRIU
	// refused to restore a process that had such a file mapped ("bad mode",
	// measured with Minecraft's profiler library on its world volume). The
	// source already prepared the volumes; on its replacement kubelet only
	// checks their root directory.
	if sc := pod.Spec.SecurityContext; sc != nil && sc.FSGroup != nil && sc.FSGroupChangePolicy == nil {
		policy := corev1.FSGroupChangeOnRootMismatch
		sc.FSGroupChangePolicy = &policy
	}
	annotateRestore(pod, mig)
	skipInitContainers(pod)
	FastReadiness(pod)
	if !mig.Status.IPPreserved || adapter == nil {
		return nil
	}
	source, err := SourcePodOf(mig)
	if err != nil {
		return err
	}
	return adapter.MutateRestoreTarget(pod, netadapter.RestoreContext{
		Source:     source,
		SourceIP:   mig.Status.SourcePodIP,
		TargetPool: mig.Status.Network.TargetPool,
	})
}

// placeOnTarget fixes the pod to the target node – directly, or held back
// until the commit and bound then.
func placeOnTarget(pod *corev1.Pod, mig *v1alpha1.Migration) {
	pod.Spec.ResourceClaims = slices.DeleteFunc(pod.Spec.ResourceClaims, func(c corev1.PodResourceClaim) bool {
		return c.Name == names.GateClaim // an earlier migration's gate
	})
	if !gateUntilCommit(mig) {
		pod.Spec.NodeName = mig.Status.TargetNode
		// nodeName and schedulingGates are mutually exclusive per API validation.
		pod.Spec.SchedulingGates = nil
		return
	}
	// Held back until the commit (names.SchedulingGateCommit), then bound
	// to the target by the target agent (internal/gate). No scheduler
	// answers to this name, so none can place it elsewhere in the moment
	// between the gate's removal and the binding – and, unlike a node
	// affinity, nothing of it restricts the next migration of the running
	// pod.
	pod.Spec.NodeName = ""
	pod.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: v1alpha1.SchedulingGateCommit}}
	pod.Spec.SchedulerName = v1alpha1.SchedulerNameBind
	if mig.Status.Network.CommitGate {
		// The commit gate (internal/agent/dragate.go): bound before the
		// freeze, kubelet takes it as far as right before its sandbox.
		pod.Spec.ResourceClaims = append(pod.Spec.ResourceClaims, gate.PodClaim(mig.UID))
	}
}

// annotateRestore sets what the restore wrapper reads: the migration, the
// old IP, how to treat TCP connections, and – from the source pod – its
// CPU baseline and the exact images the source node ran.
func annotateRestore(pod *corev1.Pod, mig *v1alpha1.Migration) {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[v1alpha1.AnnotationRestore] = mig.Name
	pod.Annotations[v1alpha1.AnnotationRestoreID] = string(mig.UID)
	pod.Annotations[v1alpha1.AnnotationOldIP] = mig.Status.SourcePodIP
	// The replacement continues the source's processes and keeps their CPU
	// baseline – also for a cold start, whose new processes must not use
	// more than the next migration expects – and the exact images the
	// source node ran (internal/images), not whatever a tag means today.
	if src, err := SourcePodOf(mig); err == nil {
		if b := src.Annotations[v1alpha1.AnnotationCPUBaseline]; b != "" {
			pod.Annotations[v1alpha1.AnnotationCPUBaseline] = b
		}
		pinImages(pod, images.ForPod(src))
	}
	switch {
	case mig.Status.IPPreserved:
		pod.Annotations[v1alpha1.AnnotationTCP] = TCPEstablished
	case mig.Status.NetworkAdapter == netadapter.NamePhantom:
		pod.Annotations[v1alpha1.AnnotationTCP] = TCPTranslate
	default:
		pod.Annotations[v1alpha1.AnnotationTCP] = TCPClose
	}
}

// pinImages sets the containers' images to the digests the source ran.
func pinImages(pod *corev1.Pod, pinned map[string]string) {
	for _, list := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for i := range list {
			img, ok := pinned[list[i].Name]
			if !ok {
				continue
			}
			list[i].Image = img
			// A digest is immutable and the target agent pulled it during
			// pre-copy: kubelet need not ask the registry inside the freeze.
			// Measured: a server image without a tag (pull policy Always)
			// cost ~1 s between the sandbox and the container.
			if strings.Contains(img, "@sha256:") {
				list[i].ImagePullPolicy = corev1.PullIfNotPresent
			}
		}
	}
}

// FastReadiness starts the replacement's readiness and startup probes
// without the initial delay they have for a cold start: the replacement
// continues processes that were serving. Until it is ready, its Services
// have no ready endpoint of their own – the source's, terminating, stops
// serving once the frozen source fails its readiness probe – and new
// connections are refused (measured on EKS: 19 s with a 30 s delay). A
// readiness probe that fails only keeps the pod not ready, so its delay
// goes. A startup probe's delay moves into its failure budget, so that a
// cold start (the restore failed) has exactly as long as before before
// kubelet restarts it. Liveness probes are left alone.
func FastReadiness(pod *corev1.Pod) {
	fix := func(c *corev1.Container) {
		if p := c.ReadinessProbe; p != nil && p.InitialDelaySeconds > 0 {
			p.InitialDelaySeconds = 0
		}
		if p := c.StartupProbe; p != nil && p.InitialDelaySeconds > 0 {
			period, failures := p.PeriodSeconds, p.FailureThreshold
			if period <= 0 {
				period = 10 // the API defaults
			}
			if failures <= 0 {
				failures = 3
			}
			p.FailureThreshold = failures + (p.InitialDelaySeconds+period-1)/period
			p.PeriodSeconds = period
			p.InitialDelaySeconds = 0
		}
	}
	for i := range pod.Spec.Containers {
		fix(&pod.Spec.Containers[i])
	}
	for i := range pod.Spec.InitContainers {
		if placement.IsSidecar(&pod.Spec.InitContainers[i]) {
			fix(&pod.Spec.InitContainers[i])
		}
	}
}

// skipInitContainers removes the classic init containers – they already
// ran on the source, and running them again could change state on
// volumes – and records them; sidecars stay.
func skipInitContainers(pod *corev1.Pod) {
	var kept []corev1.Container
	skipped := []string{}
	for _, c := range pod.Spec.InitContainers {
		if placement.IsSidecar(&c) {
			kept = append(kept, c)
		} else {
			skipped = append(skipped, c.Name)
		}
	}
	pod.Spec.InitContainers = kept
	if len(skipped) > 0 {
		b, _ := json.Marshal(skipped)
		pod.Annotations[v1alpha1.AnnotationSkippedInit] = string(b)
	} else {
		delete(pod.Annotations, v1alpha1.AnnotationSkippedInit)
	}
}

// gateUntilCommit: a replacement for a kept IP on Cilium that is created
// before the commit. Its address is handed to the target node during
// pre-copy (PoolPreparedAt) and becomes usable for it only after the
// freeze; a sandbox attempt before that would take the address from the
// running source, one after a failed attempt would wait for kubelet's next
// status refresh (up to 1 s). Gated, its first attempt comes after the
// commit and succeeds.
func gateUntilCommit(mig *v1alpha1.Migration) bool {
	if !mig.Status.IPPreserved || (mig.Status.Network.TargetPool == "" && !mig.Status.Network.CommitGate) {
		return false
	}
	switch mig.Status.Phase {
	case "", v1alpha1.PhasePending, v1alpha1.PhasePreflight, v1alpha1.PhasePreCopy:
		return true
	}
	return false
}

// BareReplacement builds the replacement for a bare pod from the stored
// source pod (same name, without runtime fields).
func BareReplacement(mig *v1alpha1.Migration, adapter netadapter.Adapter) (*corev1.Pod, error) {
	src, err := SourcePodOf(mig)
	if err != nil {
		return nil, err
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            src.Name,
			Namespace:       src.Namespace,
			Labels:          src.Labels,
			Annotations:     src.Annotations,
			OwnerReferences: src.OwnerReferences,
		},
		Spec: *src.Spec.DeepCopy(),
	}
	// Ephemeral containers (kubectl debug) cannot be created via CREATE
	// and are not part of the checkpoint anyway.
	pod.Spec.EphemeralContainers = nil
	// The copied annotations include Calico's record of the SOURCE sandbox
	// (podIP/podIPs/containerID); on a Calico cluster they would make the
	// replacement steal the source's IP during pre-copy. Applies to every
	// network mode (also generic), no-op on other CNIs.
	netadapter.ClearCalicoPodState(pod)
	// The source pod may already have had a sticky IP annotation; the
	// adapter sets the correct one next.
	if err := MutateIntoRestoreTarget(pod, mig, adapter); err != nil {
		return nil, err
	}
	return pod, nil
}

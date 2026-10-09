// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/placement"
	"paguro.dev/paguro/internal/webhook"
)

// Values for status.volumes[].kind.
const (
	VolumePVCRWO        = v1alpha1.VolumeKindPVCRWO
	VolumePVCRWX        = v1alpha1.VolumeKindPVCRWX
	VolumeEmptyDir      = "emptyDir"
	VolumeConfigMap     = "configMap"
	VolumeSecret        = "secret"
	VolumeProjected     = "projected"
	VolumeDownwardAPI   = "downwardAPI"
	VolumeOther         = "other"
	annotationMirrorPod = corev1.MirrorPodAnnotationKey
	// Size of the annotation holding the source pod; 256 KiB is the limit for
	// all annotations of an object combined.
	maxSourcePodAnnotation = 200 << 10
)

// rejection is a preflight result that leads to Failed (not a controller
// error, but a property of the pod).
type rejection struct{ msg string }

func (r *rejection) Error() string { return r.msg }

func reject(format string, args ...any) error { return &rejection{msg: fmt.Sprintf(format, args...)} }

// preflight: check the pod, select the target, decide on networking → PreCopy.
func (r *MigrationReconciler) preflight(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	res, err := r.runPreflight(ctx, mig)
	var rej *rejection
	if errors.As(err, &rej) {
		return ctrl.Result{}, r.fail(ctx, mig, "preflight: "+rej.msg)
	}
	var wait *awaitingTarget
	if errors.As(err, &wait) {
		return ctrl.Result{RequeueAfter: targetPoll}, r.reportAwaitingTarget(ctx, mig, wait.msg)
	}
	return res, err
}

type preflightResult struct {
	ownerUID    string
	ownerKind   string
	ownerName   string
	cutoverMode string
	network     v1alpha1.NetworkStatus
	origHash    string
	volumes     []v1alpha1.VolumeStatus
	targetNode  string
	adapter     string
	preserved   bool
	warnings    []string
}

func (r *MigrationReconciler) runPreflight(ctx context.Context, mig *v1alpha1.Migration) (ctrl.Result, error) {
	var pod corev1.Pod
	if err := r.Get(ctx, client.ObjectKey{Namespace: mig.Namespace, Name: mig.Spec.PodName}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, reject("pod %s/%s not found", mig.Namespace, mig.Spec.PodName)
		}
		return ctrl.Result{}, err
	}
	var res preflightResult

	warnings, err := CheckPod(&pod)
	if err != nil {
		return ctrl.Result{}, err
	}
	res.warnings = append(res.warnings, warnings...)

	if err := r.checkConcurrent(ctx, mig, &pod); err != nil {
		return ctrl.Result{}, err
	}
	// An ended migration of this pod may still be handing it back (its
	// owner label, its address): wait for it instead of racing it.
	if other, err := r.unreleasedMigration(ctx, mig, pod.UID); err != nil {
		return ctrl.Result{}, err
	} else if other != "" {
		logf.FromContext(ctx).Info("waiting for an ended migration to release the pod", "migration", other)
		return ctrl.Result{RequeueAfter: pollInterval}, nil
	}
	if err := r.resolveOwner(ctx, &pod, &res); err != nil {
		return ctrl.Result{}, err
	}

	srcNode, err := r.sourceNode(ctx, &pod)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.checkDeadline(mig, &pod, srcNode, &res); err != nil {
		return ctrl.Result{}, err
	}

	volumes, topology, volWarnings, err := r.classifyVolumes(ctx, &pod)
	if err != nil {
		return ctrl.Result{}, err
	}
	res.volumes = volumes
	res.warnings = append(res.warnings, volWarnings...)
	if w := hostPortWarning(&pod); w != "" {
		res.warnings = append(res.warnings, w)
	}

	if err := r.selectTarget(ctx, mig, &pod, srcNode, topology, &res); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.decideNetwork(ctx, mig, &pod, &res); err != nil {
		return ctrl.Result{}, err
	}
	r.decideHandOver(ctx, &res)
	if err := r.snapshotSourcePod(ctx, mig, &pod); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.enterPreCopy(ctx, mig, &pod, &res)
}

// sourceNode returns the pod's node if its agent runs and is not shutting
// down.
func (r *MigrationReconciler) sourceNode(ctx context.Context, pod *corev1.Pod) (*corev1.Node, error) {
	var n corev1.Node
	if err := r.Get(ctx, client.ObjectKey{Name: pod.Spec.NodeName}, &n); err != nil {
		return nil, err
	}
	if n.Annotations[v1alpha1.AnnotationNodeAgent] == "" {
		return nil, reject("source node %s runs no paguro agent (annotation %s missing)",
			n.Name, v1alpha1.AnnotationNodeAgent)
	}
	if n.Annotations[v1alpha1.AnnotationNodeAgentDraining] != "" {
		return nil, reject("the paguro agent on source node %s is shutting down (upgrade or uninstall); retry when it is back",
			n.Name)
	}
	return &n, nil
}

// hostPortWarning: a host port is the node's address – whoever reaches the
// pod through it reaches the old node after the move.
func hostPortWarning(pod *corev1.Pod) string {
	hps := placement.HostPorts(pod)
	if len(hps) == 0 {
		return ""
	}
	var ps []string
	for _, h := range hps {
		ps = append(ps, h.String())
	}
	return fmt.Sprintf("host ports %s: clients connected through %s's address lose "+
		"the connection (the pod answers on the target node's address); reach game servers through a Service "+
		"or a proxy instead (docs/AGONES.md)", strings.Join(ps, ", "), pod.Spec.NodeName)
}

// decideHandOver decides how the target takes over: behind the commit gate,
// with the address handed over after the source stopped (Calico) or while
// the final dump runs (Cilium's early hand-over).
func (r *MigrationReconciler) decideHandOver(ctx context.Context, res *preflightResult) {
	var target corev1.Node
	if err := r.Get(ctx, client.ObjectKey{Name: res.targetNode}, &target); err != nil {
		return
	}
	res.network.CommitGate = r.useCommitGate(&target, res.network, res.adapter, res.preserved, res.volumes, res.cutoverMode)
	res.network.HandOverAfterSourceStop = res.network.CommitGate && res.adapter == netadapter.NameCalico
	// The replacement may claim the address while the source holds it (its
	// own pool generation) and give it back after a rollback
	// (reannounce.go): Cilium.
	res.network.EarlyHandOver = res.network.CommitGate && r.EarlyHandOver && r.Pools != nil && res.network.TargetPool != ""
}

// snapshotSourcePod stores the source pod in the migration (to recreate a
// bare pod, to find the source's Cilium pool).
func (r *MigrationReconciler) snapshotSourcePod(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod) error {
	encoded, err := webhook.EncodeSourcePod(pod)
	if err != nil {
		return err
	}
	if len(encoded) > maxSourcePodAnnotation {
		return reject("pod spec too large to snapshot (%d KiB)", len(encoded)>>10)
	}
	if mig.Annotations[webhook.AnnotationSourcePod] == encoded {
		return nil
	}
	base := mig.DeepCopy()
	if mig.Annotations == nil {
		mig.Annotations = map[string]string{}
	}
	mig.Annotations[webhook.AnnotationSourcePod] = encoded
	return r.Patch(ctx, mig, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}

// enterPreCopy records the preflight's decisions and starts pre-copy.
func (r *MigrationReconciler) enterPreCopy(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod, res *preflightResult) error {
	now := r.now()
	msg := fmt.Sprintf("pre-copy to %s (network %s, ip preserved: %t)", res.targetNode, res.adapter, res.preserved)
	err := r.transition(ctx, mig, v1alpha1.PhasePreCopy, msg, func(st *v1alpha1.MigrationStatus) {
		st.SourceNode = pod.Spec.NodeName
		st.SourcePodUID = string(pod.UID)
		st.SourcePodIP = pod.Status.PodIP
		st.OwnerKind, st.OwnerName = res.ownerKind, res.ownerName
		st.Cutover.ReplacementOwnerUID = res.ownerUID
		st.Cutover.Mode = res.cutoverMode
		st.Cutover.OriginalPodTemplateHash = res.origHash
		st.TargetNode = res.targetNode
		st.NetworkAdapter = res.adapter
		st.IPPreserved = res.preserved
		st.Network = res.network
		st.Volumes = res.volumes
		st.Warnings = res.warnings
		st.Timings.PreflightMs = msSince(st.StartedAt, now.Time)
	})
	if err == nil {
		for _, w := range res.warnings {
			r.emitTyped(mig, corev1.EventTypeWarning, "PreflightWarning", w)
		}
	}
	return err
}

// CheckPod checks the static properties of a pod. An error is always a
// rejection; warnings do not block.
func CheckPod(pod *corev1.Pod) (warnings []string, err error) {
	switch {
	case pod.Spec.NodeName == "" || pod.Status.Phase != corev1.PodRunning:
		return nil, reject("pod is not running on a node (phase %s)", pod.Status.Phase)
	case !pod.DeletionTimestamp.IsZero():
		return nil, reject("pod is being deleted")
	case pod.Spec.HostNetwork:
		return nil, reject("pod uses hostNetwork")
	case pod.Spec.HostPID:
		return nil, reject("pod uses hostPID")
	case pod.Spec.HostIPC:
		return nil, reject("pod uses hostIPC")
	case pod.Annotations[annotationMirrorPod] != "":
		return nil, reject("static (mirror) pods cannot be migrated")
	case len(foreignClaims(pod)) > 0:
		return nil, reject("pod uses DRA resource claims %v: their devices cannot be checkpointed", foreignClaims(pod))
	}
	if owner := metav1.GetControllerOf(pod); owner != nil {
		switch owner.Kind {
		case "DaemonSet":
			return nil, reject("pod is owned by DaemonSet %s (one pod per node by design)", owner.Name)
		case "Node":
			return nil, reject("static (mirror) pods cannot be migrated")
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			return nil, reject("volume %q is a hostPath (data stays on the node)", v.Name)
		}
		if v.Ephemeral != nil {
			return nil, reject("volume %q is a generic ephemeral volume (deleted together with the pod)", v.Name)
		}
	}
	all := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	all = append(append(all, pod.Spec.InitContainers...), pod.Spec.Containers...)
	for _, c := range all {
		if c.TTY || c.Stdin {
			return nil, reject("container %q has tty/stdin attached", c.Name)
		}
		for _, list := range []corev1.ResourceList{c.Resources.Requests, c.Resources.Limits} {
			for name := range list {
				switch {
				case isDeviceResource(name):
					return nil, reject("container %q requests device resource %s (GPU state cannot be checkpointed)", c.Name, name)
				case isExtendedResource(name):
					warnings = appendUnique(warnings, fmt.Sprintf("container %q requests extended resource %s; it must be available on the target", c.Name, name))
				}
			}
		}
	}
	// Pods started outside the paguro RuntimeClass have no time namespace of
	// their own (CLOCK_MONOTONIC jumps to the target node's clock after the
	// restore) and may hold MPTCP sockets, which CRIU cannot dump. The source
	// agent rejects the MPTCP case before freezing; the clock is a warning.
	if pod.Spec.RuntimeClassName == nil || *pod.Spec.RuntimeClassName != v1alpha1.RuntimeClassName {
		warnings = appendUnique(warnings, "pod was not started under RuntimeClass \"paguro\": no own time namespace (monotonic clocks will jump to the target node's clock) and MPTCP not disabled; restart the pod once to fix")
	}
	return warnings, nil
}

func isDeviceResource(name corev1.ResourceName) bool {
	n := string(name)
	return strings.HasSuffix(n, "/gpu") ||
		strings.HasPrefix(n, "nvidia.com/") ||
		strings.HasPrefix(n, "amd.com/") ||
		strings.HasPrefix(n, "gpu.intel.com/")
}

func isExtendedResource(name corev1.ResourceName) bool {
	n := string(name)
	if !strings.Contains(n, "/") {
		return false // cpu, memory, ephemeral-storage, hugepages-*
	}
	return !strings.HasPrefix(n, "kubernetes.io/") && !strings.HasPrefix(n, "requests.")
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// checkConcurrent prevents two concurrent migrations of the same pod.
// If created at the same time, the older one (or alphabetically first) wins.
func (r *MigrationReconciler) checkConcurrent(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod) error {
	var list v1alpha1.MigrationList
	if err := r.List(ctx, &list, client.InNamespace(mig.Namespace)); err != nil {
		return err
	}
	restoreID := pod.Annotations[v1alpha1.AnnotationRestoreID]
	for i := range list.Items {
		o := &list.Items[i]
		if o.UID == mig.UID || o.Status.Phase.Terminal() {
			continue
		}
		if restoreID != "" && string(o.UID) == restoreID {
			return reject("pod is still being restored by migration %s", o.Name)
		}
		if o.Status.TargetPodName == pod.Name {
			return reject("pod is the target of active migration %s", o.Name)
		}
		if o.Spec.PodName != pod.Name {
			continue
		}
		// The other one is further along or older → we give up.
		started := o.Status.Phase != "" && o.Status.Phase != v1alpha1.PhasePending && o.Status.Phase != v1alpha1.PhasePreflight
		older := o.CreationTimestamp.Before(&mig.CreationTimestamp) ||
			(o.CreationTimestamp.Equal(&mig.CreationTimestamp) && o.Name < mig.Name)
		if started || older {
			return reject("pod is already being migrated by %s", o.Name)
		}
	}
	return nil
}

// resolveOwner: direct controller (key for the webhook) and display owner
// (ReplicaSet → Deployment).
func (r *MigrationReconciler) resolveOwner(ctx context.Context, pod *corev1.Pod, res *preflightResult) error {
	owner := metav1.GetControllerOf(pod)
	res.cutoverMode = v1alpha1.CutoverOnDelete
	if owner == nil {
		// Bare pod: the controller creates the target pod during pre-copy.
		res.cutoverMode = v1alpha1.CutoverEarly
		return nil
	}
	res.ownerUID, res.ownerKind, res.ownerName = string(owner.UID), owner.Kind, owner.Name
	if isGameServer(owner) {
		res.cutoverMode = v1alpha1.CutoverSameName
		return r.checkGameServer(ctx, pod, owner)
	}
	if owner.Kind != "ReplicaSet" {
		return nil
	}
	// Bypass the cache: a ReplicaSet informer just for display is not worth it.
	var rs appsv1.ReplicaSet
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, &rs); err != nil {
		// Display only – no reason to abort (fall back to on-delete).
		return client.IgnoreNotFound(err)
	}
	// Deployment ReplicaSet (selector contains pod-template-hash): the source
	// can be detached from the ReplicaSet via a label change; the replacement
	// is created immediately and waits warm on the target.
	if hash, ok := pod.Labels[labelPodTemplateHash]; ok && hash != "" && selectsOnTemplateHash(&rs) {
		// A pod still detached by an earlier migration carries that
		// migration's hash; the ReplicaSet's own is in the annotation.
		if orig := pod.Annotations[AnnotationOriginalHash]; orig != "" {
			hash = orig
		} else if strings.Contains(hash, "-paguro-") {
			return reject("pod is still detached from its ReplicaSet by an earlier migration (label %s=%s); retry once it has been cleaned up",
				labelPodTemplateHash, hash)
		}
		res.cutoverMode = v1alpha1.CutoverEarly
		res.origHash = hash
	}
	if dep := metav1.GetControllerOf(&rs); dep != nil && dep.Kind == "Deployment" {
		res.ownerKind, res.ownerName = dep.Kind, dep.Name
	}
	return nil
}

// classifyVolumes classifies the volumes and collects the topology of the
// RWO PVs (must be satisfied by the target node).
func (r *MigrationReconciler) classifyVolumes(ctx context.Context, pod *corev1.Pod) (
	[]v1alpha1.VolumeStatus, []*corev1.NodeSelector, []string, error) {
	var out []v1alpha1.VolumeStatus
	var topology []*corev1.NodeSelector
	var warnings []string
	for _, v := range pod.Spec.Volumes {
		vs := v1alpha1.VolumeStatus{Name: v.Name}
		switch {
		case v.PersistentVolumeClaim != nil:
			vs.ClaimName = v.PersistentVolumeClaim.ClaimName
			var pvc corev1.PersistentVolumeClaim
			if err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: vs.ClaimName}, &pvc); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, nil, nil, reject("PVC %s not found", vs.ClaimName)
				}
				return nil, nil, nil, err
			}
			if pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName == "" {
				return nil, nil, nil, reject("PVC %s is not bound", vs.ClaimName)
			}
			vs.Kind = VolumePVCRWO
			for _, m := range pvc.Status.AccessModes {
				if m == corev1.ReadWriteMany || m == corev1.ReadOnlyMany {
					vs.Kind = VolumePVCRWX
				}
			}
			if vs.Kind == VolumePVCRWO {
				var pv corev1.PersistentVolume
				if err := r.Get(ctx, client.ObjectKey{Name: pvc.Spec.VolumeName}, &pv); err != nil {
					return nil, nil, nil, fmt.Errorf("reading PV %s: %w", pvc.Spec.VolumeName, err)
				}
				if pv.Spec.NodeAffinity != nil && pv.Spec.NodeAffinity.Required != nil {
					topology = append(topology, pv.Spec.NodeAffinity.Required)
				}
				if pv.Spec.Local != nil {
					return nil, nil, nil, reject("PVC %s is a local volume (bound to the node)", vs.ClaimName)
				}
			}
		case v.EmptyDir != nil:
			vs.Kind = VolumeEmptyDir
			if v.EmptyDir.Medium == corev1.StorageMediumMemory {
				warnings = append(warnings, fmt.Sprintf("emptyDir %q is tmpfs; its content is transferred like RAM", v.Name))
			}
		case v.ConfigMap != nil:
			vs.Kind = VolumeConfigMap
		case v.Secret != nil:
			vs.Kind = VolumeSecret
		case v.Projected != nil:
			vs.Kind = VolumeProjected
		case v.DownwardAPI != nil:
			vs.Kind = VolumeDownwardAPI
		default:
			vs.Kind = VolumeOther
			warnings = append(warnings, fmt.Sprintf("volume %q has an unclassified type; it must be reachable from the target node", v.Name))
		}
		out = append(out, vs)
	}
	return out, topology, warnings, nil
}

func (r *MigrationReconciler) selectTarget(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod,
	src *corev1.Node, topology []*corev1.NodeSelector, res *preflightResult) error {
	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		return err
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods); err != nil {
		return err
	}
	usage := placement.NodeUsage(pods.Items, string(pod.UID))
	if err := r.addMigrationsInFlight(ctx, mig, pods.Items, usage); err != nil {
		return err
	}
	result, err := placement.Select(placement.Request{
		Pod:            pod,
		SourceNode:     src,
		Nodes:          nodes.Items,
		Usage:          usage,
		TargetNode:     mig.Spec.TargetNode,
		CPUPolicy:      mig.Spec.CPUPolicy,
		VolumeTopology: topology,
	})
	var nt *placement.NoTargetError
	if errors.As(err, &nt) {
		return r.noTarget(mig, pod, src, nt.Error())
	}
	if err != nil {
		return err
	}
	res.targetNode = result.Node
	res.warnings = append(res.warnings, result.Warnings...)
	return nil
}

// decideNetwork sets the adapter and IP preservation according to spec.network.
func (r *MigrationReconciler) decideNetwork(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod, res *preflightResult) error {
	adapter, can, reason, srcCNI := r.canPreserve(ctx, pod, res.targetNode)
	mode, err := requestedNetwork(mig, pod)
	if err != nil {
		return err
	}
	can, phantom, err := r.applyNetworkMode(ctx, mode, pod, can, reason, res)
	if err != nil {
		return err
	}
	err = r.recordNetwork(ctx, mig, pod, adapter, can, phantom, res)
	res.network.CNI = srcCNI.Name
	return err
}

// canPreserve reports whether the cluster's adapter can keep the pod's IP
// – and why not – checked against both nodes' CNI: the cluster-wide
// detection (CRDs) can be wrong per node (Calico's CRDs also exist with
// Canal: host-local IPAM, IPs bound to the node).
func (r *MigrationReconciler) canPreserve(ctx context.Context, pod *corev1.Pod, target string) (
	adapter netadapter.Adapter, can bool, reason string, srcCNI netadapter.CNIInfo) {
	adapter = netadapter.Adapter(netadapter.Generic{})
	if r.Adapter != nil {
		adapter = r.Adapter()
	}
	can, reason = adapter.CanPreserve(pod)
	if pod.Status.PodIP == "" {
		can, reason = false, "source pod has no IP"
	}
	srcCNI, dstCNI := r.nodeCNI(ctx, pod.Spec.NodeName), r.nodeCNI(ctx, target)
	if can {
		for _, c := range []netadapter.CNIInfo{srcCNI, dstCNI} {
			if c.Name != "" && c.Name != netadapter.CNIUnknown && !c.MovableIP() {
				can, reason = false, fmt.Sprintf("CNI %s (%s/%s) cannot move a pod IP between nodes", c.Name, c.Plugin, c.IPAM)
			}
		}
	}
	return adapter, can, reason, srcCNI
}

// requestedNetwork is the network mode asked for: spec.network, else the
// pod's annotation – and Phantom mode for a pod an earlier Phantom
// migration restored. An unknown value is rejected, never read as Auto.
func requestedNetwork(mig *v1alpha1.Migration, pod *corev1.Pod) (v1alpha1.NetworkMode, error) {
	// The CRD's enum admits no other value, but an object stored before an
	// upgrade keeps the old one.
	mode, err := v1alpha1.ParseNetworkMode(string(mig.Spec.Network))
	if err != nil {
		return "", reject("spec.network: %v", err)
	}
	if mode == v1alpha1.NetworkAuto {
		if mode, err = v1alpha1.ParseNetworkMode(pod.Annotations[v1alpha1.AnnotationNetwork]); err != nil {
			return "", reject("pod annotation %s: %v", v1alpha1.AnnotationNetwork, err)
		}
	}
	// A pod restored by an earlier Phantom migration has connections whose
	// sockets use an older address of the pod; only Phantom mode keeps them
	// working (the new pod gets those addresses back and the translation
	// rules follow). Keeping the IP now would answer them with resets –
	// measured on Calico: RST from the restored socket, then packets to the
	// long-gone first address.
	if pod.Annotations[v1alpha1.AnnotationTCP] == webhook.TCPTranslate {
		switch mode {
		case v1alpha1.NetworkAuto:
			mode = v1alpha1.NetworkPhantom
		case v1alpha1.NetworkPreserve:
			return "", reject("network=Preserve for a pod that an earlier Phantom migration restored: its connections from " +
				"before use an older address that only Phantom mode keeps translating; network=Phantom or Auto keeps them")
		}
	}
	return mode, nil
}

// applyNetworkMode decides between keeping the IP, Phantom mode and a new
// IP with closed connections, as the mode allows.
func (r *MigrationReconciler) applyNetworkMode(ctx context.Context, mode v1alpha1.NetworkMode, pod *corev1.Pod, can bool, reason string,
	res *preflightResult) (bool, bool, error) {
	phantom := false
	switch mode {
	case v1alpha1.NetworkGeneric:
		can = false
	case v1alpha1.NetworkPhantom:
		// A sticky IP is a /32 pool of its own. Once the source is gone,
		// Cilium releases it and routes the old address out of the
		// cluster: its eBPF load balancer then sends NodePort traffic of a
		// migrated connection to the uplink with a new SNAT address –
		// measured: the client hung, the restored socket got a reset. Keep
		// the IP instead; that keeps every connection.
		if pool := pod.Annotations[v1alpha1.AnnotationStickyIP]; pool != "" {
			return false, false, reject("network=Phantom is not supported for a pod with a sticky IP (pool %s): once the source is gone "+
				"Cilium stops routing the old address, so connections through NodePort/LoadBalancer Services and from "+
				"host-network clients would hang; network=Preserve (the default for this pod) keeps every connection", pool)
		}
		can, phantom = false, true
		missing, err := r.phantomNodesMissing(ctx)
		if err != nil {
			return false, false, err
		}
		if len(missing) > 0 {
			res.warnings = append(res.warnings, fmt.Sprintf(
				"Phantom mode: connections to peers on nodes without a Phantom-capable agent will break: %v", missing))
		}
	case v1alpha1.NetworkPreserve:
		if !can {
			return false, false, reject("network=Preserve but IP cannot be preserved: %s", reason)
		}
	default: // Auto
		// Never Phantom mode for a sticky IP (see the explicit case above):
		// a sticky pod that cannot keep its IP closes its connections.
		if !can && r.PhantomAuto && pod.Annotations[v1alpha1.AnnotationStickyIP] == "" {
			missing, err := r.phantomNodesMissing(ctx)
			if err != nil {
				return false, false, err
			}
			phantom = len(missing) == 0
		}
		switch {
		case !can && phantom:
			res.warnings = append(res.warnings, "pod IP will change; in-cluster connections are kept by Phantom mode, connections to peers outside the cluster are closed: "+reason)
		case !can:
			res.warnings = append(res.warnings, "pod IP will change and established TCP connections will be closed: "+reason)
		}
	}
	return can, phantom, nil
}

// recordNetwork fills the preflight result's adapter and network status.
func (r *MigrationReconciler) recordNetwork(ctx context.Context, mig *v1alpha1.Migration, pod *corev1.Pod,
	adapter netadapter.Adapter, can, phantom bool, res *preflightResult) error {
	res.preserved = can
	res.adapter = netadapter.NameGeneric
	switch {
	case can:
		res.adapter = adapter.Name()
	case phantom:
		if pod.Status.PodIP == "" {
			return reject("Phantom mode: source pod has no IP")
		}
		res.adapter = netadapter.NamePhantom
		res.network = v1alpha1.NetworkStatus{PhantomClusterCIDRs: r.phantomClusterCIDRs(ctx)}
	}
	// Cilium: the replacement gets a fresh pool generation for the same /32.
	if can && adapter.Name() == netadapter.NameCilium {
		ip, err := netip.ParseAddr(pod.Status.PodIP)
		if err != nil {
			return reject("source pod IP %q: %v", pod.Status.PodIP, err)
		}
		res.network = v1alpha1.NetworkStatus{
			SourcePool: pod.Annotations[netadapter.AnnotationCiliumIPPool],
			TargetPool: netadapter.GenerationPoolName(ip, string(mig.UID)),
		}
	}
	return nil
}

// nodeCNI returns what the node's agent reported about its CNI (empty Name
// if the agent has not reported yet).
func (r *MigrationReconciler) nodeCNI(ctx context.Context, node string) netadapter.CNIInfo {
	var n corev1.Node
	if node == "" || r.Get(ctx, client.ObjectKey{Name: node}, &n) != nil {
		return netadapter.CNIInfo{}
	}
	v := n.Annotations[v1alpha1.AnnotationNodeCNI]
	if v == "" {
		return netadapter.CNIInfo{}
	}
	return netadapter.ParseCNIAnnotation(v)
}

// addMigrationsInFlight books the replacements of running migrations on
// their target nodes. A replacement held at the commit gate has no node
// yet, and an on-delete owner creates it only after the source is gone, so
// NodeUsage misses them – and Paguro places replacements itself, past the
// scheduler: two migrations chosen at once could fill one node, and kubelet
// would refuse the second replacement after its source was deleted.
func (r *MigrationReconciler) addMigrationsInFlight(ctx context.Context, mig *v1alpha1.Migration, pods []corev1.Pod,
	usage map[string]placement.Usage) error {
	var list v1alpha1.MigrationList
	if err := r.List(ctx, &list); err != nil {
		return err
	}
	bound := map[string]bool{} // restore id → its replacement is on a node (counted)
	for i := range pods {
		if id := pods[i].Annotations[v1alpha1.AnnotationRestoreID]; id != "" && pods[i].Spec.NodeName != "" {
			bound[id] = true
		}
	}
	for i := range list.Items {
		m := &list.Items[i]
		if m.UID == mig.UID || m.Status.Phase.Terminal() || m.Status.TargetNode == "" || bound[string(m.UID)] {
			continue
		}
		src, err := webhook.SourcePodOf(m)
		if err != nil {
			continue // no snapshot yet (preflight not finished)
		}
		usage[m.Status.TargetNode] = placement.AddPod(usage[m.Status.TargetNode], src)
	}
	return nil
}

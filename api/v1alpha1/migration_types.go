// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package v1alpha1 contains the Paguro API types (paguro.dev/v1alpha1).
//
// A Migration is the contract between three actors:
//
//   - paguro-controller: preflight, target node selection, deleting the
//     source pod, intercepting or creating the replacement pod, final state.
//   - paguro-agent on the source node: pre-copy rounds, freeze, final dump,
//     transfer to the target agent. Writes only status.source.
//   - paguro-agent on the target node: pre-pulling images, receiving,
//     reporting the wrapper's restore result. Writes only status.target.
//
// Each actor patches only "its own" fields (merge patch on the status
// subresource), so the three do not overwrite each other.
//
// +kubebuilder:object:generate=true
// +groupName=paguro.dev
package v1alpha1

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// The API package depends on apimachinery only, so that other projects can
// import the types without pulling in controller-runtime.
var (
	GroupVersion  = schema.GroupVersion{Group: "paguro.dev", Version: "v1alpha1"}
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &Migration{}, &MigrationList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}

// Strategy determines how memory is transferred.
// +kubebuilder:validation:Enum=PreCopy;StopAndCopy
type Strategy string

const (
	// PreCopy copies memory in rounds while the app keeps running, and only
	// freezes once just a few pages are still dirty.
	StrategyPreCopy Strategy = "PreCopy"
	// StopAndCopy freezes immediately and copies everything in one go.
	// Baseline for benchmarks; shortest total duration, longest freeze.
	StrategyStopAndCopy Strategy = "StopAndCopy"
)

// NetworkMode determines whether the pod IP and TCP connections are preserved.
// +kubebuilder:validation:Enum=Auto;Preserve;Phantom;Generic
type NetworkMode string

const (
	// Auto preserves IP and TCP if the detected CNI adapter supports it,
	// otherwise Phantom if every node supports it, otherwise Generic.
	NetworkAuto NetworkMode = "Auto"
	// Preserve requires IP preservation; fails in preflight if impossible.
	NetworkPreserve NetworkMode = "Preserve"
	// Phantom gives the pod a new IP and keeps its in-cluster connections:
	// eBPF programs translate the old address of each migrated connection to
	// the new one on the nodes involved (docs/PHANTOM-MODE.md). Works with
	// any CNI.
	NetworkPhantom NetworkMode = "Phantom"
	// Generic works with any CNI: new IP, established TCP connections are
	// closed cleanly, listening sockets are kept.
	NetworkGeneric NetworkMode = "Generic"
)

// ParseNetworkMode reads a network mode as spec.network or the pod
// annotation paguro.dev/network spells it, in any case; "" is Auto. Any
// other value is an error: read as Auto, it would give the pod a mode it
// did not ask for – under Cilium a sticky IP, which rules Phantom mode out
// for the pod's lifetime.
func ParseNetworkMode(v string) (NetworkMode, error) {
	if v == "" {
		return NetworkAuto, nil
	}
	for _, m := range []NetworkMode{NetworkAuto, NetworkPreserve, NetworkPhantom, NetworkGeneric} {
		if strings.EqualFold(v, string(m)) {
			return m, nil
		}
	}
	return "", fmt.Errorf("unknown network mode %q (want auto, preserve, phantom or generic)", v)
}

// CPUPolicy governs how differing CPU features are handled.
// +kubebuilder:validation:Enum=Strict;Ignore
type CPUPolicy string

const (
	// Strict: the target CPU must have all features of the source CPU.
	CPUStrict CPUPolicy = "Strict"
	// Ignore: warn only. Risk of SIGILL if glibc/JIT selected code paths at
	// startup for features the target lacks.
	CPUIgnore CPUPolicy = "Ignore"
)

type PreCopySpec struct {
	// Maximum number of pre-copy rounds before the freeze.
	// +kubebuilder:default=8
	// +kubebuilder:validation:Minimum=1
	MaxRounds int32 `json:"maxRounds,omitempty"`
	// Freeze as soon as a round wrote fewer than this many 4 KiB pages.
	// +kubebuilder:default=2048
	DirtyPageThreshold int64 `json:"dirtyPageThreshold,omitempty"`
	// Freeze after at most this many seconds of pre-copy. 0 (default):
	// four times the first round, at least 120 s – the first round copies
	// all memory (8 GiB over 1 GbE: 90 s), so a fixed limit cut large pods
	// short.
	// +kubebuilder:validation:Minimum=0
	MaxSeconds int32 `json:"maxSeconds,omitempty"`
	// Target duration of the final dump including transfer (ms). The agent
	// only freezes once (dirty pages / measured bandwidth) is below this –
	// or MaxRounds/MaxSeconds is reached.
	// +kubebuilder:default=500
	FreezeBudgetMs int32 `json:"freezeBudgetMs,omitempty"`
	// AutoConverge gradually throttles the app's CPU (cgroup cpu.max) when it
	// dirties memory faster than the network can copy it.
	// Same principle as QEMU auto-converge.
	// +kubebuilder:default=true
	AutoConverge *bool `json:"autoConverge,omitempty"`
}

// MigrationSpec describes what should be migrated where.
type MigrationSpec struct {
	// Name of the pod in this migration's namespace.
	// +kubebuilder:validation:MinLength=1
	PodName string `json:"podName"`
	// Target node. Empty = the controller picks a compatible node.
	// +optional
	TargetNode string `json:"targetNode,omitempty"`
	// +kubebuilder:default=PreCopy
	Strategy Strategy `json:"strategy,omitempty"`
	// +optional
	// +kubebuilder:default={}
	PreCopy PreCopySpec `json:"preCopy,omitempty"`
	// +kubebuilder:default=Auto
	Network NetworkMode `json:"network,omitempty"`
	// +kubebuilder:default=Strict
	CPUPolicy CPUPolicy `json:"cpuPolicy,omitempty"`
	// Overall time limit; after that rollback (if still possible) or Failed.
	// +kubebuilder:default=600
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
}

// Phase of the migration. Order on success:
// Pending → Preflight → PreCopy → Frozen → CuttingOver → Restoring → Succeeded
// Error path before the source is deleted: … → Aborting → RolledBack
// +kubebuilder:validation:Enum=Pending;Preflight;PreCopy;Frozen;CuttingOver;Restoring;Succeeded;Failed;Aborting;RolledBack
type Phase string

const (
	PhasePending     Phase = "Pending"
	PhasePreflight   Phase = "Preflight"
	PhasePreCopy     Phase = "PreCopy"
	PhaseFrozen      Phase = "Frozen"      // source frozen and dumped; pod still alive
	PhaseCuttingOver Phase = "CuttingOver" // source pod being deleted, replacement pod being created
	PhaseRestoring   Phase = "Restoring"   // replacement pod exists, wrapper restoring
	PhaseSucceeded   Phase = "Succeeded"
	PhaseFailed      Phase = "Failed"
	// Controller requests rollback; the source agent thaws and sets
	// status.source.thawedAt, then RolledBack.
	PhaseAborting   Phase = "Aborting"
	PhaseRolledBack Phase = "RolledBack" // source thawed again, nothing lost
)

// Terminal returns true for terminal states.
func (p Phase) Terminal() bool {
	return p == PhaseSucceeded || p == PhaseFailed || p == PhaseRolledBack
}

// RoundStat is the result of a pre-copy round or of the final dump.
type RoundStat struct {
	Round int32 `json:"round"`
	// Final is true for the dump during the freeze.
	Final bool `json:"final,omitempty"`
	// Memory pages (4 KiB) written in this round.
	Pages int64 `json:"pages"`
	// Bytes transferred in this round (after compression).
	WireBytes int64 `json:"wireBytes"`
	DumpMs    int64 `json:"dumpMs"`
	SendMs    int64 `json:"sendMs"`
	// CPU throttle during this round in percent (0 = none).
	ThrottlePct int32 `json:"throttlePct,omitempty"`
}

// ContainerStatus is written by the source agent.
type ContainerStatus struct {
	Name              string `json:"name"`
	SourceContainerID string `json:"sourceContainerID,omitempty"`
	// Resident set size at the time the migration started.
	RSSBytes int64       `json:"rssBytes,omitempty"`
	Rounds   []RoundStat `json:"rounds,omitempty"`
	// Size of the rootfs delta (writable layer).
	RootfsDiffBytes int64 `json:"rootfsDiffBytes,omitempty"`
	// TCP connections in the final dump.
	TCPEstablished int32 `json:"tcpEstablished,omitempty"`
}

// TargetContainerStatus is written by the target agent.
type TargetContainerStatus struct {
	Name              string `json:"name"`
	TargetContainerID string `json:"targetContainerID,omitempty"`
	Restored          bool   `json:"restored,omitempty"`
	RestoreMs         int64  `json:"restoreMs,omitempty"`
	// Set if the wrapper had to fall back to a cold start.
	ColdStartReason string `json:"coldStartReason,omitempty"`
}

// SourceStatus is written exclusively by the agent on the source node.
type SourceStatus struct {
	// The agent has accepted the migration.
	Accepted bool `json:"accepted,omitempty"`
	// Pre-copy has converged. When the pod IP changes (no IP adapter), the
	// replacement pod is only created now and the source keeps copying until
	// the target sandbox is up, so the freeze contains no pod creation, CNI
	// or kubelet latency.
	ReadyToFreezeAt *metav1.MicroTime `json:"readyToFreezeAt,omitempty"`
	// Time of the freeze: the application was paused on the source.
	FrozenAt *metav1.MicroTime `json:"frozenAt,omitempty"`
	// When the source told the target it is paused (EarlyHandOver): from
	// then on the replacement may take the address.
	HandOverAt *metav1.MicroTime `json:"handOverAt,omitempty"`
	// All data (final dump, rootfs, emptyDir) has reached the target.
	TransferDoneAt *metav1.MicroTime `json:"transferDoneAt,omitempty"`
	// The source was thawed again after an error.
	ThawedAt *metav1.MicroTime `json:"thawedAt,omitempty"`
	Message  string            `json:"message,omitempty"`
	Error    string            `json:"error,omitempty"`
	// Phantom mode: the pod's connections, harvested during the freeze and
	// published at the commit (never earlier: before the commit the source
	// may still be thawed and keep using its connections).
	// +optional
	Phantom *SourcePhantom `json:"phantom,omitempty"`
}

// SourcePhantom is what the source agent harvested for Phantom mode.
type SourcePhantom struct {
	Flows []PhantomFlow `json:"flows,omitempty"`
	// TCP ports with a listener bound to the old IP itself (not 0.0.0.0);
	// the target redirects new connections for them (self-IP fix-up).
	OldBoundListeners []int32 `json:"oldBoundListeners,omitempty"`
	// Flows Phantom mode cannot keep (peer outside the cluster). They are
	// closed right after the restore so the application reconnects at once.
	Unsupported int32 `json:"unsupported,omitempty"`
	// Ports of the pod's unconnected UDP sockets (game servers, QUIC, DNS).
	// Every node moves the NAT bindings of their clients that came through
	// a Service from the old IP to the new one, keeping the masquerade port
	// (docs/PHANTOM-MODE.md, "UDP servers").
	// +optional
	UDPServerPorts []int32 `json:"udpServerPorts,omitempty"`
}

// PhantomFlow is one connection of the migrated pod in the pod's own view.
type PhantomFlow struct {
	// tcp | udp
	Proto string `json:"proto"`
	// Pod side, old IP:port.
	Local string `json:"local"`
	// Peer as the pod's socket sees it.
	Remote string `json:"remote"`
	// Peer on the wire when the old node rewrote it (kube-proxy DNAT of a
	// ClusterIP); empty if equal to Remote.
	Wire string `json:"wire,omitempty"`
	// in-cluster | external-direct | external-snat
	Class string `json:"class"`
	// The migrated pod is the server side (Local is a listening port).
	Server bool `json:"server,omitempty"`
}

// TargetStatus is written exclusively by the agent on the target node.
type TargetStatus struct {
	// Images pulled, receive directory ready.
	Ready bool `json:"ready,omitempty"`
	// Pod volumes (status.volumes[].name) attached to the target node in
	// advance; set together with Ready.
	PreAttachedVolumes []string `json:"preAttachedVolumes,omitempty"`
	// Address at which the target agent accepts data (host:port).
	Endpoint string `json:"endpoint,omitempty"`
	// Sandbox (network namespace with IP) ready on the target – measured by
	// the wrapper with microsecond precision (pod conditions only have seconds).
	SandboxReadyAt *metav1.MicroTime `json:"sandboxReadyAt,omitempty"`
	// Kept IP on Cilium: the replacement's /32 is on the target node ahead of
	// the freeze (its pool generation's CIDR is in the node's CiliumNode).
	AddressReadyAt *metav1.MicroTime `json:"addressReadyAt,omitempty"`
	// Commit gate: kubelet has the replacement through admission and volume
	// setup and holds it right before its sandbox; the source freezes now.
	SandboxStagedAt *metav1.MicroTime `json:"sandboxStagedAt,omitempty"`
	// First container create on the target (start of the restore).
	RestoreStartedAt *metav1.MicroTime `json:"restoreStartedAt,omitempty"`
	// Time at which the last container was running restored.
	RestoredAt *metav1.MicroTime       `json:"restoredAt,omitempty"`
	Containers []TargetContainerStatus `json:"containers,omitempty"`
	Message    string                  `json:"message,omitempty"`
	Error      string                  `json:"error,omitempty"`
	// Phantom mode: state of the target node's translation.
	// +optional
	Phantom *TargetPhantom `json:"phantom,omitempty"`
}

// TargetPhantom is written by the target agent in Phantom mode.
type TargetPhantom struct {
	// The replacement pod's (new) IP and the target node's IP.
	NewIP  string `json:"newIP,omitempty"`
	NodeIP string `json:"nodeIP,omitempty"`
	// The target node translates the flows (inbound pending until the
	// restore). Other nodes program their side only after this.
	ProgrammedAt *metav1.MicroTime `json:"programmedAt,omitempty"`
	// Indexes into status.source.phantom.flows of connections that have ended;
	// their rules are removed on every node.
	DeadFlows []int32 `json:"deadFlows,omitempty"`
	// Every flow has ended or the pod is gone: all rules can be removed.
	ReleasedAt *metav1.MicroTime `json:"releasedAt,omitempty"`
}

// Timings summarizes the duration of each stage (milliseconds).
type Timings struct {
	PreflightMs int64 `json:"preflightMs,omitempty"`
	PreCopyMs   int64 `json:"preCopyMs,omitempty"`
	// Final dump during the freeze.
	FreezeDumpMs int64 `json:"freezeDumpMs,omitempty"`
	// From freeze until all data has reached the target.
	FinalTransferMs int64 `json:"finalTransferMs,omitempty"`
	// From source pod deletion until the replacement pod is bound.
	CutoverMs int64 `json:"cutoverMs,omitempty"`
	// Volume detach+attach (from VolumeAttachment timestamps).
	VolumeMoveMs int64 `json:"volumeMoveMs,omitempty"`
	RestoreMs    int64 `json:"restoreMs,omitempty"`
	// Freeze: how long the application was frozen – from its pause on the
	// source (source.frozenAt) until the restored process runs on the
	// target. Final dump, last transfer and restore lie within it. Clients
	// notice somewhat more (TCP retransmission timing).
	FreezeMs int64 `json:"freezeMs,omitempty"`
	TotalMs  int64 `json:"totalMs,omitempty"`
}

// MigrationStatus: phase/target/timings are written by the controller,
// source/target by the respective agents.
type MigrationStatus struct {
	Phase   Phase  `json:"phase,omitempty"`
	Message string `json:"message,omitempty"`

	SourceNode   string `json:"sourceNode,omitempty"`
	TargetNode   string `json:"targetNode,omitempty"`
	SourcePodUID string `json:"sourcePodUID,omitempty"`
	SourcePodIP  string `json:"sourcePodIP,omitempty"`
	// Owner of the source pod (ReplicaSet, StatefulSet ...); empty for bare pods.
	OwnerKind     string `json:"ownerKind,omitempty"`
	OwnerName     string `json:"ownerName,omitempty"`
	TargetPodName string `json:"targetPodName,omitempty"`
	TargetPodUID  string `json:"targetPodUID,omitempty"`
	TargetPodIP   string `json:"targetPodIP,omitempty"`

	// Effective network choice: cilium | calico | phantom | generic
	NetworkAdapter string `json:"networkAdapter,omitempty"`
	IPPreserved    bool   `json:"ipPreserved,omitempty"`
	// Adapter-specific network state, written by the controller.
	// +optional
	Network NetworkStatus `json:"network,omitempty"`
	// PVCs that are re-attached (RWO) or shared along (RWX).
	Volumes []VolumeStatus `json:"volumes,omitempty"`

	Containers []ContainerStatus `json:"containers,omitempty"`
	Source     SourceStatus      `json:"source,omitempty"`
	Target     TargetStatus      `json:"target,omitempty"`
	// Phantom mode: when each other node had programmed its side of the
	// migrated connections (node name -> time). Each agent writes only its
	// own key.
	// +optional
	PhantomNodes map[string]metav1.MicroTime `json:"phantomNodes,omitempty"`
	// Phantom mode: old addresses of migrated connections that a node found
	// no longer routed into the cluster – their pod subnet's route is gone,
	// e.g. the old node was deleted (address -> time). The controller
	// drops them from the backend keeper: a stateful load balancer then
	// resets such connections at once instead of sending them out of the
	// cluster, where they would hang.
	// +optional
	PhantomUnroutable map[string]metav1.MicroTime `json:"phantomUnroutable,omitempty"`
	Timings           Timings                     `json:"timings,omitempty"`
	// Total bytes transferred (all rounds, rootfs, emptyDir).
	WireBytes int64 `json:"wireBytes,omitempty"`

	// Cutover state maintained by the controller; lets a restarted
	// controller resume at the same point.
	// +optional
	Cutover CutoverStatus `json:"cutover,omitempty"`
	// Time of the controller's last phase change
	// (basis for phase timeouts and phase metrics).
	// +optional
	PhaseChangedAt *metav1.MicroTime `json:"phaseChangedAt,omitempty"`

	StartedAt   *metav1.MicroTime `json:"startedAt,omitempty"`
	CompletedAt *metav1.MicroTime `json:"completedAt,omitempty"`
	// When the ended migration stopped touching the source pod and its
	// owner (warm target removed, pod handed back to its ReplicaSet,
	// address re-announced, source deleted after a commit, GameServer
	// released). A later migration of the same pod waits for it.
	// +optional
	ReleasedAt *metav1.MicroTime `json:"releasedAt,omitempty"`
	// Warnings from preflight (e.g. CPU feature mismatch with Ignore).
	Warnings   []string           `json:"warnings,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NetworkStatus is written exclusively by the controller.
type NetworkStatus struct {
	// CNI active on the source node (from its paguro.dev/cni annotation).
	CNI string `json:"cni,omitempty"`
	// Cilium: sticky CiliumPodIPPool of the source pod (annotation
	// ipam.cilium.io/ip-pool). Deleted at cutover.
	SourcePool string `json:"sourcePool,omitempty"`
	// Cilium: fresh pool generation for the replacement pod, same /32 as the
	// source. Created during pre-copy (PoolPreparedAt) so that the operator
	// can hand the /32 to the target node before the freeze – the source's
	// endpoint keeps the address until then (an endpoint always takes
	// precedence over a node's CIDR) – or, failing that, at cutover.
	TargetPool string `json:"targetPool,omitempty"`
	// When the controller created TargetPool during pre-copy.
	PoolPreparedAt *metav1.MicroTime `json:"poolPreparedAt,omitempty"`
	// CommitGate: the replacement waits at the commit gate on the target
	// node (a DRA claim, see internal/agent/dragate.go) and gets its sandbox
	// the moment the migration is committed. Decided at preflight: kept IP,
	// the target's agent runs the gate, no RWO volume (kubelet could not
	// reach the gate before the source's detach).
	CommitGate bool `json:"commitGate,omitempty"`
	// EarlyHandOver: the replacement leaves the commit gate as soon as the
	// source is paused, not at the commit – its sandbox (CNI, pause
	// container) is created while the final dump runs. Only where the
	// replacement can claim the address while the source still holds it
	// (Cilium: the prepared TargetPool) and the address can be given back
	// after a rollback (ReannouncedAt).
	EarlyHandOver bool `json:"earlyHandOver,omitempty"`
	// HandOverAfterSourceStop: the replacement leaves the commit gate when
	// the source agent has torn down the source's sandbox (the address is
	// free then), not at the commit. Calico: its IPAM hands the address to
	// the replacement only after the source's CNI DEL; released at the
	// commit, kubelet's first sandbox attempt failed and it retried only
	// once a second.
	HandOverAfterSourceStop bool `json:"handOverAfterSourceStop,omitempty"`
	// After a rollback with EarlyHandOver: when the controller announced
	// the source's endpoint to the cluster again (the replacement's endpoint
	// had taken over the address).
	ReannouncedAt *metav1.MicroTime `json:"reannouncedAt,omitempty"`
	// When the controller deleted SourcePool (and made sure TargetPool exists).
	PoolRotatedAt *metav1.MicroTime `json:"poolRotatedAt,omitempty"`
	// Phantom mode: prefixes that belong to the cluster (pod and service
	// ranges, node addresses). A connection to anything else cannot be
	// translated on the peer's side.
	PhantomClusterCIDRs []string `json:"phantomClusterCIDRs,omitempty"`
}

// CutoverStatus is written exclusively by the controller.
type CutoverStatus struct {
	// UID of the direct controller (ReplicaSet, StatefulSet, Job ...) of the
	// source pod. Its next new pod is turned into the restore target by the
	// webhook. Empty for bare pods.
	ReplacementOwnerUID string `json:"replacementOwnerUID,omitempty"`
	// Time at which the controller issued the deletion of the source pod.
	SourceDeletedAt *metav1.MicroTime `json:"sourceDeletedAt,omitempty"`
	// Endpoint bridge (controller): EndpointSlices that keep the serving
	// address ready in the pod's Services across the hand-over, and when
	// they were created.
	EndpointBridge   []string          `json:"endpointBridge,omitempty"`
	EndpointBridgeAt *metav1.MicroTime `json:"endpointBridgeAt,omitempty"`
	// Time at which the replacement pod object first existed.
	TargetPodCreatedAt *metav1.MicroTime `json:"targetPodCreatedAt,omitempty"`
	// Mode: "early" – the replacement pod is created during pre-copy already
	// (Deployment pods: source detached from the ReplicaSet via
	// pod-template-hash; bare pods: created by the controller) and waits warm
	// for the data; "on-delete" – the owner creates the replacement only after
	// the source is deleted (StatefulSet, Job, other owners); "same-name" –
	// the owner never creates a second pod (Agones GameServer), the
	// controller creates it under the source's name once the source is gone.
	// +kubebuilder:validation:Enum=early;on-delete;same-name
	// +optional
	Mode string `json:"mode,omitempty"`
	// Original value of the source's pod-template-hash label (early with
	// ReplicaSet); restored on rollback.
	OriginalPodTemplateHash string `json:"originalPodTemplateHash,omitempty"`
	// Time at which the controller requested the early replacement pod.
	ReplacementRequestedAt *metav1.MicroTime `json:"replacementRequestedAt,omitempty"`
	// Interception of the replacement pod by the admission webhook. The
	// controller arms it (InterceptArmedAt); the first webhook replica that
	// admits a new pod of the owner claims it (InterceptedAt, InterceptedPod)
	// with the object's resourceVersion as precondition – exactly one pod
	// becomes the restore target, whichever replica sees it.
	// +optional
	InterceptArmedAt *metav1.MicroTime `json:"interceptArmedAt,omitempty"`
	// +optional
	InterceptedAt *metav1.MicroTime `json:"interceptedAt,omitempty"`
	// Name (or generateName) of the intercepted pod.
	// +optional
	InterceptedPod string `json:"interceptedPod,omitempty"`
}

// Values for CutoverStatus.Mode.
const (
	CutoverEarly    = "early"
	CutoverOnDelete = "on-delete"
	// CutoverSameName: the owner never creates a second pod (Agones
	// GameServer); Paguro creates the replacement under the same name once
	// the source is gone.
	CutoverSameName = "same-name"
)

// VolumeKindPVCRWO is status.volumes[].kind of a ReadWriteOnce PVC.
const VolumeKindPVCRWO = "pvc-rwo"

// VolumeKindPVCRWX is status.volumes[].kind of a ReadWriteMany PVC (a
// shared filesystem).
const VolumeKindPVCRWX = "pvc-rwx"

// FreezeAfterTargetSandbox reports whether the source freezes only once the
// replacement pod's sandbox is up. That needs a new pod IP (with a kept IP
// the sandbox can only start after the cutover), an early replacement
// (on-delete owners such as StatefulSets reuse the pod name) and every RWO
// volume pre-attached (kubelet creates the sandbox only after the volumes
// are attached). Meaningful once Target.Ready is set.
func (s *MigrationStatus) FreezeAfterTargetSandbox() bool {
	if s.IPPreserved || s.Cutover.Mode != CutoverEarly {
		return false
	}
	pre := make(map[string]bool, len(s.Target.PreAttachedVolumes))
	for _, v := range s.Target.PreAttachedVolumes {
		pre[v] = true
	}
	for _, v := range s.Volumes {
		if v.Kind == VolumeKindPVCRWO && !pre[v.Name] {
			return false
		}
	}
	return true
}

type VolumeStatus struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"` // pvc-rwo | pvc-rwx | emptyDir | configMap | secret | projected | downwardAPI
	ClaimName  string            `json:"claimName,omitempty"`
	Bytes      int64             `json:"bytes,omitempty"`
	DetachedAt *metav1.MicroTime `json:"detachedAt,omitempty"`
	AttachedAt *metav1.MicroTime `json:"attachedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pmig;mig,categories=paguro
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
// +kubebuilder:printcolumn:name="From",type=string,JSONPath=`.status.sourceNode`
// +kubebuilder:printcolumn:name="To",type=string,JSONPath=`.status.targetNode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="IP-kept",type=boolean,JSONPath=`.status.ipPreserved`
// +kubebuilder:printcolumn:name="Freeze-ms",type=integer,JSONPath=`.status.timings.freezeMs`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Migration moves a running pod, including its memory state, to another
// node.
type Migration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MigrationSpec   `json:"spec,omitempty"`
	Status MigrationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type MigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Migration `json:"items"`
}

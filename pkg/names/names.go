// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package names contains the annotations, paths and file names shared by all
// Paguro components. Deliberately free of dependencies: paguro-runc runs on
// every runc invocation on the node and must start within milliseconds.
package names

// Annotations and labels. containerd passes everything with the prefix
// "paguro.dev/" through to the OCI spec (pod_annotations/container_annotations
// in the "paguro" runtime handler) – that is how the wrapper learns that it
// should restore.
const (
	// LabelMigratable is the opt-in: the pod may be migrated and gets a
	// migratable ("sticky") IP on creation if the CNI adapter needs one.
	LabelMigratable = "paguro.dev/migratable"

	// AnnotationRestore is set on the replacement pod: the name of the
	// migration (namespace = pod namespace).
	AnnotationRestore = "paguro.dev/restore"
	// AnnotationMigrating is set on an owner (Agones GameServer) while
	// Paguro replaces its pod: the migration's UID. The chart's admission
	// policy keeps the owner's controller from declaring the pod lost.
	AnnotationMigrating = "paguro.dev/migrating"

	// AnnotationRestoreID is set on the replacement pod: the UID of the
	// migration (directory name on the node).
	AnnotationRestoreID = "paguro.dev/restore-id"
	// AnnotationTestFault on a Migration makes the source agent fail at a
	// named point (failure tests; only agents started with --test-faults).
	AnnotationTestFault = "paguro.dev/test-fault"
	// AnnotationTCP is set on the replacement pod: the TCP strategy, one of
	// the TCP* values below.
	AnnotationTCP = "paguro.dev/tcp"
	// AnnotationOldIP is set on the replacement pod: the old pod IP; the
	// generic adapter adds it as an additional local address so that sockets
	// bound to it can be restored.
	AnnotationOldIP = "paguro.dev/old-ip"
	// AnnotationSkippedInit is set on the replacement pod: the removed init
	// containers (JSON list of names), because they already ran on the
	// source.
	AnnotationSkippedInit = "paguro.dev/skipped-init-containers"
	// AnnotationStickyIP is set on every pod with a sticky IP: the name of
	// the associated IP object.
	AnnotationStickyIP = "paguro.dev/sticky-ip"
	// SchedulingGateCommit holds a replacement created during pre-copy
	// (kept IP on Cilium) away from its node until the migration is
	// committed: its first sandbox attempt must come after the freeze and
	// succeed at once – a failed attempt is retried only at kubelet's next
	// status refresh, up to a second later.
	SchedulingGateCommit = "paguro.dev/commit"
	// AnnotationNodeCommitGate is a node annotation maintained by the agent:
	// "true" when the commit gate (a DRA driver) is registered with kubelet.
	AnnotationNodeCommitGate = "paguro.dev/commit-gate"
	// AnnotationNodeSubnets is a node annotation maintained by the agent
	// where the CNI gives pods addresses from the node's own subnets (AWS
	// VPC CNI, Azure CNI): those subnets, comma-separated. Phantom mode
	// counts them as in-cluster.
	AnnotationNodeSubnets = "paguro.dev/node-subnets"
	// AnnotationNodeTerminatesAt is a node annotation: the time (RFC 3339)
	// at which the node goes away regardless of what runs on it. The agent
	// sets it from the cloud's notice (EC2: a spot interruption); anything
	// else that knows the time may set it too. Migrations off the node plan
	// with it (controller, deadline).
	AnnotationNodeTerminatesAt = "paguro.dev/terminates-at"
	// TaintAgentNotReady is a startup taint for new nodes (Karpenter's
	// NodePool spec.template.spec.startupTaints, or the node's kubelet
	// registration): the agent removes it once it can take migrations, so
	// that the node counts as initialized only then.
	TaintAgentNotReady = "paguro.dev/agent-not-ready"
	// GateClaim is the name of the commit-gate claim in a replacement pod's
	// spec.resourceClaims; the ResourceClaim itself is GateClaimPrefix plus
	// the migration's UID suffix.
	GateClaim       = "paguro-gate"
	GateClaimPrefix = "paguro-gate-"
	// GateDriver is the commit gate's DRA driver and DeviceClass.
	GateDriver = "gate.paguro.dev"
	// LabelMigrationUID marks objects that belong to one migration (keeper,
	// endpoint bridge, commit-gate claim): the Migration's UID.
	LabelMigrationUID = "paguro.dev/migration-uid"
	// SchedulerNameBind is the scheduler name of such a replacement: no
	// scheduler answers to it, Paguro binds the pod itself.
	SchedulerNameBind = "paguro-bind"

	// AnnotationNodeCPUFlags is a node annotation maintained by the agent:
	// the CPU flags (sorted, comma-separated).
	AnnotationNodeCPUFlags = "paguro.dev/cpu-flags"
	// AnnotationCPUBaseline is set on migratable pods at creation: the CPU
	// features the pod's runtimes may use (comma-separated). paguro-runc
	// starts the containers with the common runtimes limited to it; a
	// target that lacks only features outside it is eligible.
	AnnotationCPUBaseline = "paguro.dev/cpu-baseline"
	// AnnotationNodeCPUModel is a node annotation: the CPU model name
	// (informational only).
	AnnotationNodeCPUModel = "paguro.dev/cpu-model"
	// AnnotationNodeAgent is a node annotation: the agent endpoint host:port.
	AnnotationNodeAgent = "paguro.dev/agent-endpoint"
	// AnnotationNodeAgentVersion is a node annotation: the agent's release
	// (its image tag). Source and target of a migration run the same one.
	AnnotationNodeAgentVersion = "paguro.dev/agent-version"
	// AnnotationNodeAgentDraining is a node annotation, set while the agent
	// shuts down (upgrade, uninstall) since the given time: it finishes the
	// migrations it takes part in but is not chosen for new ones.
	AnnotationNodeAgentDraining = "paguro.dev/agent-draining"
	// AnnotationNodeCRIU is a node annotation: the detected CRIU version.
	AnnotationNodeCRIU = "paguro.dev/criu-version"
	// AnnotationNodePhantom is a node annotation: "available" when the
	// agent can run Phantom mode (bpffs and eBPF translator ready), else
	// "unavailable".
	AnnotationNodePhantom = "paguro.dev/phantom"
	// AnnotationNetwork on a pod (or its template) chooses the network mode
	// for migrations that request Auto: preserve | phantom | generic.
	// Workloads that do not advertise their own IP can opt into the faster
	// Phantom mode.
	AnnotationNetwork = "paguro.dev/network"
	// AnnotationNodeCNI is a node annotation: the node's active CNI
	// configuration as "<name>;<plugin>/<ipam>" (netadapter.CNIInfo).
	AnnotationNodeCNI = "paguro.dev/cni"

	// RuntimeClassName is the RuntimeClass whose handler points to
	// paguro-runc.
	RuntimeClassName = "paguro"

	// Finalizer keeps Migration objects from disappearing while a source is
	// frozen.
	Finalizer = "paguro.dev/thaw-guard"
)

// Values of AnnotationTCP: how the restore treats the pod's connections.
const (
	// TCPEstablished: same IP, connections are restored as they were.
	TCPEstablished = "established"
	// TCPTranslate: Phantom mode – new IP, connections restored on the old
	// address and translated on the wire.
	TCPTranslate = "translate"
	// TCPClose: generic mode – new IP, connections are closed.
	TCPClose = "close"
)

// Paths on the node.
const (
	// StateDir is the root for received checkpoints:
	// <StateDir>/restore/<migration-uid>/
	StateDir = "/var/lib/paguro"
	// RunDir holds the wrapper's runtime markers (tmpfs, lost on reboot –
	// intentionally).
	RunDir = "/run/paguro"
	// RuncRoot is containerd's runc state root in the CRI namespace.
	RuncRoot = "/run/containerd/runc/k8s.io"

	// AgentPort is the agent's port (hostNetwork).
	AgentPort = 9555
)

// FileAborted, in <StateDir>/restore/<uid>/: the migration ended before its
// commit (rollback). The source runs on; a replacement must never start –
// the wrapper fails its create instead of waiting for data or cold-starting.
const FileAborted = "ABORTED"

// FileHandOver, in <StateDir>/restore/<uid>/: the source is paused (early
// hand-over); the target's commit gate may release the replacement.
const FileHandOver = "HANDOVER"

// File names inside <StateDir>/restore/<uid>/containers/<name>/.
const (
	FileReady      = "READY"     // all data present
	FileFailed     = "FAILED"    // source reports an abort, the wrapper should cold-start
	FileRestored   = "RESTORED"  // wrapper: restore succeeded (JSON with timings)
	FileColdStart  = "COLDSTART" // wrapper: restore failed, cold-started (reason)
	FileRootfsDiff = "rootfs-diff.tar"
	FileMeta       = "meta.json"
	FileSandbox    = "SANDBOX" // wrapper: sandbox ready (RFC3339Nano)
	// FileSandboxNetns holds the sandbox's network namespace path (host view).
	FileSandboxNetns = "SANDBOX_NETNS"
	DirImages        = "images" // images/<round>/, images/final/
)

// ReplacementName returns the name Paguro gives a replacement pod with
// generateName (ReplicaSet, Job …). It is derived deterministically from the
// migration's UID – so the target agent already knows during pre-copy under
// which name the pod will later run CNI ADD, and can request the IP in
// advance under exactly this owner.
func ReplacementName(generateName, migrationUID string) string {
	name := generateName + "p" + UIDSuffix(migrationUID)
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

// UIDSuffix returns the first 5 lowercase alphanumeric characters of a UID.
// Every name Paguro derives from a migration (replacement pod, Cilium pool
// generation, detached pod-template-hash) uses it, so the webhook and the
// controller always agree.
func UIDSuffix(uid string) string {
	out := make([]rune, 0, 5)
	for _, r := range uid {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		}
		if len(out) == 5 {
			break
		}
	}
	return string(out)
}

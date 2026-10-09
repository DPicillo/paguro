// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package agent is Paguro's data plane: one agent per node which, as the
// source, dumps and sends memory and, as the target, receives it and watches
// the restore.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/ctguard"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/shield"
)

type Agent struct {
	// Client reads from the manager's cache, which holds only this node's
	// pods; APIReader reads pods of other nodes directly. Read Nodes only
	// through APIReader: the agent may get its own Node but not list
	// Nodes, so the cache's informer for them never syncs and a Get through
	// Client blocks for good (measured: an agent that read its Node through
	// the cache never started).
	Client    client.Client
	APIReader client.Reader
	Host      *Host
	NodeName  string
	Endpoint  string // InternalIP:Port
	Token     string
	Log       *slog.Logger
	// TransferTLS is nil when the transfer runs over plain HTTP.
	TransferTLS *TransferTLS
	// transferUp: the transfer server listens; until then the node does not
	// advertise an endpoint and gets no migrations.
	transferUp atomic.Bool
	// peers caches source and target node per migration for
	// AuthorizeTransfer.
	peerMu sync.Mutex
	peers  map[types.UID][2]string
	// Cilium is nil when no Cilium agent socket exists on the node.
	Cilium *CiliumHooks
	// Phantom is nil when this node cannot run Phantom mode (no bpffs, no
	// eBPF).
	Phantom *phantomManager
	// PhantomSteerMark is the bit of the packet mark that steers the
	// forwarded connections of Phantom mode (phantom/steer.go); 0 means
	// phantom.DefaultSteerMark.
	PhantomSteerMark uint32
	// commitGate: kubelet has confirmed the commit gate's registration
	// (dragate.go).
	commitGate atomic.Bool
	// Version is the agent's release (image tag), advertised on the node.
	Version string
	// draining: since when the agent shuts down (Drain); nil while it runs.
	draining atomic.Pointer[time.Time]
	// bg: clean-ups started for ended migrations, awaited by Drain.
	bg sync.WaitGroup
	// withdrawn: the drain is over and the endpoint withdrawn; the node
	// annotations are no longer published.
	withdrawn atomic.Bool
	// advertised: the node annotations carry this agent's endpoint.
	advertised atomic.Bool
	// annotateMu serializes AnnotateNode: a slow earlier call must not
	// overwrite a later one (measured: the start-up annotation, computed
	// before kubelet confirmed the gate, landed after the confirmation).
	annotateMu sync.Mutex
	// TestFaults enables the paguro.dev/test-fault annotation (failure
	// tests). Off in production.
	TestFaults bool
	// PreAttach: the target attaches RWO volumes during pre-copy
	// (preattach.go). Needs the right to create VolumeAttachments for this
	// node, so it is opt-in.
	PreAttach bool

	// mu guards states.
	mu     sync.Mutex
	states map[types.UID]*migState
}

// migState is what this agent remembers about one migration: its running
// jobs and the one-shot steps already taken. Dropped when the Migration
// object is gone.
type migState struct {
	key types.NamespacedName

	// Source side.
	source       *sourceJob
	cancelSource context.CancelFunc
	lostReported bool // the job of an earlier agent process was reported lost
	resuming     bool // this process resumed the transfer after the commit
	thawing      bool // a thaw after an abort is running
	sourceEnded  bool // the job was ended (terminal phase)

	// Target side.
	cancelTarget context.CancelFunc // non-nil: a target job runs
	abortMarked  bool               // a waiting replacement was told the migration rolled back
	targetEnded  bool               // ended: rescue started or the images' clean-up scheduled

	// Uninvolved node (Calico, kept IP): the NAT guard of the pod's bindings.
	natSet         *ctguard.Set
	bystanderFinal bool // the guard has the bindings from the commit on

	// Every node, Phantom mode: the move of the UDP servers' NAT bindings has
	// started (udprebind.go).
	udpRebind bool
}

func (a *Agent) init() { a.states = map[types.UID]*migState{} }

// stateOf returns the migration's state; a.mu must be held.
func (a *Agent) stateOf(m *v1.Migration) *migState {
	st := a.states[m.UID]
	if st == nil {
		st = &migState{key: client.ObjectKeyFromObject(m)}
		a.states[m.UID] = st
	}
	return st
}

// forget drops the states of a deleted Migration.
func (a *Agent) forget(key types.NamespacedName) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for uid, st := range a.states {
		if st.key == key {
			delete(a.states, uid)
		}
	}
}

// SetupWithManager registers the reconciler. It filters for migrations this
// node is involved in.
func (a *Agent) SetupWithManager(mgr ctrl.Manager) error {
	a.init()
	// Phantom migrations concern every node: any node may host a peer.
	mine := predicate.NewPredicateFuncs(func(o client.Object) bool {
		m, ok := o.(*v1.Migration)
		return ok && (m.Status.SourceNode == a.NodeName || m.Status.TargetNode == a.NodeName || isPhantom(m) || needsClusterNATGuard(m))
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("paguro-agent").
		For(&v1.Migration{}, builder.WithPredicates(mine)).
		WithOptions(controllerOptions()).
		Complete(a)
}

// Reconcile starts or stops this node's jobs. The actual work runs in
// goroutines; Reconcile itself returns immediately.
func (a *Agent) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	m := &v1.Migration{}
	if err := a.Client.Get(ctx, req.NamespacedName, m); err != nil {
		if apierrors.IsNotFound(err) {
			a.forget(req.NamespacedName)
			if a.Phantom != nil {
				go a.Phantom.sweep(context.Background()) // releases what this node installed
			}
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if a.Phantom != nil && isPhantom(m) {
		go a.Phantom.reconcile(context.Background(), req.NamespacedName)
	}
	log := a.Log.With("migration", req.String(), "phase", m.Status.Phase)
	// Before taking the lock: it dumps the conntrack table.
	if m.Status.SourceNode != a.NodeName && m.Status.TargetNode != a.NodeName && needsClusterNATGuard(m) {
		a.guardBystander(m, log)
	}
	// Takes the lock briefly.
	a.rebindUDPServers(m, log)
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.stateOf(m)

	if m.Status.SourceNode == a.NodeName {
		a.reconcileSource(m, st, log)
	}
	if m.Status.TargetNode == a.NodeName {
		a.reconcileTarget(m, st, log)
	}
	return ctrl.Result{}, nil
}

// reconcileSource starts, reports, resumes, thaws or ends this node's
// source side of m. a.mu must be held; the work runs in goroutines.
func (a *Agent) reconcileSource(m *v1.Migration, st *migState, log *slog.Logger) {
	job := st.source
	switch {
	case m.Status.Phase == v1.PhasePreCopy && m.Status.Target.Ready && !m.Status.Source.Accepted && job == nil:
		jctx, cancel := context.WithCancel(context.Background())
		job = &sourceJob{a: a, log: log.With("role", "source"), m: m.DeepCopy()}
		st.source, st.cancelSource = job, cancel
		go job.run(jctx)
	case m.Status.Phase == v1.PhasePreCopy && m.Status.Source.Accepted && m.Status.Source.Error == "" &&
		job == nil && !st.lostReported:
		a.reportLostSource(m, st, log)
	case job == nil && a.resumable(m) && !st.resuming:
		// Restarted after the commit: send what the lost job did not.
		st.resuming = true
		go a.resumeTransfer(context.Background(), m.DeepCopy(), log.With("role", "source"))
	case m.Status.Phase == v1.PhaseAborting && m.Status.Source.ThawedAt == nil && !st.thawing:
		a.thawSource(m, st, job, log)
	case m.Status.Phase.Terminal() && !st.sourceEnded:
		a.endSource(m, st, log)
	}
}

// reportLostSource: this agent was restarted during pre-copy or the final
// dump; the job and its state are gone, the pod may be frozen. Reporting
// it lets the controller abort now instead of after the migration's
// timeout; the abort thaws the pod statelessly (thawSource). The commit
// sets phase Frozen in the same patch, and the final images are only sent
// after it, so before the commit no target can run a copy of the pod.
func (a *Agent) reportLostSource(m *v1.Migration, st *migState, log *slog.Logger) {
	st.lostReported = true
	go func() {
		err := a.patchStatus(context.Background(), m, map[string]any{"source": map[string]any{
			"error": "the source agent was restarted during the migration"}})
		log.Warn("lost the source job (agent restarted): migration aborted", "err", err)
		if err != nil {
			a.mu.Lock()
			st.lostReported = false
			a.mu.Unlock()
		}
	}()
}

// thawSource thaws the source after an abort – through the job, or
// statelessly when the agent was restarted and has no job in memory – and
// reports it.
func (a *Agent) thawSource(m *v1.Migration, st *migState, job *sourceJob, log *slog.Logger) {
	st.thawing = true
	if st.cancelSource != nil {
		st.cancelSource()
	}
	go func() {
		var err error
		if job != nil {
			err = job.thaw(context.Background())
		} else {
			err = a.thawPod(context.Background(), m)
		}
		patch := map[string]any{"thawedAt": now()}
		if err != nil {
			patch["error"] = "thaw: " + err.Error()
		}
		if err := a.patchStatus(context.Background(), m, map[string]any{"source": patch}); err != nil {
			// Not reported: let the next event thaw (idempotent) and report again.
			log.Warn("reporting the thaw failed", "err", err)
			a.mu.Lock()
			st.thawing = false
			a.mu.Unlock()
		}
	}()
}

// endSource ends the source side of a finished migration and removes its
// dump.
func (a *Agent) endSource(m *v1.Migration, st *migState, log *slog.Logger) {
	st.sourceEnded = true
	if st.cancelSource != nil {
		st.cancelSource()
	}
	st.source = nil
	// New IP: the frozen source kept its sandbox (its endpoint stays
	// terminating in the Services) until the replacement serves.
	if !m.Status.IPPreserved && m.Status.Cutover.SourceDeletedAt != nil && m.Status.SourcePodUID != "" {
		podUID := types.UID(m.Status.SourcePodUID)
		a.bg.Go(func() { a.stopPodSandbox(podUID, "", log.With("role", "source")) })
	}
	go a.Host.Run(context.Background(), nil, "rm", "-rf", fmt.Sprintf("%s/dump/%s", v1.StateDir, m.UID))
}

// reconcileTarget prepares, watches, rescues or ends this node's target
// side of m. a.mu must be held; the work runs in goroutines.
func (a *Agent) reconcileTarget(m *v1.Migration, st *migState, log *slog.Logger) {
	if abortedBeforeCommit(m) && !st.abortMarked {
		// The source runs on: a replacement already waiting in the
		// wrapper must fail instead of restoring or cold-starting.
		if err := markAborted(string(m.UID)); err != nil {
			log.Warn("marking the restore as aborted", "err", err)
		} else {
			st.abortMarked = true
		}
	}
	running := st.cancelTarget != nil
	switch {
	case m.Status.Phase.Terminal():
		a.endTarget(m, st)
	case committed(m.Status.Phase) && !running:
		// Restarted after the commit: the wrapper restores on its own,
		// but only a target job reports it – without one the controller
		// declared a restored migration failed after RestoreTimeout
		// (measured: target agent killed at the commit, workload
		// restored in 0.6 s, migration "Failed" 5 min later).
		jctx, cancel := context.WithCancel(context.Background())
		st.cancelTarget = cancel
		job := &targetJob{a: a, log: log.With("role", "target"), m: m.DeepCopy()}
		job.log.Info("resuming the restore watch after an agent restart")
		go job.kickSandbox(jctx)
		go func() {
			if err := job.watchRestore(jctx); err != nil && jctx.Err() == nil {
				job.log.Error("restore watch", "err", err)
			}
		}()
	case m.Status.Phase == v1.PhasePreCopy && !m.Status.Target.Ready && !running:
		jctx, cancel := context.WithCancel(context.Background())
		st.cancelTarget = cancel
		job := &targetJob{a: a, log: log.With("role", "target"), m: m.DeepCopy()}
		go job.run(jctx)
	}
}

// endTarget ends the target side of a finished migration. A failed one
// whose source is gone is rescued instead: the replacement is the only
// copy of the workload.
func (a *Agent) endTarget(m *v1.Migration, st *migState) {
	if m.Status.Phase == v1.PhaseFailed && m.Status.Cutover.SourceDeletedAt != nil {
		// Never give up on the replacement: keep kicking kubelet and the
		// Cilium nodes, and keep the checkpoint until the pod runs. A late
		// restore is still correct – the source never executed again
		// after the freeze. Pre-attached volumes stay: the replacement
		// pod needs them.
		if !st.targetEnded {
			st.targetEnded = true
			go a.rescue(m.DeepCopy())
		}
		return
	}
	if st.cancelTarget != nil {
		st.cancelTarget()
		st.cancelTarget = nil
	}
	if st.targetEnded {
		return
	}
	st.targetEnded = true
	// After the commit the replacement needs its volumes, even when the
	// migration failed (rescue).
	if a.PreAttach && (m.Status.Phase == v1.PhaseRolledBack || m.Status.Cutover.SourceDeletedAt == nil) &&
		m.Status.Phase != v1.PhaseSucceeded {
		uid := m.UID
		a.bg.Go(func() { a.releasePreAttached(context.Background(), uid) })
	}
	uid := string(m.UID)
	// A lazy-pages daemon may still be serving a large pod's memory, or
	// the replacement still waits for its restore; then the state janitor
	// removes the images later.
	time.AfterFunc(2*time.Minute, func() {
		if !inUse(uid) && !a.restoreAwaited(context.Background(), uid) {
			cleanupImages(uid)
		}
	})
}

// needsClusterNATGuard: Calico's Felix flushes the conntrack entries of a
// workload address on every node when its endpoint goes – also the NAT
// bindings of NodePort clients entering on an uninvolved node.
func needsClusterNATGuard(m *v1.Migration) bool {
	return m.Status.IPPreserved && m.Status.NetworkAdapter == netadapter.NameCalico && !m.Status.Phase.Terminal()
}

// guardBystander guards this node's NAT bindings of the migrated pod
// (natguard.go): recorded when the source is about to freeze, completed at
// the commit – before the source's endpoint goes, which makes Felix flush
// them. One guard per migration and node. The conntrack dump runs outside
// a.mu (controller-runtime never reconciles one migration twice at once).
func (a *Agent) guardBystander(m *v1.Migration, log *slog.Logger) {
	ip, err := netip.ParseAddr(m.Status.SourcePodIP)
	if err != nil || m.Status.Source.ReadyToFreezeAt == nil {
		return
	}
	frozen := m.Status.Source.FrozenAt != nil
	a.mu.Lock()
	st := a.stateOf(m)
	set := st.natSet
	done := set != nil && (!frozen || st.bystanderFinal)
	if set == nil && st.bystanderFinal {
		done = true // nothing of this pod passes this node
	}
	a.mu.Unlock()
	if done {
		return
	}
	entries, err := ctguard.Snapshot(ip)
	if err != nil {
		log.Warn("conntrack snapshot failed – NAT bindings on this node are not guarded", "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if frozen {
		st.bystanderFinal = true
	}
	switch {
	case set != nil:
		set.Add(entries)
	case len(entries) > 0:
		set = &ctguard.Set{}
		st.natSet = set
		set.Add(entries)
		go func() {
			a.guardNATSet(m, set, log.With("role", "bystander"))
			a.mu.Lock()
			st.natSet = nil
			a.mu.Unlock()
		}()
	}
}

// abortedBeforeCommit: the migration was (or is being) rolled back, or
// failed while the source still existed.
func abortedBeforeCommit(m *v1.Migration) bool {
	if m.Status.Cutover.SourceDeletedAt != nil {
		return false
	}
	return m.Status.Phase == v1.PhaseAborting || m.Status.Phase == v1.PhaseRolledBack || m.Status.Phase == v1.PhaseFailed
}

// markAborted leaves the wrapper's marker for a migration that ended before
// its commit (names.FileAborted).
func markAborted(uid string) error {
	if err := os.MkdirAll(layout.Root(uid), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(layout.Root(uid), v1.FileAborted), nil, 0o600)
}

// patchStatus writes a merge patch to the status subresource. Merge patches
// only touch the listed fields – the controller and the other agent can
// write their own fields at the same time.
func (a *Agent) patchStatus(ctx context.Context, m *v1.Migration, status map[string]any) error {
	b, err := json.Marshal(map[string]any{"status": status})
	if err != nil {
		return err
	}
	obj := &v1.Migration{}
	obj.Namespace, obj.Name = m.Namespace, m.Name
	var lastErr error
	for i := 0; i < 5; i++ {
		if lastErr = a.Client.Status().Patch(ctx, obj, client.RawPatch(types.MergePatchType, b)); !retriable(lastErr) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(time.Duration(50*(i+1)) * time.Millisecond):
		}
	}
	return lastErr
}

// retriable: an API error a retry can cure (not NotFound, not an invalid
// request).
func retriable(err error) bool {
	return err != nil && (apierrors.IsConflict(err) || apierrors.IsServerTimeout(err) || apierrors.IsTimeout(err) ||
		apierrors.IsTooManyRequests(err) || apierrors.IsServiceUnavailable(err) || apierrors.IsInternalError(err) ||
		apierrors.ReasonForError(err) == metav1.StatusReasonUnknown)
}

// AnnotateNode publishes CPU features, endpoint and CRIU version. The
// controller uses them to choose target nodes and to check CPU compatibility.
func (a *Agent) AnnotateNode(ctx context.Context) error {
	a.annotateMu.Lock()
	defer a.annotateMu.Unlock()
	if a.withdrawn.Load() {
		return nil
	}
	model, flags := CPUInfo()
	criu := "unknown"
	if out, err := a.Host.Run(ctx, nil, "criu", "--version"); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Version:"); ok {
				criu = strings.TrimSpace(v)
			}
		}
	}
	cni, err := netadapter.DetectNodeCNI(a.Host.Path("/etc/cni/net.d"))
	if err != nil {
		a.Log.Warn("CNI configuration not readable", "err", err)
	}
	annotations := map[string]any{
		v1.AnnotationNodeCNI:          cni.String(),
		v1.AnnotationNodeCPUFlags:     strings.Join(flags, ","),
		v1.AnnotationNodeCPUModel:     model,
		v1.AnnotationNodeAgent:        a.advertisedEndpoint(),
		v1.AnnotationNodeAgentVersion: a.Version,
		v1.AnnotationNodeCRIU:         criu,
		v1.AnnotationNodePhantom:      phantomCapability(a.Phantom),
		v1.AnnotationNodeCommitGate:   strconv.FormatBool(a.commitGate.Load()),
		// null removes it: a previous agent's drain is over.
		v1.AnnotationNodeAgentDraining: nil,
	}
	if since := a.draining.Load(); since != nil {
		annotations[v1.AnnotationNodeAgentDraining] = since.UTC().Format(time.RFC3339)
	}
	annotations[v1.AnnotationNodeSubnets] = nil
	if cni.PodsInNodeSubnets() {
		if subnets, err := nodeSubnets("/sys/class/net"); err != nil {
			a.Log.Warn("node subnets not readable – Phantom mode may take pods for external peers", "err", err)
		} else if len(subnets) > 0 {
			annotations[v1.AnnotationNodeSubnets] = strings.Join(subnets, ",")
		}
	}
	if a.Version == "" {
		annotations[v1.AnnotationNodeAgentVersion] = nil
	}
	patch := map[string]any{"metadata": map[string]any{"annotations": annotations}}
	b, _ := json.Marshal(patch)
	node := &corev1.Node{}
	node.Name = a.NodeName
	if err := a.Client.Patch(ctx, node, client.RawPatch(types.MergePatchType, b)); err != nil {
		return err
	}
	if annotations[v1.AnnotationNodeAgent] != "" {
		a.advertised.Store(true)
	}
	return nil
}

// Advertised: other agents and the controller can reach this agent – its
// readiness. A rolling update of the agents moves on to the next node only
// then (measured: the DaemonSet counted an agent ready 1 s before its
// endpoint was published, while it waited for its certificate).
func (a *Agent) Advertised() bool { return a.advertised.Load() && !a.withdrawn.Load() }

// errNotPreCopy: the migration left pre-copy before the source committed –
// the controller aborted it.
var errNotPreCopy = errors.New("the migration is no longer in pre-copy (aborted)")

// commit reports freeze and dump in one status patch – phase Frozen plus
// the source's data – but only while the migration is still in pre-copy: an
// abort the controller decided meanwhile must win over a late commit, or
// the controller would delete a source that this agent then thaws. The
// object's resourceVersion is the precondition. The first read comes from
// the cache (no round trip inside the freeze); a conflict – other agents
// update the status too – is retried with a fresh read.
// errCommitNotApplied: the commit failed and the migration is still in
// pre-copy – nothing was committed.
var errCommitNotApplied = errors.New("the commit did not reach the API server")

// commitTimeout bounds the commit; it is not cancelled with the job.
const commitTimeout = 30 * time.Second

// commitResolved commits and turns an unclear outcome into a clear one. The
// commit decides whether the source may ever run again, so it is neither
// cancelled with the job (an abort cancelling it halfway counted as
// committed: the target cold-started while the abort thawed the source –
// two copies) nor trusted on error: the migration is re-read, and only
// phase Frozen counts as committed.
func (a *Agent) commitResolved(ctx context.Context, m *v1.Migration, status map[string]any) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitTimeout)
	defer cancel()
	err := a.commit(cctx, m, status)
	if err == nil || errors.Is(err, errNotPreCopy) {
		return err
	}
	cur := &v1.Migration{}
	if gerr := a.APIReader.Get(cctx, client.ObjectKeyFromObject(m), cur); gerr != nil || cur.UID != m.UID {
		return err // unknown: treated as committed (the target is told to cold-start)
	}
	switch {
	case cur.Status.Phase == v1.PhasePreCopy:
		return fmt.Errorf("%w: %v", errCommitNotApplied, err)
	case cur.Status.Source.FrozenAt != nil:
		return nil // landed although the answer was lost (only the commit sets frozenAt)
	case cur.Status.Phase == v1.PhaseAborting || cur.Status.Phase == v1.PhaseRolledBack:
		return fmt.Errorf("%w: %v", errNotPreCopy, err)
	}
	return err
}

func (a *Agent) commit(ctx context.Context, m *v1.Migration, status map[string]any) error {
	status["phase"] = v1.PhaseFrozen
	var reader client.Reader = a.Client
	for i := 0; i < 8; i++ {
		cur := &v1.Migration{}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(m), cur); err != nil {
			return err
		}
		if cur.UID != m.UID || cur.Status.Phase != v1.PhasePreCopy {
			return errNotPreCopy
		}
		b, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"resourceVersion": cur.ResourceVersion},
			"status":   status,
		})
		if err != nil {
			return err
		}
		err = a.Client.Status().Patch(ctx, cur, client.RawPatch(types.MergePatchType, b))
		if !apierrors.IsConflict(err) {
			return err
		}
		reader = a.APIReader
		time.Sleep(time.Duration(10*(i+1)) * time.Millisecond)
	}
	return errors.New("commit: the migration's status kept changing")
}

// thawPod thaws all paused containers of a pod and lowers the shield –
// without knowledge from a running job, only from runc state.
func (a *Agent) thawPod(ctx context.Context, m *v1.Migration) error {
	pod := &corev1.Pod{}
	if err := a.Client.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: m.Spec.PodName}, pod); err != nil {
		return client.IgnoreNotFound(err)
	}
	if string(pod.UID) != m.Status.SourcePodUID {
		return nil
	}
	var errs []error
	netns := ""
	for _, s := range append(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses...) {
		_, id, ok := strings.Cut(s.ContainerID, "://")
		if !ok {
			continue
		}
		st, err := a.Host.State(ctx, id)
		if err != nil {
			continue
		}
		if netns == "" && st.Pid > 0 {
			netns = fmt.Sprintf("/proc/%d/ns/net", st.Pid)
		}
		if st.Status == "paused" {
			if err := a.Host.Resume(ctx, id); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if netns != "" {
		if err := shield.Lower(a.Host.ShieldRunner(ctx), netns); err != nil {
			errs = append(errs, err)
		}
	}
	// Auto-converge may have throttled the containers' CPU; the job that
	// knew the original quota is gone, its record is not.
	for _, s := range append(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses...) {
		rec := a.Host.Path(filepath.Join(v1.StateDir, "dump", string(m.UID), throttleFile(s.Name)))
		if err := a.Host.RestoreThrottle(ctx, rec); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rescue keeps a failed migration's replacement pod alive until it runs
// (restored, or cold-started by the wrapper as last resort), then cleans up.
func (a *Agent) rescue(m *v1.Migration) {
	log := a.Log.With("migration", m.Namespace+"/"+m.Name, "role", "rescue")
	if !a.rescueNeeded(context.Background(), m) {
		return
	}
	log.Warn("migration failed after the source was deleted – keeping the replacement pod alive")
	job := &targetJob{a: a, log: log, m: m}
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	job.kickSandbox(ctx)
	if err := job.watchRestore(ctx); err != nil {
		log.Error("rescue: restore watch ended", "err", err)
	}
	log.Info("rescue: replacement pod is running")
	time.Sleep(2 * time.Minute)
	cleanupImages(string(m.UID))
}

// rescueRecent: a failure this recent may still get its replacement pod
// (its owner creates it after the source's deletion).
const rescueRecent = time.Hour

// rescueNeeded: the failure is recent, or a replacement of the migration
// still waits on this node. Older failures whose replacement runs or is
// gone need nothing – measured: every agent start rescued three migrations
// failed days before, each polling for its restore for 24 h.
func (a *Agent) rescueNeeded(ctx context.Context, m *v1.Migration) bool {
	if m.Status.PhaseChangedAt == nil || time.Since(m.Status.PhaseChangedAt.Time) < rescueRecent {
		return true
	}
	pods := &corev1.PodList{}
	if err := a.Client.List(ctx, pods); err != nil {
		return true
	}
	for _, p := range pods.Items {
		if p.Annotations[v1.AnnotationRestoreID] == string(m.UID) && p.Spec.NodeName == a.NodeName &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodPending {
			return true
		}
	}
	return false
}

func controllerOptions() controller.Options { return controller.Options{MaxConcurrentReconciles: 4} }

func jsonEncode(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

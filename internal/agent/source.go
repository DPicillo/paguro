// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Source side, part 1: the job and its course – start, pre-copy until the
// target is ready, freeze and final dump, commit and transfer. The parts
// live in source_precopy.go, source_freeze.go, source_release.go and
// source_transfer.go.

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/archive"
	"paguro.dev/paguro/internal/criulog"
	"paguro.dev/paguro/internal/ctguard"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/ocispec"
	"paguro.dev/paguro/internal/phantom"
)

// pageSize is the page size of this machine (4 KiB on x86-64, 4 or 64 KiB on arm64).
var pageSize = int64(os.Getpagesize())

// lazyPagesMinRSS is the RSS from which the target restores with lazy pages.
// Measured: an eager restore writes every page before the process resumes –
// 1 GiB took 1.87 s inside the freeze, and its cost also grows with the
// target's CPU load: 128 MiB took 190 ms on an idle worker but 764 ms on a
// busy 2-vCPU control-plane node. A lazy restore costs a fixed ~100 ms
// (pages are local; faults are served from the target's own disk), so it is
// the more predictable choice from a few tens of MiB on.
const lazyPagesMinRSS = 64 << 20

// srcContainer is a container of the source pod with everything the dump
// needs.
type srcContainer struct {
	name, id, image string
	pid             int
	rss             int64
	upper           string
	throttle        *Throttle
	stat            v1.ContainerStatus
}

// sourceJob executes the source side of a migration.
type sourceJob struct {
	a      *Agent
	log    *slog.Logger
	m      *v1.Migration
	pod    *corev1.Pod
	cs     []*srcContainer
	netns  string
	client *Client
	// sandboxID is the CRI pod sandbox, resolved before the freeze so that
	// stopping it after the commit costs a single CRI call.
	sandboxID string
	// boundIPs: local addresses of the pod's sockets at the freeze (new-IP
	// modes; sent in the final metadata).
	boundIPs []string

	mu     sync.Mutex
	frozen bool // paused + shield
	// throttleMu guards the containers' throttles and throttlePct: an abort
	// restores them while the job may still be between two rounds.
	throttleMu sync.Mutex
	// throttlePct is the CPU share auto-converge leaves the containers
	// (100: not throttled).
	throttlePct int
	drained     bool // the drain shield is up (drain.go)
	// remapLinks: link remaps created after the final dump
	// (source_remap.go), removed by a rollback.
	remapLinks []string
	// emptyDirBases: what was sent of each emptyDir during pre-copy.
	emptyDirBases map[string]archive.Manifest
	// devShm: the pod's own /dev/shm held files at the freeze; they travel
	// as layout.DevShmVolume (captureFilesystems).
	devShm    bool
	committed bool // phase Frozen reported – no rollback from here on
	wire      int64
	// dumping is held (shared) while CRIU dumps; thaw takes it exclusively.
	dumping sync.RWMutex
}

// dumpTimeout bounds a single CRIU run, which is never cancelled halfway.
const dumpTimeout = 15 * time.Minute

// dump runs one CRIU dump (pre-dump or final). It is not cancelled when the
// job is: killing the runc command would only kill nsenter, and runc and
// CRIU would go on – a final dump that finishes after a thaw puts the
// cgroup back into the frozen state it found, so the pod would stay frozen
// while the status says thawed; and a CRIU killed halfway can leave its
// parasite code in the tasks. A thaw waits for running dumps instead.
func (j *sourceJob) dump(ctx context.Context, req DumpRequest) (DumpResult, error) {
	if err := ctx.Err(); err != nil {
		return DumpResult{}, err
	}
	j.dumping.RLock()
	defer j.dumping.RUnlock()
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dumpTimeout)
	defer cancel()
	return j.a.Host.Dump(dctx, req)
}

func (j *sourceJob) dumpRoot() string {
	return filepath.Join(v1.StateDir, "dump", string(j.m.UID))
}

func (j *sourceJob) imagesDir(c *srcContainer, round string) string {
	return filepath.Join(j.dumpRoot(), "containers", c.name, v1.DirImages, round)
}

// run is the complete flow; errors before the commit lead to a rollback.
func (j *sourceJob) run(ctx context.Context) {
	// Requests still in flight (hand-over retries) finish; only idle
	// connections are closed.
	defer func() {
		if j.client != nil {
			j.client.Close()
		}
	}()
	err := j.execute(ctx)
	if err == nil {
		return
	}
	attrs := []any{"err", err}
	var cf *criuFailure
	if errors.As(err, &cf) {
		attrs = append(attrs, "runc", cf.err.Error(), "criuLog", cf.log)
	}
	j.log.Error("migration failed on the source", attrs...)
	j.mu.Lock()
	committed := j.committed
	j.mu.Unlock()

	bg := context.Background()
	if !committed {
		thawErr := j.thaw(bg)
		patch := map[string]any{"error": err.Error(), "thawedAt": now()}
		if thawErr != nil {
			patch["error"] = err.Error() + "; thaw: " + thawErr.Error()
		}
		_ = j.a.patchStatus(bg, j.m, map[string]any{"source": patch})
		return
	}
	// After the commit the source is (soon) deleted. The target should not
	// wait 100 s but cold-start immediately.
	for _, c := range j.cs {
		_ = j.client.Marker(bg, string(j.m.UID), c.name, "failed", err.Error())
	}
	_ = j.a.patchStatus(bg, j.m, map[string]any{"source": map[string]any{"error": err.Error()}})
}

// execute runs the source side of a migration in four steps; until the
// commit any error rolls back (run thaws the source), after it the target
// is the workload.
func (j *sourceJob) execute(ctx context.Context) error {
	if err := j.start(ctx); err != nil {
		return err
	}
	preStart := time.Now()
	rounds, err := j.copyUntilReady(ctx)
	if err != nil {
		return err
	}
	preCopyMs := ms(time.Since(preStart))
	f, err := j.freezeAndDump(ctx, rounds)
	if err != nil {
		return err
	}
	return j.commitAndSend(ctx, f, preCopyMs)
}

// start accepts the migration and opens the transfer to the target.
func (j *sourceJob) start(ctx context.Context) error {
	m := j.m
	if err := j.resolve(ctx); err != nil {
		return fmt.Errorf("resolve containers: %w", err)
	}
	if err := j.checkBlockers(ctx); err != nil {
		return err
	}
	if err := j.a.patchStatus(ctx, m, map[string]any{
		"source":     map[string]any{"accepted": true, "message": "pre-copy running"},
		"containers": j.containerStats(),
	}); err != nil {
		return err
	}
	cl, err := j.a.newClient(m.Status.Target.Endpoint, m.Status.TargetNode)
	if err != nil {
		return err
	}
	j.client = cl
	if err := j.sendMeta(ctx, time.Time{}, 0); err != nil {
		return fmt.Errorf("target unreachable: %w", err)
	}
	return nil
}

// copyUntilReady copies memory while the application runs – the pre-copy
// rounds, then more rounds while the target gets ready – and returns the
// number of rounds sent.
func (j *sourceJob) copyUntilReady(ctx context.Context) (int, error) {
	m := j.m
	rounds := 0
	// The emptyDirs' content travels alongside the memory rounds (and stops
	// when this returns early).
	bctx, stopBases := context.WithCancel(ctx)
	defer stopBases()
	basesSent := make(chan struct{})
	go func() {
		defer close(basesSent)
		j.sendEmptyDirBases(bctx)
	}()
	if m.Spec.Strategy != v1.StrategyStopAndCopy {
		var err error
		if rounds, err = j.preCopy(ctx); err != nil {
			return 0, fmt.Errorf("pre-copy: %w", err)
		}
	}
	waits := []struct {
		needed bool
		await  func(context.Context, int) (int, error)
		what   string
	}{
		{m.Status.FreezeAfterTargetSandbox(), j.awaitTargetSandbox, "waiting for the target sandbox"},
		{m.Status.IPPreserved && m.Status.Network.TargetPool != "", j.awaitTargetAddress, "waiting for the replacement's address"},
		{m.Status.Network.CommitGate, j.awaitTargetStaged, "waiting for the replacement at the commit gate"},
	}
	for _, w := range waits {
		if !w.needed {
			continue
		}
		var err error
		if rounds, err = w.await(ctx, rounds); err != nil {
			return 0, fmt.Errorf("%s: %w", w.what, err)
		}
	}
	select {
	case <-basesSent:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	// The target folds rounds into its base in the background; the last
	// one must be done before the freeze, not inside it. The pod runs on
	// while the source waits, and what it writes meanwhile all lands in the
	// final dump: a wait longer than a round interval is followed by one
	// more round, whose compaction is short (measured on lab nodes with
	// slow disks: 2–4 s of waiting put 70–100k pages into Minecraft's
	// final dump).
	for extra := 0; rounds > 0; extra++ {
		start := time.Now()
		if err := j.awaitCompaction(ctx); err != nil {
			return 0, fmt.Errorf("the target could not apply the pre-copy rounds: %w", err)
		}
		waited := time.Since(start)
		if waited < extraRoundEvery || extra == maxCompactionRounds {
			break
		}
		j.log.Info("compaction took a while – one more round", "waitMs", ms(waited), "round", rounds+1)
		if _, err := j.copyRound(ctx, rounds+1, j.currentThrottle()); err != nil {
			return 0, err
		}
		rounds++
	}
	return rounds, nil
}

// maxCompactionRounds bounds the extra rounds while the target compacts.
const maxCompactionRounds = 3

// frozen is what freezeAndDump hands to the commit.
type frozen struct {
	at         time.Time
	rounds     int
	dumpMs     int64
	source     map[string]any // the commit's status.source
	natEntries []ctguard.Entry
	harvested  *v1.SourcePhantom // Phantom mode: the frozen pod's connections
	lockScan   <-chan []heldLock
	steps      *stepTimer
}

// stepTimer collects where the freeze goes (logged with the transfer).
type stepTimer struct {
	mu    sync.Mutex
	steps []any
}

func (s *stepTimer) add(name string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, name, ms(d))
}

func (s *stepTimer) since(name string, start time.Time) { s.add(name, time.Since(start)) }

func (s *stepTimer) list() []any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.steps)
}

// freezeAndDump freezes the pod and takes the final dump. Everything else
// the commit needs runs alongside the dump: each reads the paused pod, none
// depends on the dump (measured before, all in a row: ~40 ms between pause
// and dump for a small pod).
func (j *sourceJob) freezeAndDump(ctx context.Context, rounds int) (*frozen, error) {
	m := j.m
	// A socket or ring opened during pre-copy would fail the final dump –
	// inside the freeze. Checking costs a few file reads.
	if err := j.checkBlockers(ctx); err != nil {
		return nil, err
	}
	j.drain(ctx)
	f := &frozen{at: time.Now(), rounds: rounds, steps: &stepTimer{}}
	if err := j.freeze(ctx); err != nil {
		return nil, fmt.Errorf("freeze: %w", err)
	}
	f.steps.since("pauseMs", f.at)
	// Early hand-over (dragate.go): from now on the replacement may take the
	// address – its sandbox is created while the final dump runs. Best
	// effort: undelivered, the gate opens at the commit as usual.
	var handedOver chan time.Time
	if m.Status.Network.EarlyHandOver {
		handedOver = make(chan time.Time, 1)
		go func() {
			if err := j.client.HandOver(ctx, string(m.UID)); err != nil {
				j.log.Warn("early hand-over not delivered – the replacement starts at the commit", "err", err)
				return
			}
			handedOver <- time.Now()
		}()
	}
	// Calico: the route guard goes up now, alongside the dump – it was a
	// host program right before the CNI DEL, on the freeze's critical path.
	// Safe this early: it drops only transit traffic for the address, never
	// traffic to or from a pod interface, and it expires by itself.
	if needsRouteGuard(m) {
		go j.a.guardRoute(m, j.log)
	}
	if err := j.injectFault(ctx, "after-pause", handedOver); err != nil {
		return nil, err
	}

	waitAside := j.alongsideDump(ctx, f)
	dumpStart := time.Now()
	f.steps.add("preDumpMs", dumpStart.Sub(f.at))
	dumpErr := j.finalDump(ctx, rounds)
	f.dumpMs = ms(time.Since(dumpStart))
	f.steps.add("dumpMs", time.Since(dumpStart))
	t := time.Now()
	asideErr := waitAside()
	f.steps.since("asideWaitMs", t) // what the work alongside added to the dump
	if err := errors.Join(dumpErr, asideErr); err != nil {
		return nil, err
	}

	f.source = map[string]any{"frozenAt": micro(f.at), "message": "frozen, transferring the rest"}
	select {
	case t := <-handedOver: // nil channel: no hand-over
		f.source["handOverAt"] = micro(t)
	default:
	}
	if f.harvested != nil {
		f.source["phantom"] = f.harvested
	}
	// Everything the transfer after the commit needs, next to the dump: an
	// agent restarted after the commit sends the rest from it (resume.go).
	t = time.Now()
	if err := layout.WriteJSONAtomic(j.localFile(fileResume), j.finalMeta(f.at, rounds)); err != nil {
		return nil, fmt.Errorf("resume record: %w", err)
	}
	f.steps.since("resumeRecordMs", t)
	return f, nil
}

// alongsideDump starts what the commit needs besides the dump; each part
// reads the paused pod, none depends on the dump. The returned function
// waits for all of them.
func (j *sourceJob) alongsideDump(ctx context.Context, f *frozen) (wait func() error) {
	m := j.m
	var aside sync.WaitGroup
	// Keep-IP mode: record the NAT bindings of the pod's connections on
	// this node before the CNI may flush them (internal/ctguard).
	if m.Status.IPPreserved {
		if ip, err := netip.ParseAddr(j.pod.Status.PodIP); err == nil {
			aside.Go(func() {
				var err error
				if f.natEntries, err = ctguard.Snapshot(ip); err != nil {
					j.log.Warn("conntrack snapshot failed – NAT bindings are not guarded", "err", err)
				}
			})
		}
	}
	// New IP: the restore must configure every address the pod's sockets
	// are bound to (earlier IPs after chained migrations). Phantom mode:
	// harvest the frozen pod's connections; published with the commit, never
	// earlier.
	var boundErr, harvestErr error
	if !m.Status.IPPreserved {
		aside.Go(func() {
			bound, err := phantom.BoundAddrs(j.netns)
			if err != nil {
				boundErr = fmt.Errorf("listing bound addresses: %w", err)
				return
			}
			for _, a := range bound {
				j.boundIPs = append(j.boundIPs, a.String())
			}
			if isPhantom(m) {
				start := time.Now()
				// Without the flow list every connection would break silently.
				if f.harvested, err = harvestPhantom(j.netns, m.Status.SourcePodIP, bound, m.Status.Network.PhantomClusterCIDRs); err != nil {
					harvestErr = fmt.Errorf("harvesting connections for Phantom mode: %w", err)
					return
				}
				f.harvested.UDPServerPorts = harvestUDPServerPorts(j.netns, m.Status.SourcePodIP, j.log)
				j.log.Info("phantom: connections harvested", "flows", len(f.harvested.Flows), "unsupported", f.harvested.Unsupported,
					"oldBoundListeners", len(f.harvested.OldBoundListeners), "udpServerPorts", f.harvested.UDPServerPorts,
					"ms", ms(time.Since(start)))
			}
		})
	}
	var syncErr, filesystemsErr error
	aside.Go(func() {
		start := time.Now()
		syncErr = j.syncVolumes(ctx)
		f.steps.since("syncMs", start)
	})
	// The rootfs and emptyDir deltas, saved locally while the pod still
	// exists: after the commit kubelet deletes both. The pod is paused, its
	// writable layers cannot change.
	aside.Go(func() {
		start := time.Now()
		filesystemsErr = j.captureFilesystems(ctx)
		f.steps.since("filesystemsMs", start)
	})
	// Locks on shared filesystems (locks.go): found while the dump runs,
	// handed over before READY.
	lockScan := make(chan []heldLock, 1)
	go func() { lockScan <- sharedFSLocks("/proc", j.podPIDs(ctx)) }()
	f.lockScan = lockScan

	return func() error {
		aside.Wait()
		if filesystemsErr != nil {
			filesystemsErr = fmt.Errorf("filesystem delta: %w", filesystemsErr)
		}
		return errors.Join(syncErr, boundErr, harvestErr, filesystemsErr)
	}
}

// finalDump dumps every container at once, against the last pre-copy round.
func (j *sourceJob) finalDump(ctx context.Context, rounds int) error {
	parent := ""
	if rounds > 0 {
		parent = strconv.Itoa(rounds)
	}
	errs := make([]error, len(j.cs))
	var wg sync.WaitGroup
	for i, c := range j.cs {
		wg.Go(func() {
			req := DumpRequest{
				ContainerID: c.id, ImageDir: j.imagesDir(c, "final"),
				WorkDir: filepath.Join(j.dumpRoot(), "containers", c.name, "work-final"),
				Kind:    FinalDump, TCP: true, FileLocks: true,
				LinkRemap: hasSharedVolume(j.m),
			}
			if parent != "" {
				req.ParentDir = j.imagesDir(c, parent)
			}
			res, err := j.dump(ctx, req)
			if err == nil && req.LinkRemap {
				err = j.relinkRemaps(c, req.ImageDir)
			}
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", c.name, err)
				return
			}
			c.stat.Rounds = append(c.stat.Rounds, v1.RoundStat{Round: int32(rounds + 1), Final: true, Pages: res.Pages, DumpMs: ms(res.Duration)})
			c.stat.TCPEstablished = countTCP(j.a.Host.Path(req.ImageDir))
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("final dump: %w", err)
	}
	return nil
}

// commitAndSend commits – from here on the controller may delete the
// source – and, in parallel, sends the rest. The data may reach the target
// before the commit: the target restores only on READY, and READY waits
// for the commit. The commit's API round trip leaves the freeze.
func (j *sourceJob) commitAndSend(ctx context.Context, f *frozen, preCopyMs int64) error {
	m := j.m
	if err := ctx.Err(); err != nil {
		return err // aborted while dumping
	}
	j.mu.Lock()
	j.committed = true
	j.mu.Unlock()
	t := time.Now()
	commitPatch := map[string]any{
		"source":     f.source,
		"containers": j.containerStats(),
		"timings":    map[string]any{"preCopyMs": preCopyMs, "freezeDumpMs": f.dumpMs},
	}
	commitErr := make(chan error, 1)
	go func() { commitErr <- j.a.commitResolved(ctx, m, commitPatch) }()
	if m.Status.IPPreserved && m.Status.Network.TargetPool != "" {
		// In parallel with the commit (handover.go): from the binding,
		// kubelet needs ≥ 0.35 s until its CNI ADD – the replacement's
		// endpoint comes after the commit. Should the commit fail (an abort
		// meanwhile), the abort deletes the replacement.
		go j.releaseReplacement(ctx)
	}
	gate := sync.OnceValue(func() error { return <-commitErr })
	sendCtx, stopSend := context.WithCancel(ctx)
	defer stopSend()
	sendStart := time.Now()
	sendErr := make(chan error, 1)
	handOver := sync.OnceValue(func() error { return j.handOverLocks(sendCtx, <-f.lockScan) })
	readyGate := func() error {
		if err := gate(); err != nil {
			return err
		}
		return handOver()
	}
	go func() { sendErr <- j.sendFinal(sendCtx, f.rounds, f.at, f.steps.add, readyGate) }()
	if err := gate(); err != nil {
		if errors.Is(err, errNotPreCopy) || errors.Is(err, errCommitNotApplied) {
			// Certainly not committed: the controller aborted meanwhile,
			// or the patch did not land.
			j.mu.Lock()
			j.committed = false
			j.mu.Unlock()
		}
		stopSend() // no READY follows a failed commit; do not delay the thaw
		<-sendErr
		return err
	}
	f.steps.since("commitMs", t)
	go j.restoreThrottles() // the source never runs again: only the record goes
	go j.a.guardNAT(m, f.natEntries, j.log)
	j.log.Info("frozen and dumped", "dumpMs", f.dumpMs, "preCopyMs", preCopyMs, "rounds", f.rounds)
	j.releaseSourceNetwork()

	if err := <-sendErr; err != nil {
		return err
	}
	f.steps.since("sendMs", sendStart)
	finalTransferMs := ms(time.Since(f.at))
	j.log.Info("transfer complete", append([]any{"sinceFreezeMs", finalTransferMs, "wireBytes", j.wire}, f.steps.list()...)...)
	return j.a.patchStatus(ctx, m, map[string]any{
		"source":     map[string]any{"transferDoneAt": now(), "message": "all data at the target"},
		"containers": j.containerStats(),
		"wireBytes":  j.wire,
		"timings":    map[string]any{"finalTransferMs": finalTransferMs},
	})
}

// resolve determines container IDs, PIDs, upperdirs and the network
// namespace.
func (j *sourceJob) resolve(ctx context.Context) error {
	pod := &corev1.Pod{}
	if err := j.a.Client.Get(ctx, types.NamespacedName{Namespace: j.m.Namespace, Name: j.m.Spec.PodName}, pod); err != nil {
		return err
	}
	if string(pod.UID) != j.m.Status.SourcePodUID {
		return fmt.Errorf("pod UID %s does not match the migration (%s)", pod.UID, j.m.Status.SourcePodUID)
	}
	j.pod = pod
	images := map[string]string{}
	for _, c := range pod.Spec.Containers {
		images[c.Name] = c.Image
	}
	// Keep the order of the spec; sidecar init containers run permanently and
	// are migrated the same way.
	var statuses []corev1.ContainerStatus
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	for _, s := range pod.Status.InitContainerStatuses {
		if s.State.Running != nil {
			statuses = append(statuses, s)
			for _, ic := range pod.Spec.InitContainers {
				if ic.Name == s.Name {
					images[s.Name] = ic.Image
				}
			}
		}
	}
	for _, s := range statuses {
		if s.State.Running == nil {
			return fmt.Errorf("container %s is not running", s.Name)
		}
		_, id, ok := strings.Cut(s.ContainerID, "://")
		if !ok || !strings.HasPrefix(s.ContainerID, "containerd://") {
			return fmt.Errorf("container %s: only containerd is supported (%s)", s.Name, s.ContainerID)
		}
		st, err := j.a.Host.State(ctx, id)
		if err != nil {
			return fmt.Errorf("runc state %s: %w", s.Name, err)
		}
		if st.Status != "running" {
			return fmt.Errorf("container %s is %s", s.Name, st.Status)
		}
		upper, err := UpperDir(st.Pid)
		if err != nil {
			return err
		}
		if sb := st.Annotations[ocispec.AnnSandboxID]; sb != "" && st.Annotations[ocispec.AnnSandboxUID] == string(pod.UID) {
			j.sandboxID = sb
		}
		c := &srcContainer{name: s.Name, id: id, image: images[s.Name], pid: st.Pid, upper: upper}
		c.rss = j.a.Host.TreeRSS(ctx, st.Pid)
		c.stat = v1.ContainerStatus{Name: c.name, SourceContainerID: id, RSSBytes: c.rss}
		j.cs = append(j.cs, c)
	}
	if len(j.cs) == 0 {
		return fmt.Errorf("no running containers")
	}
	j.netns = fmt.Sprintf("/proc/%d/ns/net", j.cs[0].pid)
	return nil
}

// checkBlockers fails while the pod holds something CRIU cannot dump:
// MPTCP sockets or io_uring instances.
func (j *sourceJob) checkBlockers(ctx context.Context) error {
	if err := j.checkMPTCP(); err != nil {
		return err
	}
	var pids []int
	for _, c := range j.cs {
		pids = append(pids, j.a.Host.CgroupPids(ctx, c.pid)...)
	}
	if h := ioUringHolders("/proc", pids); len(h) > 0 {
		return fmt.Errorf("process %s holds an io_uring instance; %s", strings.Join(h, ", "), criulog.IOUringHint)
	}
	return nil
}

// checkMPTCP fails while the pod holds MPTCP sockets: CRIU cannot dump them,
// and the final dump would fail inside the freeze. Pods started under the
// paguro runtime have MPTCP disabled in their netns; a pod started earlier
// may hold some (Go >= 1.24 listeners).
func (j *sourceJob) checkMPTCP() error {
	n, err := mptcpSockets(j.cs[0].pid)
	if err != nil {
		j.log.Info("cannot count MPTCP sockets, the final dump will tell", "err", err)
		return nil
	}
	if n > 0 {
		return fmt.Errorf("the pod holds %d Multipath TCP socket(s); %s", n, criulog.MPTCPHint)
	}
	return nil
}

func now() *metav1.MicroTime { t := metav1.NowMicro(); return &t }

func micro(t time.Time) *metav1.MicroTime { m := metav1.NewMicroTime(t); return &m }

func defaultI32(v, d int32) int32 {
	if v <= 0 {
		return d
	}
	return v
}

func defaultI64(v, d int64) int64 {
	if v <= 0 {
		return d
	}
	return v
}

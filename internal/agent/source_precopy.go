// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Source side, part 2: pre-copy rounds while the application runs, auto-
// converge, and the waits for the target before the freeze.

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "paguro.dev/paguro/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/internal/archive"
)

// throttleSteps are the throttling levels for auto-converge (percent of the
// current CPU quota).
var throttleSteps = []int{100, 70, 50, 30, 20}

// preCopyMin is the least pre-copy time limit (spec.preCopy.maxSeconds 0).
const preCopyMin = 120 * time.Second

// converging reports whether rounds shrinking like the last one (pages
// after prev) reach target pages within roundsLeft. Measured: 8 GiB
// dirtied at 50 MB/s uniformly shrank by 40 % per round – never "not
// converging" by a 20 % rule, yet far from the budget when time ran out.
func converging(pages, prev, target int64, roundsLeft int) bool {
	if pages <= target {
		return true
	}
	if pages*5 > prev*4 || roundsLeft <= 0 {
		return false // less than 20 % per round, or no round left
	}
	q := float64(pages) / float64(prev)
	need := math.Log(float64(max(target, 1))/float64(pages)) / math.Log(q)
	return need <= float64(roundsLeft)
}

// preCopy runs rounds until the estimated final dump fits into the freeze
// budget. It returns the number of rounds.
//
// Estimate: the final dump writes roughly as many pages as the app dirtied
// in the last round (given a similar round duration). Cost = fixed dump cost
// (CRIU overhead, measured as the smallest round duration per container) +
// pages × 4 KiB / throughput (measured: raw bytes per second through
// dump+compression+network).
func (j *sourceJob) preCopy(ctx context.Context) (int, error) {
	pc := j.m.Spec.PreCopy
	maxRounds := int(defaultI32(pc.MaxRounds, 8))
	threshold := defaultI64(pc.DirtyPageThreshold, 2048)
	budget := time.Duration(defaultI32(pc.FreezeBudgetMs, 500)) * time.Millisecond
	start := time.Now()
	deadline := start.Add(time.Duration(pc.MaxSeconds) * time.Second) // 0: set after the first round
	autoConverge := pc.AutoConverge == nil || *pc.AutoConverge

	// The throttle stays until the freeze (or a rollback, thaw): the extra
	// rounds while the target gets ready would otherwise dirty memory at
	// full speed again and grow the final dump.
	step := 0
	j.throttleMu.Lock()
	j.throttlePct = throttleSteps[0]
	j.throttleMu.Unlock()

	var prevPages int64 = -1
	var minOverhead time.Duration = time.Hour
	for r := 1; r <= maxRounds; r++ {
		if err := ctx.Err(); err != nil {
			return r - 1, err
		}
		rr, err := j.copyRound(ctx, r, throttleSteps[step])
		if err != nil {
			return r - 1, err
		}
		pages, raw, dumpDur, sendDur := rr.pages, rr.raw, rr.dump, rr.send
		minOverhead = min(minOverhead, rr.minDump)

		// Throughput of the whole chain (dump + send) in raw bytes per second.
		throughput := float64(raw) / (dumpDur + sendDur).Seconds()
		if throughput <= 0 {
			throughput = 100e6
		}
		estimate := minOverhead + time.Duration(float64(pages*pageSize)/throughput*float64(time.Second))
		j.log.Info("pre-copy round", "round", r, "pages", pages, "MiB", pages*pageSize>>20,
			"dumpMs", ms(dumpDur), "sendMs", ms(sendDur), "estFreezeMs", ms(estimate), "budgetMs", ms(budget),
			"throttle", throttleSteps[step])

		if r == 1 && pc.MaxSeconds <= 0 {
			deadline = start.Add(max(preCopyMin, 4*time.Since(start)))
		}
		switch {
		case estimate <= budget:
			j.log.Info("freeze budget reached", "round", r)
			return r, nil
		case pages <= threshold:
			return r, nil
		case time.Now().After(deadline):
			j.log.Warn("pre-copy time limit reached – freezing anyway", "estFreezeMs", ms(estimate))
			return r, nil
		}
		// Throttle when the rounds do not shrink fast enough to reach the
		// budget within the rounds left (round 1 copies everything, so the
		// ratio counts from round 2 on).
		budgetPages := int64(throughput * budget.Seconds() / float64(pageSize))
		if autoConverge && r >= 3 && prevPages > 0 && !converging(pages, prevPages, budgetPages, maxRounds-r) &&
			step < len(throttleSteps)-1 {
			step++
			j.throttleMu.Lock()
			for _, c := range j.cs {
				if c.throttle == nil {
					t, err := j.a.Host.NewThrottle(ctx, c.pid)
					if err == nil {
						// A restarted agent must be able to undo it.
						err = t.Persist(j.localFile(throttleFile(c.name)))
					}
					if err != nil {
						j.log.Warn("throttling not possible", "container", c.name, "err", err)
						continue
					}
					c.throttle = t
				}
				if err := c.throttle.Set(ctx, throttleSteps[step]); err != nil {
					j.log.Warn("throttling failed", "container", c.name, "err", err)
				}
			}
			j.throttlePct = throttleSteps[step]
			j.throttleMu.Unlock()
			j.log.Info("auto-converge: throttling CPU", "pct", throttleSteps[step])
		}
		prevPages = pages
	}
	return maxRounds, nil
}

// roundResult sums one pre-copy round over all containers.
type roundResult struct {
	pages, raw int64
	dump, send time.Duration
	// minDump is the shortest per-container dump (fixed CRIU overhead).
	minDump time.Duration
}

// copyRound dumps every container incrementally (parent: round r-1) and
// sends the images to the target.
func (j *sourceJob) copyRound(ctx context.Context, r, throttlePct int) (roundResult, error) {
	rr := roundResult{minDump: time.Hour}
	for _, c := range j.cs {
		req := DumpRequest{
			ContainerID: c.id, ImageDir: j.imagesDir(c, strconv.Itoa(r)),
			WorkDir: filepath.Join(j.dumpRoot(), "containers", c.name, "work-"+strconv.Itoa(r)),
			Kind:    PreDump,
		}
		if r > 1 {
			req.ParentDir = j.imagesDir(c, strconv.Itoa(r-1))
		}
		res, err := dumpRetrying(ctx, func() (DumpResult, error) { return j.dump(ctx, req) },
			func() error {
				return errors.Join(os.RemoveAll(j.a.Host.Path(req.ImageDir)), os.RemoveAll(j.a.Host.Path(req.WorkDir)))
			}, j.log.With("round", r, "container", c.name))
		if err != nil {
			return rr, fmt.Errorf("round %d, %s: %w", r, c.name, err)
		}
		st, err := j.sendDir(ctx, c, strconv.Itoa(r))
		if err != nil {
			return rr, fmt.Errorf("send round %d, %s: %w", r, c.name, err)
		}
		c.stat.Rounds = append(c.stat.Rounds, v1.RoundStat{
			Round: int32(r), Pages: res.Pages, WireBytes: st.WireBytes,
			DumpMs: ms(res.Duration), SendMs: ms(st.Duration), ThrottlePct: int32(throttlePct),
		})
		rr.pages += res.Pages
		rr.raw += st.RawBytes
		rr.dump += res.Duration
		rr.send += st.Duration
		rr.minDump = min(rr.minDump, res.Duration)
	}
	_ = j.a.patchStatus(ctx, j.m, map[string]any{"containers": j.containerStats(), "wireBytes": j.wire})
	return rr, nil
}

// A pre-copy round whose dump could not freeze the processes – one in
// uninterruptible sleep, such as NFS I/O, cannot be seized within CRIU's
// timeout – is tried again, preDumpRetries times, preDumpRetryWait apart.
// A failed pre-dump loses nothing: CRIU lets the processes run on, and the
// round starts over. Measured on EKS (GitLab, PostgreSQL on EFS): round 6
// failed with "Unseizable non-zombie … state D", and the whole migration
// rolled back after 3 min of pre-copy.
var (
	preDumpRetries   = 2
	preDumpRetryWait = 2 * time.Second
)

// dumpRetrying runs dump, again after clean when it failed to freeze.
func dumpRetrying(ctx context.Context, dump func() (DumpResult, error), clean func() error, log *slog.Logger) (DumpResult, error) {
	for attempt := 1; ; attempt++ {
		res, err := dump()
		if err == nil || attempt > preDumpRetries || !unseizable(err) {
			return res, err
		}
		log.Warn("pre-copy: CRIU could not freeze the processes (one in uninterruptible sleep?) – the round starts over",
			"attempt", attempt, "err", err)
		if cerr := clean(); cerr != nil {
			return res, errors.Join(err, cerr)
		}
		select {
		case <-ctx.Done():
			return res, err
		case <-time.After(preDumpRetryWait):
		}
	}
}

// unseizable: CRIU gave up freezing the processes.
func unseizable(err error) bool {
	var cf *criuFailure
	if !errors.As(err, &cf) {
		return false
	}
	s := cf.summary + "\n" + cf.log
	return strings.Contains(s, "Unseizable") || strings.Contains(s, "Timeout reached. Try to interrupt")
}

// targetSandboxTimeout bounds the wait for the replacement's sandbox. The
// source has not been frozen yet, so running into it rolls back cleanly.
const targetSandboxTimeout = 3 * time.Minute

// awaitTargetSandbox holds the freeze until the replacement pod's sandbox is
// up (FreezeAfterTargetSandbox): the replacement is only created now, and
// pod admission, volume setup, CNI ADD and the sandbox start then all happen
// before the freeze. Returns the last round.
func (j *sourceJob) awaitTargetSandbox(ctx context.Context, rounds int) (int, error) {
	return j.awaitTarget(ctx, rounds, targetWait{
		what:   "target sandbox is up",
		report: "pre-copy converged, waiting for the target sandbox",
		ready:  func(m *v1.Migration) bool { return m.Status.Target.SandboxReadyAt != nil },
		limit:  targetSandboxTimeout,
		timedOut: func(*v1.Migration) error {
			return fmt.Errorf("target sandbox not up within %s", targetSandboxTimeout)
		},
		poll: 20 * time.Millisecond,
	})
}

// awaitTargetAddress holds the freeze (kept IP on Cilium) until the target
// reports that the replacement's /32 is on its node (handover.go) – then the
// replacement's first sandbox attempt after the commit succeeds. Bounded:
// after addressWait it freezes anyway, and the replacement waits for the
// address after the freeze, as before. Returns the last round.
func (j *sourceJob) awaitTargetAddress(ctx context.Context, rounds int) (int, error) {
	return j.awaitTarget(ctx, rounds, targetWait{
		what:  "replacement's address is on the target",
		ready: func(m *v1.Migration) bool { return m.Status.Target.AddressReadyAt != nil },
		limit: addressWait,
		poll:  20 * time.Millisecond,
	})
}

// awaitTargetStaged holds the freeze (commit gate) until kubelet on the
// target holds the replacement right before its sandbox (dragate.go): the
// source reports that it is ready to freeze, the target agent binds the
// replacement, kubelet admits it and sets up its volumes – all of that now,
// not inside the freeze. Bounded: after stageWait the migration is aborted
// (the source keeps running) – never frozen without the replacement at the
// gate: it references its gate claim for good, and a replacement kubelet
// does not take as far as the gate might never start – after the commit
// there would be no way back. Before the freeze an abort costs nothing.
func (j *sourceJob) awaitTargetStaged(ctx context.Context, rounds int) (int, error) {
	return j.awaitTarget(ctx, rounds, targetWait{
		what:   "replacement held at the commit gate",
		report: "pre-copy converged, waiting for the replacement at the commit gate",
		ready:  func(m *v1.Migration) bool { return m.Status.Target.SandboxStagedAt != nil },
		limit:  stageWait,
		timedOut: func(m *v1.Migration) error {
			return fmt.Errorf("the replacement did not reach the commit gate within %s (target agent: %q)", stageWait, m.Status.Target.Message)
		},
		poll: 10 * time.Millisecond,
	})
}

// targetWait is one condition the freeze waits for (awaitTarget).
type targetWait struct {
	what string // logged when it is met
	// report, if set, is reported with status.source.readyToFreezeAt before
	// the wait: the target acts on it.
	report string
	ready  func(*v1.Migration) bool
	limit  time.Duration
	// timedOut builds the error that aborts after limit; nil: freeze anyway.
	timedOut func(*v1.Migration) error
	// poll: how often the agent's cache is asked – each poll interval can
	// end up in the freeze's lead time, so it is short.
	poll time.Duration
}

// extraRoundEvery: while the source waits for the target it keeps copying,
// so that the final dump does not grow with the wait.
const extraRoundEvery = time.Second

// awaitTarget waits for w, copying a round about every second meanwhile,
// and returns the last round.
func (j *sourceJob) awaitTarget(ctx context.Context, rounds int, w targetWait) (int, error) {
	start := time.Now()
	if w.report != "" {
		if err := j.a.patchStatus(ctx, j.m, map[string]any{"source": map[string]any{
			"readyToFreezeAt": now(), "message": w.report,
		}}); err != nil {
			return rounds, err
		}
	}
	key := client.ObjectKeyFromObject(j.m)
	extra := 0
	lastRound := time.Now()
	for {
		m := &v1.Migration{}
		if err := j.a.Client.Get(ctx, key, m); err != nil {
			return rounds, err
		}
		if w.ready(m) {
			if extra > 0 || time.Since(start) > 50*time.Millisecond {
				j.log.Info(w.what+" – freezing", "waitMs", ms(time.Since(start)), "extraRounds", extra)
			}
			return rounds, nil
		}
		if time.Since(start) > w.limit {
			if w.timedOut != nil {
				return rounds, w.timedOut(m)
			}
			j.log.Warn("not yet: "+w.what+" – freezing anyway", "waitMs", ms(time.Since(start)))
			return rounds, nil
		}
		if rounds > 0 && time.Since(lastRound) >= extraRoundEvery {
			if _, err := j.copyRound(ctx, rounds+1, j.currentThrottle()); err != nil {
				return rounds, err
			}
			rounds++
			extra++
			lastRound = time.Now()
			continue
		}
		select {
		case <-ctx.Done():
			return rounds, ctx.Err()
		case <-time.After(w.poll):
		}
	}
}

// stageWait bounds awaitTargetStaged.
const stageWait = 20 * time.Second

// addressWait bounds awaitTargetAddress.
const addressWait = 10 * time.Second

// awaitCompaction waits for the target to apply every container's rounds.
func (j *sourceJob) awaitCompaction(ctx context.Context) error {
	errs := make([]error, len(j.cs))
	var wg sync.WaitGroup
	for i, c := range j.cs {
		wg.Go(func() { errs[i] = j.client.AwaitCompaction(ctx, string(j.m.UID), c.name) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// currentThrottle is the CPU share the containers have now (100: full).
func (j *sourceJob) currentThrottle() int {
	j.throttleMu.Lock()
	defer j.throttleMu.Unlock()
	return j.throttlePct
}

// restoreThrottles gives the containers their CPU back (rollback) or
// just forgets the throttle (after the commit the source never runs again).
func (j *sourceJob) restoreThrottles() {
	j.throttleMu.Lock()
	defer j.throttleMu.Unlock()
	for _, c := range j.cs {
		if c.throttle != nil && c.throttle.Restore(context.Background()) == nil {
			_ = os.Remove(j.localFile(throttleFile(c.name)))
			c.throttle = nil
		}
	}
	j.throttlePct = throttleSteps[0]
}

func (j *sourceJob) sendDir(ctx context.Context, c *srcContainer, round string) (SendStats, error) {
	dir := j.a.Host.Path(j.imagesDir(c, round))
	st, err := j.client.Send(ctx, "PUT", fmt.Sprintf("/v1/m/%s/c/%s/images/%s", j.m.UID, c.name, round), func(w io.Writer) error {
		_, err := archive.Pack(w, dir, archive.PackOptions{})
		return err
	})
	j.mu.Lock()
	j.wire += st.WireBytes
	j.mu.Unlock()
	return st, err
}

// injectFault fails the migration at a named point for failure tests
// (annotation paguro.dev/test-fault on the Migration), only on agents
// started with --test-faults. "after-pause" fails once the source is
// paused – after the early hand-over has reached the target and its
// sandbox had time to take the address – so the rollback path is
// exercised with the address already moved.
func (j *sourceJob) injectFault(ctx context.Context, point string, handOver chan time.Time) error {
	if !j.a.TestFaults || j.m.Annotations[v1.AnnotationTestFault] != point {
		return nil
	}
	if handOver != nil {
		select {
		case t := <-handOver:
			handOver <- t
		case <-time.After(2 * time.Second):
		}
		select {
		case <-ctx.Done():
		case <-time.After(1500 * time.Millisecond):
		}
	}
	return fmt.Errorf("injected fault %q (%s)", point, v1.AnnotationTestFault)
}

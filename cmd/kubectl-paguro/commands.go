// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/placement"
)

// migrateFlags are the options of a migration (migrate and drain).
type migrateFlags struct {
	to, strategy, network, cpuPolicy string
	freezeBudget, timeout            time.Duration
	noAutoConverge                   bool
}

func (f *migrateFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.to, "to", "", "target node (default: controller picks the best node)")
	fs.StringVar(&f.strategy, "strategy", "PreCopy", "PreCopy | StopAndCopy")
	fs.StringVar(&f.network, "network", "Auto", "Auto | Preserve | Phantom (new IP, in-cluster connections kept) | Generic (new IP, connections closed)")
	fs.StringVar(&f.cpuPolicy, "cpu-policy", "Strict", "Strict | Ignore")
	fs.DurationVar(&f.freezeBudget, "freeze-budget", 500*time.Millisecond, "target freeze time; pre-copy continues until the rest fits")
	fs.BoolVar(&f.noAutoConverge, "no-auto-converge", false, "do not throttle the app's CPU to make pre-copy converge")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Minute, "overall timeout (rollback if not frozen by then)")
}

func oneOf(name, v string, allowed ...string) error {
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return nil
		}
	}
	return fmt.Errorf("--%s must be one of %s, got %q", name, strings.Join(allowed, "|"), v)
}

func canonical(v string, allowed ...string) string {
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return a
		}
	}
	return v
}

func (f *migrateFlags) spec(pod string) (v1alpha1.MigrationSpec, error) {
	// The same reading as the webhook's and preflight's (any case).
	network, netErr := v1alpha1.ParseNetworkMode(f.network)
	if netErr != nil {
		netErr = fmt.Errorf("--network: %w", netErr)
	}
	for _, chk := range []error{
		oneOf("strategy", f.strategy, "PreCopy", "StopAndCopy"),
		netErr,
		oneOf("cpu-policy", f.cpuPolicy, "Strict", "Ignore"),
	} {
		if chk != nil {
			return v1alpha1.MigrationSpec{}, chk
		}
	}
	if f.freezeBudget <= 0 || f.freezeBudget > time.Minute {
		return v1alpha1.MigrationSpec{}, fmt.Errorf("--freeze-budget must be between 1ms and 1m")
	}
	return v1alpha1.MigrationSpec{
		PodName:    pod,
		TargetNode: f.to,
		Strategy:   v1alpha1.Strategy(canonical(f.strategy, "PreCopy", "StopAndCopy")),
		Network:    network,
		CPUPolicy:  v1alpha1.CPUPolicy(canonical(f.cpuPolicy, "Strict", "Ignore")),
		PreCopy: v1alpha1.PreCopySpec{
			FreezeBudgetMs: int32(f.freezeBudget.Milliseconds()),
			AutoConverge:   ptr.To(!f.noAutoConverge),
		},
		TimeoutSeconds: int32(f.timeout.Seconds()),
	}, nil
}

// migrationName: <pod>-<5 random characters>, at most 63 characters.
func migrationName(pod string) string {
	const alphabet = "bcdfghjklmnpqrstvwxz2456789"
	suffix := make([]byte, 5)
	for i := range suffix {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		suffix[i] = alphabet[n.Int64()]
	}
	if len(pod) > 57 {
		pod = strings.TrimRight(pod[:57], "-.")
	}
	return pod + "-" + string(suffix)
}

func createMigration(ctx context.Context, c client.Client, ns string, spec v1alpha1.MigrationSpec) (*v1alpha1.Migration, error) {
	m := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{
			Name: migrationName(spec.PodName), Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/created-by": "kubectl-paguro"},
		},
		Spec: spec,
	}
	if err := c.Create(ctx, m); err != nil {
		return nil, fmt.Errorf("creating migration for pod %s/%s: %w", ns, spec.PodName, err)
	}
	return m, nil
}

func cmdMigrate(ctx context.Context, args []string) error {
	var g globals
	var mf migrateFlags
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	g.register(fs)
	mf.register(fs)
	wait := fs.Bool("wait", false, "follow the migration with a live progress view")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: kubectl paguro migrate <pod> [flags]")
	}
	pod := strings.TrimPrefix(pos[0], "pod/")
	spec, err := mf.spec(pod)
	if err != nil {
		return err
	}
	c, ns, err := g.connect()
	if err != nil {
		return err
	}
	m, err := createMigration(ctx, c, ns, spec)
	if err != nil {
		return err
	}
	fmt.Printf("migration %s created\n", paint(m.Namespace+"/"+m.Name, sBold))
	if !*wait {
		fmt.Printf("follow with: kubectl paguro describe %s -n %s\n", m.Name, m.Namespace)
		return nil
	}
	final, err := follow(ctx, c, client.ObjectKeyFromObject(m))
	if err != nil {
		return err
	}
	if final.Status.Phase != v1alpha1.PhaseSucceeded {
		return exitError(1)
	}
	return nil
}

// follow shows progress live (terminal) or line by line (pipe) until the
// migration reaches a terminal state.
func follow(ctx context.Context, c client.Client, key client.ObjectKey) (*v1alpha1.Migration, error) {
	obs := observed{}
	tty := isTerminal(os.Stdout)
	prevLines := 0
	var lastPhase v1alpha1.Phase
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		var m v1alpha1.Migration
		if err := c.Get(ctx, key, &m); err != nil {
			if ctx.Err() != nil {
				fmt.Printf("\nstopped following; the migration continues: kubectl paguro describe %s -n %s\n", key.Name, key.Namespace)
				return nil, exitError(130)
			}
			return nil, err
		}
		now := time.Now()
		if _, seen := obs[m.Status.Phase]; !seen {
			obs[m.Status.Phase] = now
		}

		if tty {
			frame := append(renderHeader(&m), "")
			frame = append(frame, renderTimeline(&m, obs, now)...)
			if r := renderRounds(&m); len(r) > 0 {
				frame = append(append(frame, "", paint("Pre-copy rounds", sBold)), r...)
			}
			if prevLines > 0 {
				fmt.Printf("\x1b[%dF\x1b[J", prevLines)
			}
			printLines(frame)
			prevLines = len(frame)
		} else if m.Status.Phase != lastPhase {
			fmt.Printf("%s  %-12s %s\n", now.Format("15:04:05.000"), m.Status.Phase, m.Status.Message)
		}
		lastPhase = m.Status.Phase

		if m.Status.Phase.Terminal() {
			fmt.Println()
			printLines(renderSummary(&m))
			return &m, nil
		}
		select {
		case <-ctx.Done():
			fmt.Printf("\nstopped following; the migration continues: kubectl paguro describe %s -n %s\n", key.Name, key.Namespace)
			return nil, exitError(130)
		case <-tick.C:
		}
	}
}

func phaseColor(p v1alpha1.Phase) string {
	switch p {
	case v1alpha1.PhaseSucceeded:
		return paint(string(p), sGreen)
	case v1alpha1.PhaseFailed:
		return paint(string(p), sRed, sBold)
	case v1alpha1.PhaseAborting, v1alpha1.PhaseRolledBack:
		return paint(string(p), sYellow)
	case "":
		return paint("Pending", sDim)
	default:
		return paint(string(p), sCyan)
	}
}

func freezeCell(m *v1alpha1.Migration) string {
	if m.Status.Timings.FreezeMs <= 0 {
		return paint("–", sDim)
	}
	badge, _ := freezeStyles(m.Status.Timings.FreezeMs, freezeBudget(m))
	return paint(" "+fmtMs(m.Status.Timings.FreezeMs)+" ", badge)
}

func cmdList(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	g.register(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	c, ns, err := g.connect()
	if err != nil {
		return err
	}
	var opts []client.ListOption
	if !g.allNamespaces {
		opts = append(opts, client.InNamespace(ns))
	}
	var list v1alpha1.MigrationList
	if err := c.List(ctx, &list, opts...); err != nil {
		return err
	}
	if len(list.Items) == 0 {
		fmt.Println("no migrations found")
		return nil
	}
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[j].CreationTimestamp.Before(&list.Items[i].CreationTimestamp)
	})
	header := []string{"NAME", ">FREEZE", "PHASE", "POD", "FROM → TO", "IP", ">WIRE", ">AGE"}
	if g.allNamespaces {
		header = append([]string{"NAMESPACE"}, header...)
	}
	var rows [][]string
	for i := range list.Items {
		m := &list.Items[i]
		ip := paint("new", sDim)
		if m.Status.IPPreserved {
			ip = paint("kept", sGreen)
		}
		row := []string{
			m.Name, freezeCell(m), phaseColor(m.Status.Phase), m.Spec.PodName,
			orDash(m.Status.SourceNode) + " → " + orDash(firstNonEmpty(m.Status.TargetNode, m.Spec.TargetNode)),
			ip, fmtBytes(m.Status.WireBytes), duration.HumanDuration(time.Since(m.CreationTimestamp.Time)),
		}
		if g.allNamespaces {
			row = append([]string{m.Namespace}, row...)
		}
		rows = append(rows, row)
	}
	printLines(table(header, rows))
	return nil
}

func cmdDescribe(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("describe", flag.ContinueOnError)
	g.register(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: kubectl paguro describe <migration>")
	}
	c, ns, err := g.connect()
	if err != nil {
		return err
	}
	var m v1alpha1.Migration
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: pos[0]}, &m); err != nil {
		return err
	}
	st := &m.Status
	out := renderHeader(&m)
	if st.Phase.Terminal() && st.Timings.FreezeMs > 0 {
		out = append(out, "", "  "+freezeCell(&m)+paint("  freeze", sBold)+
			paint(fmt.Sprintf("  (freeze budget %s)", fmtMs(int64(freezeBudget(&m)))), sDim))
	}
	out = append(out, "", paint("Phases", sBold))
	out = append(out, renderTimeline(&m, observed{}, time.Now())...)

	if r := renderRounds(&m); len(r) > 0 {
		out = append(append(out, "", paint("Pre-copy rounds", sBold)), r...)
	}
	if st.Timings != (v1alpha1.Timings{}) {
		out = append(append(out, "", paint("Timing breakdown", sBold)+paint("  (❄ = workload frozen)", sDim)), renderTimingBars(&m)...)
	}
	out = append(out, renderVolumes(st)...)
	out = append(out, renderTargetContainers(st)...)
	out = append(out, renderDetails(&m)...)
	out = append(out, renderEvents(ctx, c, ns, &m)...)
	printLines(out)
	return nil
}

func renderVolumes(st *v1alpha1.MigrationStatus) []string {
	if len(st.Volumes) == 0 {
		return nil
	}
	var rows [][]string
	for _, v := range st.Volumes {
		rows = append(rows, []string{v.Name, v.Kind, orDash(v.ClaimName), stamp(v.DetachedAt), stamp(v.AttachedAt)})
	}
	out := []string{"", paint("Volumes", sBold)}
	for _, l := range table([]string{"NAME", "KIND", "CLAIM", "DETACHED", "ATTACHED"}, rows) {
		out = append(out, "  "+l)
	}
	return out
}

func renderTargetContainers(st *v1alpha1.MigrationStatus) []string {
	if len(st.Target.Containers) == 0 {
		return nil
	}
	var rows [][]string
	for _, c := range st.Target.Containers {
		res := paint("restored", sGreen)
		if c.ColdStartReason != "" {
			res = paint("cold start: "+c.ColdStartReason, sYellow)
		}
		rows = append(rows, []string{c.Name, res, fmtMs(c.RestoreMs)})
	}
	out := []string{"", paint("Target containers", sBold)}
	for _, l := range table([]string{"NAME", "RESULT", ">RESTORE"}, rows) {
		out = append(out, "  "+l)
	}
	return out
}

func renderDetails(m *v1alpha1.Migration) []string {
	st := &m.Status
	out := []string{"", paint("Details", sBold),
		"  " + kv("Phase", phaseColor(st.Phase)+"  "+st.Message),
		"  " + kv("Owner", orDash(strings.Trim(st.OwnerKind+"/"+st.OwnerName, "/"))),
		"  " + kv("Source pod", fmt.Sprintf("%s  uid %s  ip %s", m.Spec.PodName, orDash(st.SourcePodUID), orDash(st.SourcePodIP))),
		"  " + kv("Target pod", fmt.Sprintf("%s  ip %s", orDash(st.TargetPodName), orDash(st.TargetPodIP))),
		"  " + kv("Bytes on wire", fmtBytes(st.WireBytes))}
	if nw := st.Network; nw.TargetPool != "" {
		rotated := paint("pending (rotated at cutover)", sDim)
		if nw.PoolRotatedAt != nil {
			rotated = "rotated " + stamp(nw.PoolRotatedAt)
		}
		out = append(out, "  "+kv("Sticky pool", fmt.Sprintf("%s → %s  %s", orDash(nw.SourcePool), nw.TargetPool, rotated)))
	}
	if st.Source.Error != "" {
		out = append(out, "  "+kv("Source error", paint(st.Source.Error, sRed)))
	}
	if st.Target.Error != "" {
		out = append(out, "  "+kv("Target error", paint(st.Target.Error, sRed)))
	}
	for _, w := range st.Warnings {
		out = append(out, "  "+paint("⚠ "+w, sYellow))
	}
	for _, cond := range st.Conditions {
		out = append(out, "  "+kv("Condition", fmt.Sprintf("%s=%s (%s) %s", cond.Type, cond.Status, cond.Reason, cond.Message)))
	}
	return out
}

// renderEvents lists the migration's events, oldest first (none if the
// events cannot be read).
func renderEvents(ctx context.Context, c client.Client, ns string, m *v1alpha1.Migration) []string {
	var evs corev1.EventList
	if err := c.List(ctx, &evs, client.InNamespace(ns), client.MatchingFields{"involvedObject.uid": string(m.UID)}); err != nil || len(evs.Items) == 0 {
		return nil
	}
	sort.Slice(evs.Items, func(i, j int) bool { return eventTime(&evs.Items[i]).Before(eventTime(&evs.Items[j])) })
	var rows [][]string
	for _, e := range evs.Items {
		typ := e.Type
		if typ == corev1.EventTypeWarning {
			typ = paint(typ, sYellow)
		}
		rows = append(rows, []string{eventTime(&e).Local().Format("15:04:05.000"), typ, e.Reason, e.Message})
	}
	out := []string{"", paint("Events", sBold)}
	for _, l := range table([]string{"TIME", "TYPE", "REASON", "MESSAGE"}, rows) {
		out = append(out, "  "+l)
	}
	return out
}

func eventTime(e *corev1.Event) time.Time {
	switch {
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	default:
		return e.CreationTimestamp.Time
	}
}

func stamp(t *metav1.MicroTime) string {
	if t == nil {
		return "–"
	}
	return t.Local().Format("15:04:05.000")
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func cmdDrain(ctx context.Context, args []string) error {
	var g globals
	var mf migrateFlags
	fs := flag.NewFlagSet("drain", flag.ContinueOnError)
	g.register(fs)
	mf.register(fs)
	selector := fs.String("selector", "", "additional label selector for pods")
	parallel := fs.Int("parallel", 1, "number of concurrent migrations")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: kubectl paguro drain <node> [--selector k=v] [--parallel N]")
	}
	node := pos[0]
	if *parallel < 1 {
		return fmt.Errorf("--parallel must be >= 1")
	}
	sel, err := labels.Parse(strings.Trim(v1alpha1.LabelMigratable+"=true,"+*selector, ","))
	if err != nil {
		return fmt.Errorf("--selector: %w", err)
	}
	c, _, err := g.connect()
	if err != nil {
		return err
	}
	todo, err := drainablePods(ctx, c, node, sel, g.namespace)
	if err != nil {
		return err
	}
	if len(todo) == 0 {
		fmt.Printf("no running migratable pods (%s) on node %s\n", sel, node)
		return nil
	}
	fmt.Printf("draining %s: %d pod(s), %d at a time\n", paint(node, sBold), len(todo), *parallel)
	return reportDrain(node, drainAll(ctx, c, todo, *parallel, mf))
}

// drainablePods lists the running pods on node that match sel.
func drainablePods(ctx context.Context, c client.Client, node string, sel labels.Selector, namespace string) ([]corev1.Pod, error) {
	opts := []client.ListOption{client.MatchingLabelsSelector{Selector: sel}, client.MatchingFields{"spec.nodeName": node}}
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	var pods corev1.PodList
	if err := c.List(ctx, &pods, opts...); err != nil {
		return nil, err
	}
	var todo []corev1.Pod
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp.IsZero() {
			todo = append(todo, p)
		}
	}
	return todo, nil
}

// drainResult is one pod's outcome of a drain.
type drainResult struct {
	pod string
	m   *v1alpha1.Migration
	err error
}

// drainAll migrates the pods, parallel at a time, logging as they go.
func drainAll(ctx context.Context, c client.Client, todo []corev1.Pod, parallel int, mf migrateFlags) []drainResult {
	results := make([]drainResult, len(todo))
	var mu sync.Mutex
	logf := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Printf("%s  "+format+"\n", append([]any{time.Now().Format("15:04:05.000")}, a...)...)
	}
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i := range todo {
		p := todo[i]
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = drainResult{pod: p.Namespace + "/" + p.Name, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			m, err := drainOne(ctx, c, &p, mf, logf)
			results[i] = drainResult{pod: p.Namespace + "/" + p.Name, m: m, err: err}
		})
	}
	wg.Wait()
	return results
}

// reportDrain prints the drain's table; an error if any migration did not
// succeed.
func reportDrain(node string, results []drainResult) error {
	var rows [][]string
	failed := 0
	for _, r := range results {
		if r.err != nil || r.m == nil {
			failed++
			rows = append(rows, []string{r.pod, "–", paint("error", sRed), "–", "–", fmt.Sprint(r.err)})
			continue
		}
		ip := paint("new", sDim)
		if r.m.Status.IPPreserved {
			ip = paint("kept", sGreen)
		}
		if r.m.Status.Phase != v1alpha1.PhaseSucceeded {
			failed++
		}
		rows = append(rows, []string{r.pod, freezeCell(r.m), phaseColor(r.m.Status.Phase),
			orDash(r.m.Status.TargetNode), ip, r.m.Status.Message})
	}
	fmt.Println()
	printLines(table([]string{"POD", ">FREEZE", "RESULT", "TARGET", "IP", "MESSAGE"}, rows))
	if failed > 0 {
		fmt.Printf("\n%s %d of %d migrations did not succeed\n", paint("✗", sRed), failed, len(results))
		return exitError(1)
	}
	fmt.Printf("\n%s node %s drained\n", paint("✓", sGreen), node)
	return nil
}

// drainOne migrates a pod and waits for the result.
func drainOne(ctx context.Context, c client.Client, p *corev1.Pod, mf migrateFlags, logf func(string, ...any)) (*v1alpha1.Migration, error) {
	spec, err := mf.spec(p.Name)
	if err != nil {
		return nil, err
	}
	m, err := createMigration(ctx, c, p.Namespace, spec)
	if err != nil {
		return nil, err
	}
	who := paint(p.Namespace+"/"+p.Name, sBold)
	logf("%s  migration %s created", who, m.Name)
	var last v1alpha1.Phase
	for {
		if err := c.Get(ctx, client.ObjectKeyFromObject(m), m); err != nil {
			return nil, err
		}
		if m.Status.Phase != last {
			extra := ""
			if m.Status.Phase == v1alpha1.PhaseSucceeded {
				extra = " freeze " + freezeCell(m)
			}
			logf("%s  %s%s", who, phaseColor(m.Status.Phase), extra)
			last = m.Status.Phase
		}
		if m.Status.Phase.Terminal() {
			return m, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func cmdNodes(ctx context.Context, args []string) error {
	var g globals
	fs := flag.NewFlagSet("nodes", flag.ContinueOnError)
	g.register(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	c, _, err := g.connect()
	if err != nil {
		return err
	}
	var nodes corev1.NodeList
	if err := c.List(ctx, &nodes); err != nil {
		return err
	}
	sort.Slice(nodes.Items, func(i, j int) bool { return nodes.Items[i].Name < nodes.Items[j].Name })
	var rows [][]string
	for _, n := range nodes.Items {
		a := n.Annotations
		agent := paint("no agent", sRed)
		if e := a[v1alpha1.AnnotationNodeAgent]; e != "" {
			agent = paint(e, sGreen)
		}
		if a[v1alpha1.AnnotationNodeAgentDraining] != "" {
			agent = paint("draining", sYellow)
		}
		flags := len(placement.ParseCPUFlags(a[v1alpha1.AnnotationNodeCPUFlags]))
		rows = append(rows, []string{n.Name, agent, orDash(a[v1alpha1.AnnotationNodeAgentVersion]), orDash(a[v1alpha1.AnnotationNodeCRIU]),
			orDash(a[v1alpha1.AnnotationNodeCPUModel]), fmt.Sprint(flags)})
	}
	printLines(table([]string{"NODE", "AGENT", "RELEASE", "CRIU", "CPU MODEL", ">CPU FLAGS"}, rows))

	// Matrix: can a pod migrate from row (source) to column (target)?
	fmt.Println()
	fmt.Println(paint("CPU compatibility", sBold) + paint("  (row = source, column = target; ✓ = target has all source CPU features)", sDim))
	header := []string{"from \\ to"}
	for i := range nodes.Items {
		header = append(header, fmt.Sprintf("[%d]", i+1))
	}
	var mrows [][]string
	for i, src := range nodes.Items {
		row := []string{fmt.Sprintf("[%d] %s", i+1, src.Name)}
		for j, dst := range nodes.Items {
			cell := ""
			switch {
			case i == j:
				cell = paint("·", sDim)
			case dst.Annotations[v1alpha1.AnnotationNodeAgent] == "" || src.Annotations[v1alpha1.AnnotationNodeAgent] == "":
				cell = paint("?", sDim)
			default:
				missing := placement.MissingCPUFlags(src.Annotations[v1alpha1.AnnotationNodeCPUFlags], dst.Annotations[v1alpha1.AnnotationNodeCPUFlags])
				if len(missing) == 0 {
					cell = paint("✓", sGreen)
				} else {
					cell = paint(fmt.Sprintf("✗%d", len(missing)), sRed)
				}
			}
			row = append(row, cell)
		}
		mrows = append(mrows, row)
	}
	for _, l := range table(header, mrows) {
		fmt.Println("  " + l)
	}
	fmt.Println(paint("  ✗N = N CPU features missing on target (cpuPolicy=Ignore allows it with SIGILL risk) · ? = no paguro agent", sDim))
	return nil
}

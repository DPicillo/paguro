// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"fmt"
	"strings"
	"time"

	"paguro.dev/paguro/api/v1alpha1"
)

var successPath = []v1alpha1.Phase{
	v1alpha1.PhasePending, v1alpha1.PhasePreflight, v1alpha1.PhasePreCopy, v1alpha1.PhaseFrozen,
	v1alpha1.PhaseCuttingOver, v1alpha1.PhaseRestoring, v1alpha1.PhaseSucceeded,
}

// observed records when the CLI first saw a phase
// (fallback when the status has no timestamp for it).
type observed map[v1alpha1.Phase]time.Time

// phaseTime returns the time a phase was entered, taken from the status.
func phaseTime(m *v1alpha1.Migration, p v1alpha1.Phase, obs observed) (time.Time, bool) {
	st := &m.Status
	switch p {
	case v1alpha1.PhasePending:
		return m.CreationTimestamp.Time, !m.CreationTimestamp.IsZero()
	case v1alpha1.PhasePreflight:
		if st.StartedAt != nil {
			return st.StartedAt.Time, true
		}
	case v1alpha1.PhasePreCopy:
		if st.StartedAt != nil && st.TargetNode != "" {
			return st.StartedAt.Add(time.Duration(st.Timings.PreflightMs) * time.Millisecond), true
		}
	case v1alpha1.PhaseFrozen:
		if st.Source.FrozenAt != nil {
			return st.Source.FrozenAt.Time, true
		}
	case v1alpha1.PhaseCuttingOver:
		if st.Cutover.SourceDeletedAt != nil {
			return st.Cutover.SourceDeletedAt.Time, true
		}
	case v1alpha1.PhaseRestoring:
		// early: the warm target exists before the freeze; Restoring starts
		// right after the source deletion.
		if st.Cutover.Mode == v1alpha1.CutoverEarly && st.Cutover.SourceDeletedAt != nil {
			return st.Cutover.SourceDeletedAt.Time, true
		}
		if st.Cutover.TargetPodCreatedAt != nil {
			return st.Cutover.TargetPodCreatedAt.Time, true
		}
	case v1alpha1.PhaseSucceeded, v1alpha1.PhaseFailed, v1alpha1.PhaseRolledBack:
		if st.CompletedAt != nil && st.Phase == p {
			return st.CompletedAt.Time, true
		}
	}
	if p == st.Phase && st.PhaseChangedAt != nil {
		return st.PhaseChangedAt.Time, true
	}
	t, ok := obs[p]
	return t, ok
}

// renderHeader: who, from where to where, how.
func renderHeader(m *v1alpha1.Migration) []string {
	st := &m.Status
	from, to := orDash(st.SourceNode), orDash(st.TargetNode)
	if to == "–" && m.Spec.TargetNode != "" {
		to = m.Spec.TargetNode
	}
	net := orDash(st.NetworkAdapter)
	if st.NetworkAdapter != "" {
		if st.IPPreserved {
			net += " · " + paint("IP kept", sGreen)
		} else {
			net += " · " + paint("new IP", sYellow)
		}
	}
	return []string{
		paint("paguro", sBold, sCyan) + "  " + paint(m.Namespace+"/"+m.Spec.PodName, sBold) +
			"   " + from + paint(" ──▶ ", sCyan) + to + "   " + paint(m.Name, sDim),
		paint(fmt.Sprintf("strategy %s · network %s · cutover %s · freeze budget %s · cpu %s",
			orDash(string(m.Spec.Strategy)), net, orDash(m.Status.Cutover.Mode), fmtMs(int64(freezeBudget(m))),
			orDash(string(m.Spec.CPUPolicy))), sDim),
	}
}

func freezeBudget(m *v1alpha1.Migration) int32 {
	if m.Spec.PreCopy.FreezeBudgetMs > 0 {
		return m.Spec.PreCopy.FreezeBudgetMs
	}
	return 500
}

// renderTimeline: one line per phase with timestamp and detail.
func renderTimeline(m *v1alpha1.Migration, obs observed, now time.Time) []string {
	st := &m.Status
	cur := st.Phase
	if cur == "" {
		cur = v1alpha1.PhasePending
	}
	steps := successPath
	switch cur {
	case v1alpha1.PhaseAborting, v1alpha1.PhaseRolledBack:
		steps = append(reachedPrefix(m, obs), v1alpha1.PhaseAborting)
		if cur == v1alpha1.PhaseRolledBack {
			steps = append(steps, v1alpha1.PhaseRolledBack)
		}
	case v1alpha1.PhaseFailed:
		steps = append(reachedPrefix(m, obs), v1alpha1.PhaseFailed)
	}
	start, hasStart := phaseTime(m, v1alpha1.PhasePending, obs)
	curIdx := indexOf(steps, cur)

	var out []string
	for i, p := range steps {
		icon, name := paint("○", sDim), paint(padRight(string(p), 12), sDim)
		switch {
		case p == v1alpha1.PhaseFailed:
			icon, name = paint("✗", sRed, sBold), paint(padRight(string(p), 12), sRed, sBold)
		case p == v1alpha1.PhaseRolledBack || p == v1alpha1.PhaseAborting:
			icon, name = paint("↺", sYellow), paint(padRight(string(p), 12), sYellow)
			if p == cur && !cur.Terminal() {
				icon = paint("●", sYellow, sBold)
			}
		case i < curIdx || (i == curIdx && cur.Terminal()):
			icon, name = paint("✓", sGreen), padRight(string(p), 12)
		case i == curIdx:
			icon, name = paint("●", sCyan, sBold), paint(padRight(string(p), 12), sBold)
		}
		stamp, delta := "", ""
		if t, ok := phaseTime(m, p, obs); ok && (i <= curIdx) {
			stamp = t.Local().Format("15:04:05.000")
			if hasStart {
				delta = "+" + fmtDur(t.Sub(start))
			}
		}
		line := fmt.Sprintf("  %s %s %s  %s", icon, name, padRight(paint(stamp, sDim), 12), padLeft(paint(delta, sDim), 9))
		if d := phaseDetail(m, p, i == curIdx && !cur.Terminal(), now); d != "" {
			line += "   " + d
		}
		out = append(out, strings.TrimRight(line, " "))
	}
	return out
}

// reachedPrefix: phases of the success path that were demonstrably reached.
func reachedPrefix(m *v1alpha1.Migration, obs observed) []v1alpha1.Phase {
	var out []v1alpha1.Phase
	for _, p := range successPath[:len(successPath)-1] {
		if _, ok := phaseTime(m, p, obs); !ok && p != v1alpha1.PhasePending {
			break
		}
		out = append(out, p)
	}
	return out
}

func phaseDetail(m *v1alpha1.Migration, p v1alpha1.Phase, active bool, now time.Time) string {
	st := &m.Status
	switch p {
	case v1alpha1.PhasePreflight:
		if st.TargetNode != "" {
			return paint("target "+st.TargetNode, sDim)
		}
	case v1alpha1.PhasePreCopy:
		rounds, bytes := 0, int64(0)
		for _, c := range st.Containers {
			for _, r := range c.Rounds {
				if !r.Final {
					rounds = max(rounds, int(r.Round))
					bytes += r.WireBytes
				}
			}
		}
		warm := ""
		if st.Cutover.Mode == v1alpha1.CutoverEarly && st.TargetPodName != "" {
			state := "requested"
			if st.TargetPodUID != "" {
				state = "waiting"
			}
			warm = paint(" · warm target "+st.TargetPodName+" "+state, sDim)
		}
		switch {
		case active && !st.Target.Ready:
			return paint("target pulling images …", sDim) + warm
		case rounds > 0:
			return paint(fmt.Sprintf("%d rounds · %s", rounds, fmtBytes(bytes)), sDim) + warm
		case active:
			return paint("waiting for source agent …", sDim) + warm
		}
	case v1alpha1.PhaseFrozen:
		if st.Timings.FreezeDumpMs > 0 {
			return paint("❄ final dump "+fmtMs(st.Timings.FreezeDumpMs), sCyan)
		}
		if st.Source.FrozenAt != nil {
			return paint("❄ app frozen", sCyan)
		}
	case v1alpha1.PhaseCuttingOver:
		if st.Cutover.Mode == v1alpha1.CutoverEarly && st.Cutover.SourceDeletedAt != nil {
			return paint("source deleted, warm target takes over", sDim)
		}
		if st.Timings.CutoverMs > 0 {
			return paint("replacement after "+fmtMs(st.Timings.CutoverMs), sDim)
		}
	case v1alpha1.PhaseRestoring:
		if st.Timings.RestoreMs > 0 {
			return paint("restore "+fmtMs(st.Timings.RestoreMs), sDim)
		}
		if active && st.Source.FrozenAt != nil {
			// Show the ongoing freeze live.
			return paint("frozen for "+fmtDur(now.Sub(st.Source.FrozenAt.Time)), sYellow)
		}
	case v1alpha1.PhaseSucceeded, v1alpha1.PhaseFailed, v1alpha1.PhaseRolledBack, v1alpha1.PhaseAborting:
		if st.Phase == p {
			return st.Message
		}
	}
	return ""
}

// renderRounds: table of pre-copy rounds per container.
func renderRounds(m *v1alpha1.Migration) []string {
	var out []string
	for _, c := range m.Status.Containers {
		if len(c.Rounds) == 0 {
			continue
		}
		var rows [][]string
		for _, r := range c.Rounds {
			label := fmt.Sprint(r.Round)
			if r.Final {
				label = paint("final ❄", sCyan)
			}
			throttle := "–"
			if r.ThrottlePct > 0 {
				throttle = paint(fmt.Sprintf("%d%%", r.ThrottlePct), sYellow)
			}
			rows = append(rows, []string{
				label, fmt.Sprint(r.Pages), fmt.Sprintf("%.1f", float64(r.WireBytes)/(1<<20)),
				fmt.Sprint(r.DumpMs + r.SendMs), throttle,
			})
		}
		title := fmt.Sprintf("  container %s  rss %s", paint(c.Name, sBold), fmtBytes(c.RSSBytes))
		if c.TCPEstablished > 0 {
			title += fmt.Sprintf("  tcp %d", c.TCPEstablished)
		}
		out = append(out, title)
		for _, l := range table([]string{">round", ">pages", ">MB", ">ms", ">throttle"}, rows) {
			out = append(out, "    "+l)
		}
	}
	return out
}

// renderSummary: result box; the freeze is the headline number.
func renderSummary(m *v1alpha1.Migration) []string {
	st := &m.Status
	budget := freezeBudget(m)
	var lines []string
	if st.Phase == v1alpha1.PhaseSucceeded && st.Timings.FreezeMs > 0 {
		dt := st.Timings.FreezeMs
		hs, fg := freezeStyles(dt, budget)
		for _, row := range bigText(fmtMs(dt)) {
			lines = append(lines, paint(row, fg, sBold))
		}
		verdict := paint("within budget", sGreen)
		if dt > int64(budget) {
			verdict = paint(fmt.Sprintf("%.1f× over budget", float64(dt)/float64(budget)), sRed)
		}
		lines = append(lines, paint(" FREEZE "+fmtMs(dt)+" ", hs)+"  "+
			fmt.Sprintf("freeze budget %s · %s", fmtMs(int64(budget)), verdict), "")
	}

	ip := paint("no", sYellow)
	switch {
	case st.IPPreserved:
		ip = paint("yes", sGreen) + " " + st.SourcePodIP + " · TCP connections kept"
	case st.TargetPodIP != "" && st.NetworkAdapter == "phantom":
		ip += fmt.Sprintf(" %s → %s · in-cluster connections kept (Phantom mode)", orDash(st.SourcePodIP), st.TargetPodIP)
	case st.TargetPodIP != "":
		ip += fmt.Sprintf(" %s → %s · TCP connections closed", orDash(st.SourcePodIP), st.TargetPodIP)
	}
	lines = append(lines, kv("IP preserved", ip))

	rwo, rwx, move := 0, 0, ""
	for _, v := range st.Volumes {
		switch v.Kind {
		case "pvc-rwo":
			rwo++
		case "pvc-rwx":
			rwx++
		}
	}
	if st.Timings.VolumeMoveMs > 0 {
		move = " · detach+attach " + fmtMs(st.Timings.VolumeMoveMs)
	}
	lines = append(lines,
		kv("Volumes moved", fmt.Sprintf("%d RWO, %d RWX%s", rwo, rwx, move)),
		kv("Bytes on wire", fmtBytes(st.WireBytes)),
		kv("Pre-copy", fmtMs(st.Timings.PreCopyMs)),
		kv("Total", fmtMs(st.Timings.TotalMs)))
	for _, w := range st.Warnings {
		lines = append(lines, paint("⚠ "+w, sYellow))
	}

	title := " " + string(st.Phase) + " "
	switch st.Phase {
	case v1alpha1.PhaseSucceeded:
		title = paint(" ✓ migrated ", sGreen)
		if hasColdStart(m) {
			title = paint(" ⚠ running, but cold-started (memory state lost) ", sYellow)
		}
	case v1alpha1.PhaseFailed:
		title = paint(" ✗ failed ", sRed)
		lines = append([]string{paint(st.Message, sRed), ""}, lines...)
	case v1alpha1.PhaseRolledBack:
		title = paint(" ↺ rolled back – pod continues on "+st.SourceNode+" ", sYellow)
		lines = append([]string{st.Message, ""}, lines...)
	}
	return box(title, lines)
}

func hasColdStart(m *v1alpha1.Migration) bool {
	for _, c := range m.Status.Target.Containers {
		if c.ColdStartReason != "" {
			return true
		}
	}
	return false
}

// renderTimingBars: time breakdown as a bar chart (describe).
func renderTimingBars(m *v1alpha1.Migration) []string {
	t := m.Status.Timings
	items := []struct {
		name string
		ms   int64
		note string
	}{
		{"preflight", t.PreflightMs, "checks + placement"},
		{"pre-copy", t.PreCopyMs, "app keeps running"},
		{"freeze + dump", t.FreezeDumpMs, "❄ final dump"},
		{"final transfer", t.FinalTransferMs, "❄ rest of the data"},
		{"cutover", t.CutoverMs, "❄ delete source → replacement exists"},
		{"volume move", t.VolumeMoveMs, "❄ detach + attach (overlaps transfer)"},
		{"restore", t.RestoreMs, "❄ replacement → restored"},
	}
	var maxMs int64
	for _, it := range items {
		maxMs = max(maxMs, it.ms)
	}
	maxMs = max(maxMs, t.FreezeMs)
	const width = 36
	var out []string
	for _, it := range items {
		out = append(out, fmt.Sprintf("  %s %s  %s %s", padRight(it.name, 15), padLeft(fmtMs(it.ms), 8),
			padRight(paint(bar(float64(it.ms), float64(maxMs), width), sBlue), width), paint(it.note, sDim)))
	}
	_, fg := freezeStyles(t.FreezeMs, freezeBudget(m))
	out = append(out, "  "+strings.Repeat("─", 15+8+width+4),
		fmt.Sprintf("  %s %s  %s %s", padRight(paint("FREEZE", sBold), 15), padLeft(paint(fmtMs(t.FreezeMs), sBold), 8),
			padRight(paint(bar(float64(t.FreezeMs), float64(maxMs), width), fg), width),
			paint("budget "+fmtMs(int64(freezeBudget(m))), sDim)),
		fmt.Sprintf("  %s %s", padRight("total", 15), padLeft(fmtMs(t.TotalMs), 8)))
	return out
}

func kv(k, v string) string { return paint(padRight(k, 15), sDim) + v }

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func fmtDur(d time.Duration) string {
	if d < time.Millisecond {
		return "0 ms"
	}
	return fmtMs(d.Milliseconds())
}

func indexOf(list []v1alpha1.Phase, p v1alpha1.Phase) int {
	for i, v := range list {
		if v == p {
			return i
		}
	}
	return -1
}

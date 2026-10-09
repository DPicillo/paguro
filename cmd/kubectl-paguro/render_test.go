// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"paguro.dev/paguro/api/v1alpha1"
)

func sampleMigration() *v1alpha1.Migration {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	at := func(ms int) *metav1.MicroTime {
		t := metav1.NewMicroTime(t0.Add(time.Duration(ms) * time.Millisecond))
		return &t
	}
	return &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-0-k7f2q", Namespace: "shop", CreationTimestamp: metav1.NewTime(t0)},
		Spec: v1alpha1.MigrationSpec{PodName: "redis-0", Strategy: v1alpha1.StrategyPreCopy, CPUPolicy: v1alpha1.CPUStrict,
			PreCopy: v1alpha1.PreCopySpec{FreezeBudgetMs: 500}},
		Status: v1alpha1.MigrationStatus{
			Phase: v1alpha1.PhaseSucceeded, Message: "restored on node-b, freeze 312 ms",
			SourceNode: "node-a", TargetNode: "node-b", NetworkAdapter: "cilium", IPPreserved: true,
			SourcePodIP: "10.250.0.7", TargetPodIP: "10.250.0.7",
			Volumes: []v1alpha1.VolumeStatus{{Name: "data", Kind: "pvc-rwo", ClaimName: "data-redis-0"}},
			Containers: []v1alpha1.ContainerStatus{{Name: "redis", RSSBytes: 1 << 30, TCPEstablished: 12, Rounds: []v1alpha1.RoundStat{
				{Round: 1, Pages: 262144, WireBytes: 900 << 20, DumpMs: 400, SendMs: 7100},
				{Round: 2, Pages: 30000, WireBytes: 110 << 20, DumpMs: 60, SendMs: 900, ThrottlePct: 20},
				{Round: 3, Final: true, Pages: 1800, WireBytes: 7 << 20, DumpMs: 70, SendMs: 40},
			}}},
			Source:      v1alpha1.SourceStatus{FrozenAt: at(9000)},
			Target:      v1alpha1.TargetStatus{RestoredAt: at(9312)},
			Cutover:     v1alpha1.CutoverStatus{SourceDeletedAt: at(9120), TargetPodCreatedAt: at(9150)},
			WireBytes:   1017 << 20,
			StartedAt:   at(5),
			CompletedAt: at(9330),
			Timings: v1alpha1.Timings{PreflightMs: 12, PreCopyMs: 8460, FreezeDumpMs: 70, FinalTransferMs: 110,
				CutoverMs: 30, VolumeMoveMs: 2900, RestoreMs: 162, FreezeMs: 312, TotalMs: 9325},
		},
	}
}

func TestRenderSucceeded(t *testing.T) {
	m := sampleMigration()
	var out []string
	out = append(out, renderHeader(m)...)
	out = append(out, renderTimeline(m, observed{}, time.Now())...)
	out = append(out, renderRounds(m)...)
	out = append(out, renderTimingBars(m)...)
	out = append(out, renderSummary(m)...)
	text := strings.Join(out, "\n")
	for _, want := range []string{"FREEZE 312 ms", "within budget", "final ❄", "20%", "IP kept", "1 RWO", "✓ Succeeded"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if testing.Verbose() {
		t.Log("\n" + text)
	}
}

func TestRenderNetworkModes(t *testing.T) {
	for _, c := range []struct {
		adapter string
		want    string
	}{
		{"phantom", "10.250.0.7 → 10.0.2.9 · in-cluster connections kept (Phantom mode)"},
		{"generic", "10.250.0.7 → 10.0.2.9 · TCP connections closed"},
	} {
		m := sampleMigration()
		m.Status.NetworkAdapter, m.Status.IPPreserved, m.Status.TargetPodIP = c.adapter, false, "10.0.2.9"
		if text := strings.Join(renderSummary(m), "\n"); !strings.Contains(text, c.want) {
			t.Errorf("%s: summary lacks %q:\n%s", c.adapter, c.want, text)
		}
	}
}

func TestRenderFailedTimeline(t *testing.T) {
	m := sampleMigration()
	m.Status.Phase = v1alpha1.PhaseRolledBack
	m.Status.Source.FrozenAt = nil
	m.Status.Cutover = v1alpha1.CutoverStatus{}
	lines := renderTimeline(m, observed{}, time.Now())
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "Aborting") || !strings.Contains(text, "RolledBack") || strings.Contains(text, "Restoring") {
		t.Errorf("unexpected rollback timeline:\n%s", text)
	}
}

func TestHelpers(t *testing.T) {
	if got := fmtMs(312); got != "312 ms" {
		t.Error(got)
	}
	if got := fmtMs(9325); got != "9.3 s" {
		t.Error(got)
	}
	if got := fmtBytes(1017 << 20); got != "1017.0 MiB" {
		t.Error(got)
	}
	if n := migrationName(strings.Repeat("a", 80)); len(n) > 63 {
		t.Errorf("name too long: %d", len(n))
	}
	rows := table([]string{"A", ">B"}, [][]string{{"x", "1"}, {"long", "22"}})
	if rows[1] != "x       1" || rows[2] != "long   22" {
		t.Errorf("table alignment: %q", rows)
	}
}

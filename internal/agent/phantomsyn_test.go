// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// Attempts to the old address are handed back from the restore until
// shortly after the migration succeeded – not before the restore, not after
// a failure, not for ever.
func TestSYNHandBackWindow(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 55, 0, 0, time.UTC)
	at := func(d time.Duration) *metav1.MicroTime { t := metav1.NewMicroTime(now.Add(d)); return &t }
	mig := func(phase v1.Phase, restored, completed *metav1.MicroTime) *v1.Migration {
		m := &v1.Migration{}
		m.Status.Phase, m.Status.CompletedAt = phase, completed
		m.Status.Target.RestoredAt = restored
		return m
	}
	cases := []struct {
		name string
		m    *v1.Migration
		over bool
	}{
		{"restored, replacement not ready yet", mig(v1.PhaseRestoring, at(-3*time.Second), nil), false},
		{"succeeded a moment ago", mig(v1.PhaseSucceeded, at(-8*time.Second), at(-2*time.Second)), false},
		{"succeeded long ago", mig(v1.PhaseSucceeded, at(-time.Minute), at(-synAfter-time.Second)), true},
		{"failed", mig(v1.PhaseFailed, at(-3*time.Second), at(-time.Second)), true},
		{"restored long ago, never ready", mig(v1.PhaseRestoring, at(-synMax-time.Second), nil), true},
	}
	for _, c := range cases {
		if got := synWindowOver(c.m, now); got != c.over {
			t.Errorf("%s: over %v, want %v", c.name, got, c.over)
		}
	}
	// Not before the restore: nothing serves in place of the old address.
	pm := &phantomManager{}
	pm.handBackSYNs(mig(v1.PhaseFrozen, nil, nil))
	if len(pm.synBack) != 0 {
		t.Error("hand-back started before the restore")
	}
}

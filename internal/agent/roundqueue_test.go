// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Rounds are applied one after the other in arrival order; drain waits for
// all of them; a failure refuses later rounds and fails the drain.
func TestRoundQueue(t *testing.T) {
	var s roundQueues
	var mu sync.Mutex
	var applied []string
	release := make(chan struct{})
	apply := func(name string, block bool, err error) func() error {
		return func() error {
			if block {
				<-release
			}
			mu.Lock()
			applied = append(applied, name)
			mu.Unlock()
			return err
		}
	}
	if err := s.add("m", "c", "1", apply("1", true, nil)); err != nil {
		t.Fatal(err)
	}
	if err := s.add("m", "c", "2", apply("2", false, nil)); err != nil {
		t.Fatal(err)
	}
	// Round 1 is still being applied: a retry of round 1 and READY wait.
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.awaitRound(short, "m", "c", "1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retry of a round being applied did not wait: %v", err)
	}
	if err := s.drain(short, "m", "c"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain did not wait: %v", err)
	}
	close(release)
	if err := s.drain(context.Background(), "m", "c"); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 || applied[0] != "1" || applied[1] != "2" {
		t.Fatalf("applied %v, want [1 2]", applied)
	}

	// Another container: round 1 fails, round 2 is refused, READY fails.
	if err := s.add("m", "d", "1", apply("d1", false, errors.New("disk full"))); err != nil {
		t.Fatal(err)
	}
	if err := s.drain(context.Background(), "m", "d"); err == nil {
		t.Fatal("drain after a failed round succeeded")
	}
	if err := s.add("m", "d", "2", apply("d2", false, nil)); err == nil {
		t.Fatal("a round after a failed one was accepted")
	}
	s.forget("m", "d")
	if err := s.drain(context.Background(), "m", "d"); err != nil {
		t.Fatalf("forgotten container: %v", err)
	}
}

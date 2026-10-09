// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"fmt"
	"sync"
)

// roundQueues applies the pre-copy rounds of every container to its
// compacted base image (criuimg.ApplyRound) in the background, one
// container's rounds strictly in the order they arrived.
//
// The target used to compact a round before it answered the round's
// transfer, and the source waited for it: the 8 GiB pod's rounds went out
// at ~55 MB/s on a link that carried the final round at 115 MB/s, and every
// slower round left more dirty pages for the freeze. Now the target answers
// once the round is on disk; the next round travels while the previous one
// is folded in. READY waits until all of a container's rounds are applied
// (drain) – the restore reads the compacted images.
type roundQueues struct {
	mu sync.Mutex
	q  map[string]*roundQueue // uid/container
}

type roundQueue struct {
	rounds []queuedRound // received, not yet applied, in arrival order
	// broken is the first failure: base and delta are unusable, every
	// later round is refused and READY fails (the source rolls back during
	// pre-copy, the target cold-starts after the commit).
	broken error
	// changed is closed and replaced whenever a round has been applied.
	changed chan struct{}
}

type queuedRound struct {
	name  string
	apply func() error
}

func queueKey(uid, container string) string { return uid + "/" + container }

// get returns the container's queue; s.mu must be held.
func (s *roundQueues) get(key string) *roundQueue {
	if s.q == nil {
		s.q = map[string]*roundQueue{}
	}
	q := s.q[key]
	if q == nil {
		q = &roundQueue{changed: make(chan struct{})}
		s.q[key] = q
	}
	return q
}

// add queues a received round; a worker applies the queue's rounds one
// after the other. Refused once a round failed.
func (s *roundQueues) add(uid, container, round string, apply func() error) error {
	key := queueKey(uid, container)
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.get(key)
	if q.broken != nil {
		return q.broken
	}
	q.rounds = append(q.rounds, queuedRound{name: round, apply: apply})
	if len(q.rounds) == 1 {
		go s.work(key, q)
	}
	return nil
}

func (s *roundQueues) work(key string, q *roundQueue) {
	for {
		s.mu.Lock()
		next := q.rounds[0]
		s.mu.Unlock()
		err := next.apply()
		s.mu.Lock()
		q.rounds = q.rounds[1:]
		if err != nil && q.broken == nil {
			q.broken = fmt.Errorf("round %s could not be applied to the base image: %w", next.name, err)
		}
		close(q.changed)
		q.changed = make(chan struct{})
		done := len(q.rounds) == 0
		if done && q.broken == nil {
			delete(s.q, key) // nothing to remember; a later round starts afresh
		}
		s.mu.Unlock()
		if done {
			return
		}
	}
}

// pending reports whether round is waiting or being applied.
func (q *roundQueue) pending(round string) bool {
	for _, r := range q.rounds {
		if r.name == round {
			return true
		}
	}
	return false
}

// awaitRound waits until round is no longer queued – a retried transfer of
// a round must not replace its files while they are being applied.
func (s *roundQueues) awaitRound(ctx context.Context, uid, container, round string) error {
	return s.await(ctx, uid, container, func(q *roundQueue) bool { return !q.pending(round) })
}

// drain waits until every received round of the container is applied and
// reports a failure.
func (s *roundQueues) drain(ctx context.Context, uid, container string) error {
	return s.await(ctx, uid, container, func(q *roundQueue) bool { return len(q.rounds) == 0 })
}

func (s *roundQueues) await(ctx context.Context, uid, container string, done func(*roundQueue) bool) error {
	key := queueKey(uid, container)
	for {
		s.mu.Lock()
		q, ok := s.q[key]
		if !ok {
			s.mu.Unlock()
			return nil
		}
		if done(q) {
			err := q.broken
			s.mu.Unlock()
			return err
		}
		changed := q.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// forget drops what is remembered about a container (a broken queue) once
// its transfer is over.
func (s *roundQueues) forget(uid, container string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := queueKey(uid, container)
	if q, ok := s.q[key]; ok && len(q.rounds) == 0 {
		delete(s.q, key)
	}
}

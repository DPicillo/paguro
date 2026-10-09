// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// interruptionPoll is how often the agent asks for a scheduled termination
// (AWS recommends every five seconds).
const interruptionPoll = 5 * time.Second

// InterruptionSource tells when the cloud will take the node away; ok is
// false while nothing is scheduled.
type InterruptionSource interface {
	TerminatesAt(ctx context.Context) (at time.Time, ok bool, err error)
}

// InterruptionSourceFor returns the source for a node's cloud, from its
// providerID; nil where there is none (on-premises, unknown clouds).
func InterruptionSourceFor(providerID string) InterruptionSource {
	if strings.HasPrefix(providerID, "aws://") {
		return &ec2Metadata{base: "http://169.254.169.254", http: &http.Client{Timeout: 2 * time.Second}}
	}
	return nil
}

// NodeInterruptionSource returns the interruption source of the agent's
// node (nil where its cloud has none).
func (a *Agent) NodeInterruptionSource(ctx context.Context) (InterruptionSource, error) {
	n := &corev1.Node{}
	if err := a.APIReader.Get(ctx, client.ObjectKey{Name: a.NodeName}, n); err != nil {
		return nil, err
	}
	return InterruptionSourceFor(n.Spec.ProviderID), nil
}

// RunInterruptionWatch keeps the node's paguro.dev/terminates-at in step
// with the source: set once a termination is scheduled, removed when it is
// not (a stop that was called off). The controller plans the migrations
// off the node with it – what fits before the time moves, the rest is
// evicted at once (controller/deadline.go).
func (a *Agent) RunInterruptionWatch(ctx context.Context, src InterruptionSource) {
	a.watchInterruptions(ctx, src, interruptionPoll)
}

func (a *Agent) watchInterruptions(ctx context.Context, src InterruptionSource, every time.Duration) {
	published := "?" // unknown: the first answer is written either way
	for {
		at, ok, err := src.TerminatesAt(ctx)
		switch {
		case err != nil:
			a.Log.Debug("interruption notice not readable", "err", err)
		default:
			want := ""
			if ok {
				want = at.UTC().Format(time.RFC3339)
			}
			if want != published {
				if err := a.publishTermination(ctx, want); err != nil {
					a.Log.Warn("node annotation "+v1.AnnotationNodeTerminatesAt, "err", err)
				} else {
					published = want
					if ok {
						a.Log.Info("the node will be terminated", "at", want, "in", time.Until(at).Round(time.Second).String())
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// publishTermination sets the annotation, or removes it for "".
func (a *Agent) publishTermination(ctx context.Context, at string) error {
	var value any
	if at != "" {
		value = at
	}
	b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{
		v1.AnnotationNodeTerminatesAt: value}}})
	node := &corev1.Node{}
	node.Name = a.NodeName
	return a.Client.Patch(ctx, node, client.RawPatch(types.MergePatchType, b))
}

// ec2Metadata reads a spot interruption from the EC2 instance metadata
// service (IMDSv2): spot/instance-action answers 404 until AWS has
// scheduled the instance's termination (or stop, or hibernation), then
// {"action": "terminate", "time": "…"} – two minutes ahead.
type ec2Metadata struct {
	base     string
	http     *http.Client
	token    string
	tokenExp time.Time
}

const ec2TokenTTL = 6 * time.Hour

func (m *ec2Metadata) TerminatesAt(ctx context.Context) (time.Time, bool, error) {
	if m.token == "" || time.Now().After(m.tokenExp) {
		if err := m.newToken(ctx); err != nil {
			return time.Time{}, false, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+"/latest/meta-data/spot/instance-action", nil)
	if err != nil {
		return time.Time{}, false, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", m.token)
	resp, err := m.http.Do(req)
	if err != nil {
		return time.Time{}, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return time.Time{}, false, nil
	case http.StatusUnauthorized:
		m.token = "" // expired early: a new one next time
		return time.Time{}, false, fmt.Errorf("instance metadata: token refused")
	case http.StatusOK:
	default:
		return time.Time{}, false, fmt.Errorf("instance metadata: %s", resp.Status)
	}
	var action struct {
		Action string `json:"action"`
		Time   string `json:"time"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&action); err != nil {
		return time.Time{}, false, fmt.Errorf("instance metadata: spot/instance-action: %w", err)
	}
	at, err := time.Parse(time.RFC3339, action.Time)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("instance metadata: spot/instance-action time %q: %w", action.Time, err)
	}
	// stop and hibernate end the node's pods just the same.
	return at, true, nil
}

func (m *ec2Metadata) newToken(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, m.base+"/latest/api/token", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", fmt.Sprint(int(ec2TokenTTL.Seconds())))
	resp, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("instance metadata token: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	m.token = strings.TrimSpace(string(b))
	// Renew a minute early: a token that expires during a request is refused.
	m.tokenExp = time.Now().Add(ec2TokenTTL - time.Minute)
	return nil
}

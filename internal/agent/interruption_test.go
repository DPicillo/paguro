// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "paguro.dev/paguro/api/v1alpha1"
)

// fakeIMDS answers like EC2's instance metadata service (IMDSv2): a token
// first, then spot/instance-action – 404, or the scheduled action.
type fakeIMDS struct {
	mu     sync.Mutex
	action string // body of spot/instance-action; "" answers 404
	tokens int
}

func (f *fakeIMDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
		if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			http.Error(w, "ttl missing", http.StatusBadRequest)
			return
		}
		f.tokens++
		_, _ = w.Write([]byte("token-1"))
	case r.URL.Path == "/latest/meta-data/spot/instance-action":
		if r.Header.Get("X-aws-ec2-metadata-token") != "token-1" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		if f.action == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(f.action))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIMDS) set(action string) {
	f.mu.Lock()
	f.action = action
	f.mu.Unlock()
}

func TestEC2SpotInstanceAction(t *testing.T) {
	imds := &fakeIMDS{}
	srv := httptest.NewServer(imds)
	defer srv.Close()
	m := &ec2Metadata{base: srv.URL, http: srv.Client()}
	ctx := context.Background()
	if _, ok, err := m.TerminatesAt(ctx); err != nil || ok {
		t.Fatalf("nothing scheduled: ok %v err %v", ok, err)
	}
	imds.set(`{"action": "terminate", "time": "2026-10-07T18:13:30Z"}`)
	at, ok, err := m.TerminatesAt(ctx)
	if err != nil || !ok || !at.Equal(time.Date(2026, 10, 7, 18, 13, 30, 0, time.UTC)) {
		t.Fatalf("scheduled: %v %v %v", at, ok, err)
	}
	if imds.tokens != 1 {
		t.Fatalf("the token is reused, got %d requests", imds.tokens)
	}
	imds.set(`{"action": "terminate", "time": "soon"}`)
	if _, _, err := m.TerminatesAt(ctx); err == nil {
		t.Fatal("a time that does not parse must be an error")
	}
	if InterruptionSourceFor("aws:///eu-central-1a/i-0abc") == nil || InterruptionSourceFor("openstack:///x") != nil {
		t.Fatal("only EC2 nodes have a source")
	}
}

type fakeSource struct {
	mu sync.Mutex
	at time.Time
	ok bool
}

func (f *fakeSource) TerminatesAt(context.Context) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.at, f.ok, nil
}

// The watch sets paguro.dev/terminates-at once a termination is scheduled
// and removes it when it is called off.
func TestInterruptionWatchAnnotatesNode(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", Annotations: map[string]string{"other": "kept"}}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()
	a := &Agent{Client: cl, NodeName: "node-a", Log: slog.New(slog.DiscardHandler)}
	src := &fakeSource{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.watchInterruptions(ctx, src, 10*time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()

	annotation := func() (string, bool) {
		n := &corev1.Node{}
		_ = cl.Get(ctx, client.ObjectKey{Name: "node-a"}, n)
		v, ok := n.Annotations[v1.AnnotationNodeTerminatesAt]
		if n.Annotations["other"] != "kept" {
			t.Fatal("other annotations must stay")
		}
		return v, ok
	}
	waitFor := func(want string, present bool) {
		t.Helper()
		for range 200 {
			if v, ok := annotation(); ok == present && v == want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		v, ok := annotation()
		t.Fatalf("want %q (present %v), got %q (%v)", want, present, v, ok)
	}
	waitFor("", false)
	src.mu.Lock()
	src.at, src.ok = time.Date(2026, 10, 7, 18, 13, 30, 0, time.FixedZone("CEST", 2*3600)), true
	src.mu.Unlock()
	waitFor("2026-10-07T16:13:30Z", true)
	src.mu.Lock()
	src.ok = false
	src.mu.Unlock()
	waitFor("", false)
}

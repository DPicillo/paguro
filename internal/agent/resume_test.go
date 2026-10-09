// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/pkg/names"
)

// targetStub records the requests of a final transfer; fail names a path
// suffix to answer with 500.
type targetStub struct {
	mu   sync.Mutex
	reqs []string
	fail string
}

func (s *targetStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Method+" "+r.URL.Path)
	fail := s.fail != "" && strings.HasSuffix(r.URL.Path, s.fail)
	s.mu.Unlock()
	if fail {
		http.Error(w, "disk full", http.StatusInternalServerError)
	}
}

func (s *targetStub) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.reqs
	s.reqs = nil
	slices.Sort(out)
	return out
}

// dumpDir creates a dump directory with final images and a rootfs diff per
// container, as the source job leaves it after the commit.
func dumpDir(t *testing.T, root, dumpRoot string, containers ...string) {
	t.Helper()
	for _, c := range containers {
		dir := filepath.Join(root, dumpRoot, "containers", c)
		if err := os.MkdirAll(filepath.Join(dir, v1.DirImages, "final"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, v1.DirImages, "final", "pages-1.img"), []byte("pages of "+c), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, v1.FileRootfsDiff), []byte("rootfs of "+c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSendFinalResumes(t *testing.T) {
	root := t.TempDir()
	dumpRoot := "/var/lib/paguro/dump/mig-1"
	dumpDir(t, root, dumpRoot, "a", "b")
	stub := &targetStub{fail: "/c/b/images/final"}
	srv := httptest.NewServer(stub)
	defer srv.Close()

	a := &Agent{Host: &Host{Root: root}}
	var done []string
	f := finalSend{
		UID:      "mig-1",
		Client:   &Client{Endpoint: strings.TrimPrefix(srv.URL, "http://"), HTTP: srv.Client()},
		Meta:     layout.Meta{UID: "mig-1", Containers: []layout.ContainerMeta{{Name: "a"}, {Name: "b"}}},
		DumpRoot: dumpRoot,
		Done:     func(c string, _ SendStats, _ time.Duration) { done = append(done, c) },
	}
	sentReady := filepath.Join(root, dumpRoot, fileSentReady)

	// First attempt: a arrives, b's final images are refused.
	if err := a.sendFinal(context.Background(), f); err == nil || !strings.Contains(err.Error(), "b final") {
		t.Fatalf("first attempt: err = %v, want b's final images to fail", err)
	}
	if got := readSentReady(sentReady); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("sent-ready after the first attempt = %q, want [a]", got)
	}
	if !slices.Equal(done, []string{"a"}) {
		t.Fatalf("done = %q", done)
	}
	stub.take()

	// The resumed transfer sends the metadata again and only container b:
	// the target may already be restoring a from its images.
	stub.fail = ""
	done = nil
	if err := a.sendFinal(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /v1/m/mig-1/c/b/ready",
		"PUT /v1/m/mig-1/c/b/images/final",
		"PUT /v1/m/mig-1/c/b/rootfs",
		"PUT /v1/m/mig-1/meta",
	}
	if got := stub.take(); !slices.Equal(got, want) {
		t.Fatalf("resumed requests = %q, want %q", got, want)
	}
	if got := readSentReady(sentReady); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("sent-ready = %q, want [a b]", got)
	}

	// Everything sent: a third run sends only the metadata.
	if err := a.sendFinal(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if got := stub.take(); !slices.Equal(got, []string{"PUT /v1/m/mig-1/meta"}) {
		t.Fatalf("complete transfer resent %q", got)
	}
}

func TestResumable(t *testing.T) {
	now := metav1.NowMicro()
	committed := func(mut func(*v1.Migration)) *v1.Migration {
		m := &v1.Migration{}
		m.Status.Phase = v1.PhaseCuttingOver
		m.Status.SourceNode = "node-a"
		m.Status.Source.FrozenAt = &now
		m.Status.Target.Endpoint = "10.0.0.2:9443"
		if mut != nil {
			mut(m)
		}
		return m
	}
	a := &Agent{NodeName: "node-a"}
	cases := []struct {
		name string
		m    *v1.Migration
		want bool
	}{
		{"committed, transfer open", committed(nil), true},
		{"restoring", committed(func(m *v1.Migration) { m.Status.Phase = v1.PhaseRestoring }), true},
		{"pre-copy: nothing committed", committed(func(m *v1.Migration) { m.Status.Phase = v1.PhasePreCopy }), false},
		{"terminal", committed(func(m *v1.Migration) { m.Status.Phase = v1.PhaseSucceeded }), false},
		{"other source node", committed(func(m *v1.Migration) { m.Status.SourceNode = "node-b" }), false},
		{"not frozen", committed(func(m *v1.Migration) { m.Status.Source.FrozenAt = nil }), false},
		{"transfer done", committed(func(m *v1.Migration) { m.Status.Source.TransferDoneAt = &now }), false},
		{"source failed", committed(func(m *v1.Migration) { m.Status.Source.Error = "dump failed" }), false},
		{"no target endpoint", committed(func(m *v1.Migration) { m.Status.Target.Endpoint = "" }), false},
	}
	for _, c := range cases {
		if got := a.resumable(c.m); got != c.want {
			t.Errorf("%s: resumable = %v, want %v", c.name, got, c.want)
		}
	}
}

// targetServer runs the real transfer server on a temporary state directory.
func targetServer(t *testing.T) (*Client, func()) {
	t.Helper()
	old := layout.StateDir
	layout.StateDir = t.TempDir()
	srv := httptest.NewServer((&Server{Token: "t", Log: slog.New(slog.DiscardHandler)}).Handler())
	return &Client{Endpoint: strings.TrimPrefix(srv.URL, "http://"), Token: "t", HTTP: srv.Client()},
		func() { srv.Close(); layout.StateDir = old }
}

func TestServerRefusesChangesAfterReady(t *testing.T) {
	cl, stop := targetServer(t)
	defer stop()
	ctx := context.Background()
	put := func(path, body string) error {
		_, err := cl.Send(ctx, "PUT", path, func(w io.Writer) error { _, err := io.WriteString(w, body); return err })
		return err
	}
	if err := put("/v1/m/mig-1/c/a/rootfs", "rootfs"); err != nil {
		t.Fatal(err)
	}
	if err := cl.Marker(ctx, "mig-1", "a", "ready", ""); err != nil {
		t.Fatal(err)
	}
	// From here on the restore may be reading a's data.
	if err := put("/v1/m/mig-1/c/a/rootfs", "other"); !errors.Is(err, errComplete) {
		t.Errorf("rootfs after READY: err = %v, want errComplete", err)
	}
	if err := put("/v1/m/mig-1/c/a/images/final", ""); !errors.Is(err, errComplete) {
		t.Errorf("images after READY: err = %v, want errComplete", err)
	}
	if err := cl.Marker(ctx, "mig-1", "a", "failed", "late error"); !errors.Is(err, errComplete) {
		t.Errorf("FAILED after READY: err = %v, want errComplete", err)
	}
	if err := cl.Marker(ctx, "mig-1", "a", "ready", ""); err != nil {
		t.Errorf("READY again: %v", err)
	}
	dir := layout.ContainerDir("mig-1", "a")
	if b, _ := os.ReadFile(filepath.Join(dir, names.FileRootfsDiff)); string(b) != "rootfs" {
		t.Errorf("rootfs changed after READY: %q", b)
	}
	if layout.Exists(filepath.Join(dir, names.FileFailed)) {
		t.Error("FAILED written after READY")
	}
	// Another container of the pod is not affected.
	if err := put("/v1/m/mig-1/c/b/rootfs", "rootfs"); err != nil {
		t.Errorf("container b: %v", err)
	}
}

// The agent restarts after READY reached the target but before sent-ready
// recorded it: the resumed transfer must leave that container alone.
func TestSendFinalReadyWithoutRecord(t *testing.T) {
	cl, stop := targetServer(t)
	defer stop()
	root := t.TempDir()
	dumpRoot := "/var/lib/paguro/dump/mig-1"
	dumpDir(t, root, dumpRoot, "a")
	a := &Agent{Host: &Host{Root: root}}
	f := finalSend{UID: "mig-1", Client: cl, DumpRoot: dumpRoot,
		Meta: layout.Meta{UID: "mig-1", Containers: []layout.ContainerMeta{{Name: "a"}}}}
	if err := a.sendFinal(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(layout.ImagesDir("mig-1", "a"), "final", "pages-1.img")
	before, err := os.Stat(img)
	if err != nil {
		t.Fatal(err)
	}
	sentReady := filepath.Join(root, dumpRoot, fileSentReady)
	if err := os.Remove(sentReady); err != nil {
		t.Fatal(err)
	}
	if err := a.sendFinal(context.Background(), f); err != nil {
		t.Fatalf("resumed transfer: %v", err)
	}
	after, err := os.Stat(img)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the target's final images were replaced (err %v)", err)
	}
	if got := readSentReady(sentReady); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("sent-ready = %q, want [a]", got)
	}
}

// The commit runs in parallel with the transfer: the data may arrive before
// it, READY never does.
func TestSendFinalWaitsForCommit(t *testing.T) {
	root := t.TempDir()
	dumpRoot := "/var/lib/paguro/dump/mig-1"
	dumpDir(t, root, dumpRoot, "a")
	stub := &targetStub{}
	srv := httptest.NewServer(stub)
	defer srv.Close()
	a := &Agent{Host: &Host{Root: root}}
	f := finalSend{UID: "mig-1", DumpRoot: dumpRoot,
		Client: &Client{Endpoint: strings.TrimPrefix(srv.URL, "http://"), HTTP: srv.Client()},
		Meta:   layout.Meta{UID: "mig-1", Containers: []layout.ContainerMeta{{Name: "a"}}}}

	f.Gate = func() error { return errors.New("aborted before the commit") }
	if err := a.sendFinal(context.Background(), f); err == nil {
		t.Fatal("a failed commit must fail the transfer")
	}
	want := []string{"PUT /v1/m/mig-1/c/a/images/final", "PUT /v1/m/mig-1/c/a/rootfs", "PUT /v1/m/mig-1/meta"}
	if got := stub.take(); !slices.Equal(got, want) {
		t.Fatalf("requests = %q, want the data without READY %q", got, want)
	}
	if got := readSentReady(filepath.Join(root, dumpRoot, fileSentReady)); len(got) != 0 {
		t.Fatalf("sent-ready = %q after a failed commit", got)
	}

	committed := make(chan struct{})
	f.Gate = func() error { <-committed; return nil }
	done := make(chan error, 1)
	go func() { done <- a.sendFinal(context.Background(), f) }()
	time.Sleep(50 * time.Millisecond)
	for _, r := range stub.take() {
		if strings.HasSuffix(r, "/ready") {
			t.Fatal("READY sent before the commit")
		}
	}
	close(committed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := stub.take(); !slices.Contains(got, "POST /v1/m/mig-1/c/a/ready") {
		t.Fatalf("no READY after the commit: %q", got)
	}
}

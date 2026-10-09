// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
)

func TestEndpointIDForIP(t *testing.T) {
	body := `[{"id":12,"status":{"networking":{"addressing":[{"ipv4":"10.244.1.5"}]}}},
	          {"id":78,"status":{"networking":{"addressing":[{"ipv4":"10.250.0.1","ipv6":""}]}}}]`
	id, err := endpointIDForIP(body, "10.250.0.1")
	if err != nil || id != 78 {
		t.Fatalf("id=%d err=%v", id, err)
	}
	if _, err := endpointIDForIP(body, "10.9.9.9"); err == nil {
		t.Fatal("expected an error for an unknown IP")
	}
}

// The name must match what the attach/detach controller computes, otherwise
// it would create a second VolumeAttachment instead of adopting ours.
func TestAttachmentName(t *testing.T) {
	// Reference value: sha256("vol-123" + "cinder.csi.openstack.org" + "k8s-w-3")
	got := attachmentName("vol-123", "cinder.csi.openstack.org", "k8s-w-3")
	if len(got) != 68 || got[:4] != "csi-" {
		t.Fatalf("unexpected name %q", got)
	}
	if got != attachmentName("vol-123", "cinder.csi.openstack.org", "k8s-w-3") {
		t.Fatal("not deterministic")
	}
}

// fakeIPAM mimics the Cilium agent's IPAM API for one pool with one address.
type fakeIPAM struct {
	mu      sync.Mutex
	owner   string          // holder of the address, "" when free
	pending map[string]bool // owners with a failed request
	// poolDeleted: the pool resource is gone (rotation); the node keeps its
	// CIDR as long as it needs it
	poolDeleted bool
	calls       []string
}

func (f *fakeIPAM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/ipam":
		owner := r.URL.Query().Get("owner")
		if r.URL.Query().Get("pool") == "broken" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("pool") != "paguro-10-250-0-4-ab" || f.poolDeleted {
			f.pending[owner] = true // Cilium records even this failure as pending
			http.Error(w, "IP pool not found in stateDB table", http.StatusBadGateway)
			return
		}
		if f.owner != "" {
			f.pending[owner] = true
			http.Error(w, `"all CIDR ranges are exhausted"`, http.StatusBadGateway)
			return
		}
		f.owner = owner
		delete(f.pending, owner)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"address":{"ipv4":"10.250.0.4","ipv4-pool-name":"paguro-10-250-0-4-ab"}}`)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/ipam/10.250.0.4":
		// by address: no check against the pool table (the pool may be gone)
		owner := r.URL.Query().Get("owner")
		if f.owner != "" {
			f.pending[owner] = true
			http.Error(w, "IP already allocated", http.StatusBadGateway)
			return
		}
		f.owner = owner
		delete(f.pending, owner)
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/ipam/10.250.0.4":
		f.owner = ""
	default:
		http.NotFound(w, r)
	}
}

func fakeCilium(t *testing.T, f *fakeIPAM) *CiliumHooks {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "cilium.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: f}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return NewCiliumHooks(sock)
}

// The pod still has the address: the hold stays pending and keeps the
// CIDR's demand; Unhold takes the freed address and gives it back.
func TestHoldWhileInUse(t *testing.T) {
	f := &fakeIPAM{owner: "pod", pending: map[string]bool{}}
	c := fakeCilium(t, f)
	ctx := context.Background()
	taken, err := c.Hold(ctx, "paguro-10-250-0-4-ab", "paguro-hold/m1")
	if err != nil || taken != "" {
		t.Fatalf("hold: taken=%q err=%v", taken, err)
	}
	if !f.pending["paguro-hold/m1"] {
		t.Fatal("hold must leave a pending request")
	}
	f.mu.Lock()
	f.owner = ""         // the pod's address is released (early release / CNI DEL)
	f.poolDeleted = true // and the controller rotated the pool
	f.mu.Unlock()
	if err := c.Unhold(ctx, "paguro-10-250-0-4-ab", "paguro-hold/m1", "10.250.0.4", taken); err != nil {
		t.Fatal(err)
	}
	if f.owner != "" || f.pending["paguro-hold/m1"] {
		t.Fatalf("unhold left owner=%q pending=%v", f.owner, f.pending)
	}
}

// The address is free already: the hold takes it, and Unhold releases
// exactly that address (another request would fail – the hold has it).
func TestHoldTakesFreeAddress(t *testing.T) {
	f := &fakeIPAM{pending: map[string]bool{}}
	c := fakeCilium(t, f)
	ctx := context.Background()
	taken, err := c.Hold(ctx, "paguro-10-250-0-4-ab", "paguro-hold/m1")
	if err != nil || taken != "10.250.0.4" || f.owner != "paguro-hold/m1" {
		t.Fatalf("hold: taken=%q owner=%q err=%v", taken, f.owner, err)
	}
	if err := c.Unhold(ctx, "paguro-10-250-0-4-ab", "paguro-hold/m1", "10.250.0.4", taken); err != nil {
		t.Fatal(err)
	}
	if f.owner != "" {
		t.Fatalf("address still held by %q", f.owner)
	}
}

func TestHoldReportsOtherErrors(t *testing.T) {
	c := fakeCilium(t, &fakeIPAM{pending: map[string]bool{}})
	if _, err := c.Hold(context.Background(), "broken", "paguro-hold/m1"); err == nil {
		t.Fatal("expected an error for a refusal Cilium does not keep as pending")
	}
	// An unknown pool is kept as pending, like an exhausted one.
	if _, err := c.Hold(context.Background(), "other-pool", "paguro-hold/m1"); err != nil {
		t.Fatalf("unknown pool: %v", err)
	}
}

func TestPendingRefusal(t *testing.T) {
	for body, want := range map[string]bool{
		`"all CIDR ranges are exhausted"`: true,
		`"unable to allocate from pool \"paguro-10-250-0-5-ab\" (family ipv4): pool not (yet) available"`: true,
		`"IP pool 'paguro-10-250-0-4-7bcf4' not found in stateDB table"`:                                  true,
		`"invalid owner"`: false,
	} {
		if got := pendingRefusal(body); got != want {
			t.Errorf("pendingRefusal(%s) = %v", body, got)
		}
	}
}

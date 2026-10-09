// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CiliumHooks speed up the handover of a sticky IP between two nodes.
// Without them the handover takes as long as the chain
//
//	source pod deleted → kubelet kills → CNI DEL → Cilium releases IP →
//	(debounce) → CiliumNode update → operator allocates to the target →
//	CNI ADD on the target keeps failing with "pool not (yet) available"
//
// Some links can be brought forward:
//
//   - EarlyRelease (source, right after the final dump): the IP is released
//     via the agent API instead of waiting for kill + CNI DEL. The frozen pod
//     behind its shield no longer sends or receives anything – the fact that
//     its endpoint still carries the IP in the eBPF datapath for a short time
//     does no harm.
//   - Hold (source, before the release): keeps the sticky /32 allocated to
//     the source node until the restore. Cilium routes a remote address by
//     the endpoint's entry in its ipcache and, without one, by the pool
//     CIDRs of the nodes (fallback entries with the node as tunnel peer). A
//     released IP of a one-address pool frees its CIDR at once, and every
//     node then treats the address as outside the cluster until the target
//     has its endpoint – a NodePort/LoadBalancer connection whose packets
//     arrive in that window is NATed afresh for the uplink and reset after
//     the restore (measured: 7 s window during an RWO volume move; the
//     entry node rebound the client to its node IP). With the hold the
//     address keeps pointing at the source node (packets are dropped there,
//     the client retransmits) until the target's endpoint, which takes
//     precedence over any CIDR entry, appears.
//
// A pre-request of the pool on the target via POST /ipam was tried once and
// dropped: back then one pool moved between nodes, and a request under a
// separate owner left a pending entry for up to 5 minutes (a 64 s freeze
// when the node later became the source). With a fresh pool generation per
// migration it is back in a safe form (handover.go): the generation is
// created during pre-copy, the request uses the CNI plugin's own owner and
// is made only while the pool's CIDR is not on the node, and the
// replacement is held back by a scheduling gate until the commit.
//
// The release uses the Cilium agent's local REST API (Unix socket); if it is
// unavailable, only the slower default chain remains – not an error.
type CiliumHooks struct {
	Socket string // host path, e.g. /var/run/cilium/cilium.sock
	http   *http.Client
}

func NewCiliumHooks(socket string) *CiliumHooks {
	return &CiliumHooks{Socket: socket, http: &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}}
}

func (c *CiliumHooks) do(ctx context.Context, method, path string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://cilium/v1"+path, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return resp.StatusCode, strings.TrimSpace(string(b)), nil
}

// EarlyRelease releases the IP of a (frozen) pod – in the same order as
// CNI DEL: first delete the endpoint (otherwise Cilium refuses with "IP is in
// use by endpoint N"), then the address. The later CNI DEL by kubelet finds
// neither and ends as a no-op.
func (c *CiliumHooks) EarlyRelease(ctx context.Context, ip, pool string) error {
	code, body, err := c.do(ctx, http.MethodGet, "/endpoint")
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("cilium endpoints: HTTP %d: %s", code, body)
	}
	id, err := endpointIDForIP(body, ip)
	if err != nil {
		return err
	}
	if code, body, err = c.do(ctx, http.MethodDelete, fmt.Sprintf("/endpoint/%d", id)); err != nil {
		return err
	} else if code/100 != 2 {
		return fmt.Errorf("delete cilium endpoint %d: HTTP %d: %s", id, code, body)
	}
	code, body, err = c.do(ctx, http.MethodDelete, "/ipam/"+url.PathEscape(ip)+"?pool="+url.QueryEscape(pool))
	if err != nil {
		return err
	}
	if code/100 != 2 {
		return fmt.Errorf("cilium release: HTTP %d: %s", code, body)
	}
	return nil
}

// endpointIDForIP finds the endpoint with this IPv4 address in the endpoint
// list.
func endpointIDForIP(body, ip string) (int64, error) {
	var eps []struct {
		ID     int64 `json:"id"`
		Status struct {
			Networking struct {
				Addressing []struct {
					IPv4 string `json:"ipv4"`
				} `json:"addressing"`
			} `json:"networking"`
		} `json:"status"`
	}
	// Endpoint lists get large; decode only what is needed.
	if err := json.Unmarshal([]byte(body), &eps); err != nil {
		return 0, fmt.Errorf("endpoint list: %w", err)
	}
	for _, e := range eps {
		for _, a := range e.Status.Networking.Addressing {
			if a.IPv4 == ip {
				return e.ID, nil
			}
		}
	}
	return 0, fmt.Errorf("no Cilium endpoint with IP %s", ip)
}

// Hold keeps the pool's CIDR on this node after its only address is released:
// a request for the pool under a separate owner. While the pod still has the
// address the request fails and Cilium records it as pending (it keeps the
// pool's demand for pendingAllocationTTL, 5 minutes); should the address be
// free already, the request takes it (returned as taken). Either way the
// agent does not give the CIDR back. Unhold ends it.
func (c *CiliumHooks) Hold(ctx context.Context, pool, owner string) (taken string, err error) {
	code, body, err := c.allocate(ctx, pool, owner)
	switch {
	case err != nil:
		return "", err
	case code/100 == 2:
		return allocatedIPv4(body)
	case pendingRefusal(body):
		return "", nil
	default:
		return "", fmt.Errorf("cilium hold: HTTP %d: %s", code, body)
	}
}

// pendingRefusal: refusals that Cilium records as a pending request – the
// pool's addresses are taken, its CIDR is not on this node yet, or the pool
// object is not known (yet) – and that therefore count as demand for the
// pool (multipool_manager.go: upsertPendingAllocation on every failure).
func pendingRefusal(body string) bool {
	for _, s := range []string{"exhausted", "not (yet) available", "not found in stateDB"} {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

// Unhold ends a Hold on ip. A pending request is cleared by taking the (now
// free) address under the same owner – by address: the old pool is deleted
// by then, and Cilium refuses requests for the next free address of a pool
// it no longer knows (and records them as pending again) – then the address
// is released again. Without it a pending request expires on its own.
func (c *CiliumHooks) Unhold(ctx context.Context, pool, owner, ip, taken string) error {
	if taken == "" {
		q := url.Values{"owner": {owner}, "pool": {pool}}
		code, body, err := c.do(ctx, http.MethodPost, "/ipam/"+url.PathEscape(ip)+"?"+q.Encode())
		if err != nil {
			return err
		}
		if code/100 != 2 {
			return fmt.Errorf("cilium unhold: HTTP %d: %s", code, body)
		}
		taken = ip
	}
	code, body, err := c.do(ctx, http.MethodDelete, "/ipam/"+url.PathEscape(taken)+"?pool="+url.QueryEscape(pool))
	if err != nil {
		return err
	}
	if code/100 != 2 {
		return fmt.Errorf("cilium unhold release: HTTP %d: %s", code, body)
	}
	return nil
}

func (c *CiliumHooks) allocate(ctx context.Context, pool, owner string) (int, string, error) {
	q := url.Values{"family": {"ipv4"}, "owner": {owner}, "pool": {pool}}
	return c.do(ctx, http.MethodPost, "/ipam?"+q.Encode())
}

func allocatedIPv4(body string) (string, error) {
	var res struct {
		Address struct {
			IPv4 string `json:"ipv4"`
		} `json:"address"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil || res.Address.IPv4 == "" {
		return "", fmt.Errorf("cilium allocation: no address in %q", body)
	}
	return res.Address.IPv4, nil
}

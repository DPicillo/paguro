// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

// Phantom mode on the node side (docs/PHANTOM-MODE.md, section 13).
//
// After the commit the source publishes the frozen pod's connections
// (status.source.phantom). The target agent then programs its node – the
// replacement's inbound rules stay pending until the restore – and reports
// status.target.phantom.programmedAt. Only then does every other agent program
// its side (peer pods and host clients on that node) and report
// status.phantomNodes[node]. Order matters: a peer that translates before the
// target knows a flow makes the new pod's kernel answer with RST.
//
// What a node installed is kept in a state file per migration, so that a
// restarted agent removes exactly that: rules by owner id, reservations
// from the file. Rules end with their connections: the target agent
// reports ended flows (status.target.phantom.deadFlows) and, when none is left
// or the pod is gone, releasedAt.
//
// Part 1, here: the manager and its state files. Programming nodes:
// phantom_program.go; routes: phantom_routes.go; undoing:
// phantom_release.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/layout"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/phantom"
)

// phantomStateDir holds one JSON file per migration this node programmed.
var phantomStateDir = filepath.Join(v1.StateDir, "phantom")

// isPhantom reports whether a migration runs in Phantom mode.
func isPhantom(m *v1.Migration) bool { return m.Status.NetworkAdapter == netadapter.NamePhantom }

// phantomRecord is what this node installed for one migration.
type phantomRecord struct {
	UID       types.UID `json:"uid"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	ID        uint32    `json:"id"`
	Target    bool      `json:"target"`
	// PerFlow[i] is the plan of status.source.phantom.flows[i] on this node.
	PerFlow []phantom.PlanResult `json:"perFlow"`
	// Dead flows whose rules were removed already.
	Dead []int32 `json:"dead,omitempty"`
	// Aborted: dead flows whose sockets on this node were aborted after a
	// cold start of the replacement (abortStranded).
	Aborted []int32 `json:"aborted,omitempty"`
	// Target only.
	Netns          string `json:"netns,omitempty"` // in-process path
	OldIP          string `json:"oldIP,omitempty"`
	NewIP          string `json:"newIP,omitempty"`
	NodeIP         string `json:"nodeIP,omitempty"`
	PendingCleared bool   `json:"pendingCleared,omitempty"`
	// Reported: the status report of this node's programming went through.
	Reported bool `json:"reported,omitempty"`
	// Routes this record needs for old addresses (phantom.EnsureOffLinkRoute;
	// Netns "" is the host). A chained migration needs the same routes as
	// the one before it, so a route goes only when no record needs it.
	Routes []phantomRoute `json:"routes,omitempty"`
	// Programmed: when this node applied the record. For an address that
	// several records need, the newest one says where it goes.
	Programmed time.Time `json:"programmed,omitempty"`
}

type phantomRoute struct {
	Netns string `json:"netns,omitempty"`
	Addr  string `json:"addr"`
	// Like is the address the route copies: the pod's new IP.
	Like string `json:"like,omitempty"`
	// Routed: a CNI route took the address into the cluster when the
	// record was programmed (host namespace only).
	Routed bool `json:"routed,omitempty"`
}

// same: both are the route for the same address in the same namespace.
func (r phantomRoute) same(o phantomRoute) bool { return r.Netns == o.Netns && r.Addr == o.Addr }

// phantomManager owns this node's translator. All operations are serialized:
// they take milliseconds and touch shared maps and sysctls.
type phantomManager struct {
	a   *Agent
	log *slog.Logger

	mu      sync.Mutex
	t       *phantom.Translator
	records map[types.UID]*phantomRecord
	gc      map[types.UID]bool // target GC loop running
	// gcWake wakes a target's GC loop before its next tick (a cold start).
	gcWake map[types.UID]chan struct{}
	// released migrations are never programmed again, even if a stale
	// event arrives later.
	released map[types.UID]bool
	// unroutableSent: lost old addresses already reported.
	unroutableSent map[unroutable]bool
	// hostCovered: host devices this process attached the host programs to
	// after the records were programmed (coverHostDevices).
	hostCovered map[string]bool
	// steerNets: pod namespaces with steering rules (syncSteering); the
	// host's is always checked.
	steerNets map[string]bool
	// steer keeps the steering (steering()); steerErr: the last error
	// logged per namespace.
	steer    *phantom.Steering
	steerErr map[string]string
	// routeOf: the tuple the kernel routes a host flow by, per flow
	// (routingTuples); ctErr: the last conntrack error logged.
	routeOf map[phantom.Tuple]phantom.Tuple
	ctErr   string
	// synBack: migrations whose connection attempts to the old address
	// this node hands back to the Service (phantomsyn.go).
	synBack map[types.UID]bool
}

// EnablePhantom sets up Phantom mode on this node (a.Phantom). It fails when
// the node has no bpffs at /sys/fs/bpf or cannot load the programs.
func EnablePhantom(a *Agent) (*phantomManager, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &fs); err != nil {
		return nil, fmt.Errorf("/sys/fs/bpf: %w", err)
	}
	if fs.Type != unix.BPF_FS_MAGIC {
		return nil, errors.New("/sys/fs/bpf is not a bpffs (mount the host's /sys/fs/bpf into the agent)")
	}
	pm, err := newPhantomManager(a)
	if err != nil {
		return nil, err
	}
	a.Phantom = pm
	return pm, nil
}

// Sweep releases what this node installed for migrations that are gone.
func (pm *phantomManager) Sweep(ctx context.Context) { pm.sweep(ctx) }

// newPhantomManager opens the translator (creating or re-using the pinned
// maps) and loads the records of a previous agent run.
func newPhantomManager(a *Agent) (*phantomManager, error) {
	t, err := phantom.New(phantom.DefaultPinPath)
	if err != nil {
		return nil, err
	}
	if n, err := t.PruneDefunct(); err == nil && n > 0 {
		a.Log.Info("phantom: removed attachments of vanished interfaces", "count", n)
	}
	pm := &phantomManager{a: a, log: a.Log.With("component", "phantom"), t: t,
		records: map[types.UID]*phantomRecord{}, gc: map[types.UID]bool{}, released: map[types.UID]bool{},
		unroutableSent: map[unroutable]bool{}}
	if err := os.MkdirAll(phantomStateDir, 0o700); err != nil {
		return nil, err
	}
	entries, _ := os.ReadDir(phantomStateDir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(phantomStateDir, e.Name()))
		if err != nil {
			continue
		}
		r := &phantomRecord{}
		if json.Unmarshal(b, r) == nil && r.UID != "" {
			pm.records[r.UID] = r
		}
	}
	return pm, nil
}

func (pm *phantomManager) save(r *phantomRecord) error {
	return layout.WriteJSONAtomic(filepath.Join(phantomStateDir, string(r.UID)+".json"), r)
}

// sweep releases records whose migration no longer exists (deleted while
// the agent was down, or a new migration with the same name).
func (pm *phantomManager) sweep(ctx context.Context) {
	pm.mu.Lock()
	recs := make([]*phantomRecord, 0, len(pm.records))
	for _, r := range pm.records {
		recs = append(recs, r)
	}
	pm.mu.Unlock()
	for _, r := range recs {
		m := &v1.Migration{}
		err := pm.a.Client.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.Name}, m)
		if err == nil && m.UID == r.UID {
			continue
		}
		if err != nil && client.IgnoreNotFound(err) != nil {
			continue
		}
		pm.mu.Lock()
		pm.release(r, "migration gone")
		pm.mu.Unlock()
	}
}

// tr returns the translator, creating it after an idle cleanup.
func (pm *phantomManager) tr() (*phantom.Translator, error) {
	if pm.t == nil {
		t, err := phantom.New(phantom.DefaultPinPath)
		if err != nil {
			return nil, err
		}
		pm.t = t
	}
	return pm.t, nil
}

// harvestPhantom collects the frozen pod's connections and its listeners bound
// to the old IP (source, during the freeze). Classification needs the
// cluster's prefixes, computed by the controller at preflight.
func harvestPhantom(netns string, oldIP string, bound []netip.Addr, cidrs []string) (*v1.SourcePhantom, error) {
	old, err := netip.ParseAddr(oldIP)
	if err != nil {
		return nil, fmt.Errorf("old IP: %w", err)
	}
	// The current IP plus any earlier IP that sockets are still bound to
	// (connections that survived a previous Phantom migration).
	ips := []netip.Addr{old}
	for _, a := range bound {
		if a != old && a.Is4() == old.Is4() {
			ips = append(ips, a)
		}
	}
	var flows []phantom.Flow
	for _, ip := range ips {
		f, err := phantom.HarvestFlows(netns, ip)
		if err != nil {
			return nil, err
		}
		flows = append(flows, f...)
	}
	var nets []netip.Prefix
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			nets = append(nets, p)
		}
	}
	// The old node's conntrack table: where the pod's own connections to a
	// ClusterIP really go (kube-proxy DNAT) – "" is this (host) namespace.
	if flows, err = phantom.ResolveWithConntrack("", flows, nets); err != nil {
		return nil, err
	}
	flows = phantom.Classify(flows, nets)
	listeners, err := phantom.HarvestOldBoundListeners(netns, old)
	if err != nil {
		return nil, err
	}
	out := &v1.SourcePhantom{Flows: flowsToAPI(flows)}
	for _, p := range listeners {
		out.OldBoundListeners = append(out.OldBoundListeners, int32(p))
	}
	for _, f := range flows {
		if f.Class != phantom.ClassInCluster {
			out.Unsupported++
		}
	}
	return out, nil
}

// phantomCapability is published as node annotation paguro.dev/phantom:
// whether this node can translate (the controller picks Phantom mode only
// if every node can).
func phantomCapability(pm *phantomManager) string {
	if pm == nil {
		return "unavailable"
	}
	return "available"
}

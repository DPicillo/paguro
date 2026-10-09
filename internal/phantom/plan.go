// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
)

// Migration describes one pod migration in Phantom mode.
type Migration struct {
	// ID tags all rules of this migration (Rule.Owner). Use MigrationID.
	ID uint32
	// OldIP is the pod IP before the migration; the restored sockets keep
	// using it inside the pod.
	OldIP netip.Addr
	// NewIP is the IP the CNI assigned to the replacement pod.
	NewIP netip.Addr
	// NewNodeIP is the target node's tunnel endpoint. Only needed for
	// host-scope rules on collect_md overlay devices (FlagTunnel).
	NewNodeIP netip.Addr
}

// MigrationID derives a stable 32-bit owner id from a migration name
// (e.g. "<namespace>/<podmigration>").
func MigrationID(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	id := h.Sum32()
	if id == 0 {
		id = 1
	}
	return id
}

// FlowClass says where the peer of a flow lives.
type FlowClass uint8

const (
	// ClassInCluster: the wire peer is a pod or node address of this
	// cluster. Preserved by Phantom mode.
	ClassInCluster FlowClass = iota
	// ClassExternalDirect: the peer is outside the cluster and sees the
	// pod address directly (no SNAT; e.g. routable pod IPs on AWS VPC CNI
	// or BGP). Peer cannot be programmed: NOT preserved by Phantom mode.
	ClassExternalDirect
	// ClassExternalSNAT: the peer is outside the cluster and the old node
	// masqueraded the flow. NOT preserved by Phantom mode alone (needs the old
	// node as an anchor; see docs/PHANTOM-MODE.md, "External egress").
	ClassExternalSNAT
)

// Flow is one connection of the migrated pod, harvested at freeze time,
// in the pod's (inside) view.
type Flow struct {
	Proto Proto
	// Local is the pod's socket address (OldIP:port).
	Local netip.AddrPort
	// Remote is the peer address as the pod's socket sees it.
	Remote netip.AddrPort
	// Wire is the peer address on the wire when the old node rewrote it
	// (kube-proxy DNAT of a ClusterIP the pod connected to). Zero value:
	// same as Remote.
	Wire  netip.AddrPort
	Class FlowClass
	// Server is true when the migrated pod is the server side of the flow
	// (Local is a listening port), i.e. the peer chose its port. Decides
	// on which side the wire tuple is reserved (see reserve.go).
	Server bool
}

func (f Flow) wire() netip.AddrPort {
	if f.Wire.IsValid() {
		return f.Wire
	}
	return f.Remote
}

func (f Flow) String() string {
	s := fmt.Sprintf("%s %s<->%s", f.Proto, f.Local, f.Remote)
	if f.Wire.IsValid() && f.Wire != f.Remote {
		s += fmt.Sprintf(" (wire %s)", f.Wire)
	}
	return s
}

// PodEndpoint locates a pod interface on this node.
type PodEndpoint struct {
	Netns  string // netns path of the pod
	Ifname string // interface inside the pod (eth0)
	// HostIfname is the host-side veth (lxc*, cali*, ...), needed for the
	// migrated pod (host-local bypass) and for KindPodHostSide placement.
	HostIfname string
}

// NodeContext is what the agent knows about its own node.
type NodeContext struct {
	// IsTarget: this node runs the replacement pod.
	IsTarget bool
	// Migrated is the replacement pod's endpoint (IsTarget only).
	Migrated PodEndpoint
	// LocalPods maps pod IPs on this node to their endpoints.
	LocalPods map[netip.Addr]PodEndpoint
	// HostIPs are this node's own addresses (host network namespace).
	HostIPs map[netip.Addr]bool
	// HostDevices are the node devices that carry pod traffic (see
	// docs/PHANTOM-MODE.md "Host devices"). Host-scope rules need them.
	HostDevices []string
	// HostSidePlacement attaches pod programs to the host-side veth
	// (KindPodHostSide) instead of inside the pod netns.
	HostSidePlacement bool
	// ViaNetfilter reports whether a local pod peer reaches the old
	// address through a kernel DNAT (kube-proxy iptables/ipvs ClusterIP);
	// such flows need host-scope rules. Nil means "never" (Cilium with
	// socket-LB, or no Service in between).
	ViaNetfilter func(Flow) bool
	// Remap maps the OLD address of other active migrations to their NEW
	// address (a peer that was itself migrated). Nil means identity.
	Remap func(netip.Addr) (netip.Addr, bool)
	// Pending installs the migrated pod's inbound rules with FlagPending
	// (drop until ClearPending), so the rules can be programmed before
	// the CRIU restore completes.
	Pending bool
	// TunnelRewrite sets FlagTunnel on host-scope Out rules (collect_md
	// overlay devices where the CNI chose the tunnel endpoint before our
	// program runs).
	TunnelRewrite bool
	// OnLink reports whether an address is on-link inside a pod's network
	// namespace (no gateway). A local peer pod for which NEW is on-link
	// gets FlagNeigh. Nil means "never".
	OnLink func(netnsPath string, a netip.Addr) bool
	// SourceVerify: the CNI drops packets that leave a pod with a source
	// address other than the pod's (Antrea's SpoofGuard, Cilium).
	SourceVerify bool
}

// PlanResult is what one node must install for one migration.
type PlanResult struct {
	Rules       []Rule
	Attachments []Attachment
	// Reservations are client ports to reserve (ip_local_reserved_ports)
	// so no new connection can reuse a migrated flow's wire tuple.
	Reservations []Reservation
	// ConntrackReservations are wire tuples to block for netfilter NAT
	// (placeholder conntrack entries in the host netns of this node).
	ConntrackReservations []Tuple
	// Wire are the migrated flows' tuples on the wire at the target node
	// (peer -> new address); stale conntrack entries of them go before the
	// rules are installed (FlushStaleConntrack). Target node only.
	Wire []Tuple
	// Unsupported are flows Phantom mode cannot preserve (external peers).
	Unsupported []Flow
}

// Plan computes the rules and attachments one node needs. It is a pure
// function: every node computes its own share from the same flow list.
func Plan(m Migration, flows []Flow, ctx NodeContext) (PlanResult, error) {
	if !m.OldIP.IsValid() || !m.NewIP.IsValid() {
		return PlanResult{}, fmt.Errorf("phantom: migration needs OldIP and NewIP")
	}
	if m.OldIP.Is4() != m.NewIP.Is4() {
		return PlanResult{}, fmt.Errorf("phantom: OldIP and NewIP must be the same family")
	}
	pl := &planner{m: m, ctx: ctx, attach: map[Attachment]bool{}, resv: map[Reservation]bool{}}
	for _, f := range flows {
		if f.Local.Addr() != m.OldIP {
			return pl.res, fmt.Errorf("phantom: flow %v does not belong to %s", f, m.OldIP)
		}
		if f.Class != ClassInCluster {
			pl.res.Unsupported = append(pl.res.Unsupported, f)
			continue
		}
		pl.flow(f)
	}
	return pl.res, nil
}

// PlanFlows plans every flow on its own (so that a node can revert one
// ended connection), each translated from its own local address: after
// chained migrations the pod's sockets can be bound to any earlier address
// of the pod, and they keep it on every hop – m.OldIP, the address the pod
// had right before this hop, is only one of them.
func PlanFlows(m Migration, flows []Flow, ctx NodeContext) ([]PlanResult, error) {
	out := make([]PlanResult, 0, len(flows))
	for _, f := range flows {
		fm := m
		fm.OldIP = f.Local.Addr()
		p, err := Plan(fm, []Flow{f}, ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// planner is one run of Plan.
type planner struct {
	m      Migration
	ctx    NodeContext
	res    PlanResult
	attach map[Attachment]bool
	resv   map[Reservation]bool
}

// flow plans one in-cluster flow: the migrated pod's side (target node)
// and the peer's side (if the peer lives on this node).
//
// The pod may have come back to an address it held before, which this
// connection still uses (OLD == NEW): its rules are identities then – and
// must be installed anyway. Keyed by the same 5-tuples, they replace the
// previous migration's rules, which would still rewrite the connection to
// the pod's last address (measured: both clients reset). The datapath
// redirects only rewritten destinations (FlagNeigh), so an identity rule
// cannot loop.
func (pl *planner) flow(f Flow) {
	oldL := f.Local
	newL := netip.AddrPortFrom(pl.m.NewIP, f.Local.Port())
	peerInside := f.wire()           // the peer endpoint's own view of itself
	peerWire := pl.remap(peerInside) // the peer on the wire
	if pl.ctx.IsTarget {
		pl.migratedSide(f, oldL, newL, peerWire)
	}
	pl.peerSide(f, oldL, newL, peerInside, peerWire)
}

// migratedSide: the rules in the migrated pod (target node).
func (pl *planner) migratedSide(f Flow, oldL, newL, peerWire netip.AddrPort) {
	var fl Flags
	if pl.ctx.Pending {
		fl |= FlagPending
	}
	pl.res.Rules = append(pl.res.Rules,
		Rule{Scope: ScopePod, Dir: Out, Owner: pl.m.ID,
			Match:   Tuple{f.Proto, oldL, f.Remote},
			Rewrite: Tuple{f.Proto, newL, peerWire}},
		Rule{Scope: ScopePod, Dir: In, Owner: pl.m.ID, Flags: fl,
			Match:   Tuple{f.Proto, peerWire, newL},
			Rewrite: Tuple{f.Proto, f.Remote, oldL}},
	)
	pl.res.Wire = append(pl.res.Wire, Tuple{f.Proto, peerWire, newL})
	pl.podAttach(pl.ctx.Migrated)
	if !f.Server {
		// The pod initiated the flow: its new connections must not pick
		// the same local port towards the same peer.
		pl.reserve(pl.ctx.Migrated.Netns, f.Local.Port())
	}
}

// peerSide: the rules for the flow's peer, if it is a pod or the host on
// this node – in the peer pod, or at host scope when the peer is the host
// or a kernel DNAT sits between the peer and the old address.
func (pl *planner) peerSide(f Flow, oldL, newL, peerInside, peerWire netip.AddrPort) {
	ctx := pl.ctx
	peerAddr := peerInside.Addr()
	ep, isPod := ctx.LocalPods[peerAddr]
	if !isPod && ctx.LocalPods != nil && peerWire.Addr() != peerAddr {
		// The peer is itself a migrated pod: it is known locally by its
		// NEW address.
		ep, isPod = ctx.LocalPods[peerWire.Addr()]
	}
	isHost := ctx.HostIPs[peerAddr]
	if !isPod && !isHost {
		return
	}
	out := Rule{Dir: Out, Owner: pl.m.ID,
		Match:   Tuple{f.Proto, peerInside, oldL},
		Rewrite: Tuple{f.Proto, peerWire, newL}}
	in := Rule{Dir: In, Owner: pl.m.ID,
		Match:   Tuple{f.Proto, newL, peerWire},
		Rewrite: Tuple{f.Proto, oldL, peerInside}}
	if f.Server && isPod {
		// The peer pod initiated the flow and picked peerInside.Port.
		pl.reserve(ep.Netns, peerInside.Port())
	}
	if !isHost && (ctx.ViaNetfilter == nil || !ctx.ViaNetfilter(f)) {
		out.Scope, in.Scope = ScopePod, ScopePod
		// The peer routed OLD (through its gateway when OLD was on another
		// node); NEW is on its own segment when it runs on the target node.
		if ctx.OnLink != nil && newL.Addr().Is4() && !ctx.HostSidePlacement && ctx.OnLink(ep.Netns, newL.Addr()) {
			out.Flags |= FlagNeigh
		}
		pl.res.Rules = append(pl.res.Rules, out, in)
		pl.podAttach(ep)
		return
	}
	pl.hostScope(f, out, in, peerInside, peerWire, newL, isHost)
}

// hostScope: the peer's rules at host scope (a host socket, or a pod
// behind a kernel DNAT).
func (pl *planner) hostScope(f Flow, out, in Rule, peerInside, peerWire, newL netip.AddrPort, isHost bool) {
	ctx := pl.ctx
	if f.Server && isHost {
		// A host socket or netfilter SNAT (NodePort entry node) chose the
		// port: block it for both.
		pl.reserve("", peerInside.Port())
		// Not when the wire tuple is the connection's own again (the pod
		// came back to the address the connection was opened to): the
		// connection's own conntrack entry holds that tuple already, and a
		// placeholder cannot be created next to it – kube-proxy's NodePort
		// entry has the same reply tuple, the kernel refuses the second
		// entry. Measured on EKS (A→B→A, the pod got its first address
		// back): the failed placeholder failed the whole node, which was
		// never programmed, and its clients kept sending to the address of
		// the hop before.
		if out.Rewrite != out.Match {
			pl.res.ConntrackReservations = append(pl.res.ConntrackReservations, out.Rewrite)
		}
	}
	out.Scope, in.Scope = ScopeHost, ScopeHost
	out.Flags |= FlagReroute
	if ctx.TunnelRewrite && pl.m.NewNodeIP.IsValid() {
		out.Flags |= FlagTunnel
		out.TunnelRemote = pl.m.NewNodeIP
	}
	if ctx.IsTarget && isHost {
		// Host client on the target node: replies come straight out of the
		// migrated pod's veth into the host stack.
		in.Flags |= FlagLocal
		if ctx.Migrated.HostIfname != "" {
			pl.add(Attachment{Ifname: ctx.Migrated.HostIfname, Kind: KindHostLocal})
		}
	}
	if ctx.IsTarget && !isHost && ctx.Migrated.HostIfname != "" {
		// A local pod reaching the migrated pod through a DNAT on the target
		// node (kube-proxy, or Antrea's proxy in Open vSwitch): the reply
		// never crosses a host device, so the host-scope programs go on the
		// migrated pod's veth.
		if ctx.SourceVerify {
			// The CNI drops a reply that leaves the pod's port with OLD as
			// its source (measured with Antrea's SpoofGuard: the connection
			// hung). Hand it to the host stack instead, like a host
			// client's reply: the host routes it back through the gateway
			// port, which carries any source, and the CNI undoes its DNAT
			// there.
			in.Flags |= FlagLocal
			pl.add(Attachment{Ifname: ctx.Migrated.HostIfname, Kind: KindHostLocal})
		} else {
			pl.add(Attachment{Ifname: ctx.Migrated.HostIfname, Kind: KindHostDevice})
		}
	}
	pl.res.Rules = append(pl.res.Rules, out, in)
	for _, d := range ctx.HostDevices {
		pl.add(Attachment{Ifname: d, Kind: KindHostDevice})
	}
}

func (pl *planner) remap(a netip.AddrPort) netip.AddrPort {
	if pl.ctx.Remap == nil {
		return a
	}
	if n, ok := pl.ctx.Remap(a.Addr()); ok {
		return netip.AddrPortFrom(n, a.Port())
	}
	return a
}

func (pl *planner) add(a Attachment) {
	if !pl.attach[a] {
		pl.attach[a] = true
		pl.res.Attachments = append(pl.res.Attachments, a)
	}
}

func (pl *planner) podAttach(ep PodEndpoint) {
	if pl.ctx.HostSidePlacement {
		pl.add(Attachment{Ifname: ep.HostIfname, Kind: KindPodHostSide})
	} else {
		pl.add(Attachment{Netns: ep.Netns, Ifname: ep.Ifname, Kind: KindPod})
	}
}

func (pl *planner) reserve(netns string, port uint16) {
	r := Reservation{Netns: netns, Port: port}
	if !pl.resv[r] {
		pl.resv[r] = true
		pl.res.Reservations = append(pl.res.Reservations, r)
	}
}

// Apply installs a plan on this node in a safe order: attachments,
// reservations, then rules (a rule is only useful once its hooks exist).
func (t *Translator) Apply(p PlanResult) error {
	for _, a := range p.Attachments {
		if err := t.Attach(a); err != nil {
			return err
		}
	}
	if err := applyReservations(p, true); err != nil {
		return err
	}
	return t.Upsert(p.Rules...)
}

// Revert removes the rules and reservations of a plan (e.g. for flows the
// garbage collector found dead). Attachments stay; detach them when a pod
// has no flows left.
func (t *Translator) Revert(p PlanResult) error {
	return errors.Join(t.Delete(p.Rules...), applyReservations(p, false))
}

// RevertOwned is Revert for a plan of migration owner: rules that a later
// migration has taken over (same key, other owner) stay.
func (t *Translator) RevertOwned(owner uint32, p PlanResult) error {
	return errors.Join(t.DeleteOwned(owner, p.Rules...), applyReservations(p, false))
}

func applyReservations(p PlanResult, add bool) error {
	byNs := map[string][]uint16{}
	for _, r := range p.Reservations {
		byNs[r.Netns] = append(byNs[r.Netns], r.Port)
	}
	var errs []error
	for ns, ports := range byNs {
		if add {
			errs = append(errs, ReservePorts(ns, ports...))
		} else {
			errs = append(errs, ReleasePorts(ns, ports...))
		}
	}
	for _, w := range p.ConntrackReservations {
		if add {
			errs = append(errs, ReserveConntrack("", w))
		} else {
			errs = append(errs, ReleaseConntrack("", w))
		}
	}
	return errors.Join(errs...)
}

// PendingRules returns the rules whose FlagPending must be cleared once the
// restore completed (use with Translator.SetFlags(0, FlagPending, ...)).
func (p PlanResult) PendingRules() []Rule {
	var out []Rule
	for _, r := range p.Rules {
		if r.Flags&FlagPending != 0 {
			out = append(out, r)
		}
	}
	return out
}

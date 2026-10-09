// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
	"testing"
)

// Chained migrations, end to end at the level of the rule tables: every
// node of a small cluster installs what PlanFlows gives it for each hop
// (as the agent does), earlier hops are released by owner, and packets of
// every connection are pushed through the tables in both directions.

// simNode is a node's pair of translation maps (one map per direction,
// keyed by scope and match tuple, as in the datapath).
type simNode map[simKey]Rule

type simKey struct {
	s Scope
	d Direction
	m Tuple
}

func (n simNode) install(plans []PlanResult) {
	for _, p := range plans {
		for _, r := range p.Rules {
			n[simKey{r.Scope, r.Dir, r.Match}] = r // Upsert replaces
		}
	}
}

func (n simNode) deleteOwner(id uint32) {
	for k, r := range n {
		if r.Owner == id {
			delete(n, k)
		}
	}
}

func (n simNode) xlate(s Scope, d Direction, t Tuple) Tuple {
	if r, ok := n[simKey{s, d, t}]; ok {
		return r.Rewrite
	}
	return t
}

var (
	chainPort   = uint16(25565)
	clientPod1  = netip.MustParseAddr("192.168.67.49")
	clientPod2  = netip.MustParseAddr("192.168.72.98")
	clientHost  = netip.MustParseAddr("192.168.78.222") // NodePort entry node (masquerade)
	addrX       = netip.MustParseAddr("192.168.93.41")
	addrY       = netip.MustParseAddr("192.168.86.98")
	addrZ       = netip.MustParseAddr("192.168.93.52")
	clientsNode = "C"
)

// conn is one connection of the migrated pod: its socket-local address
// (kept on every hop) and the client.
type conn struct {
	local  netip.AddrPort
	client netip.AddrPort
	host   bool // the client is the host of node C (NodePort SNAT)
}

func (c conn) flow() Flow {
	return Flow{Proto: TCP, Local: c.local, Remote: c.client, Server: true}
}

type chain struct {
	t     *testing.T
	nodes map[string]simNode
	at    string     // node the pod runs on
	addr  netip.Addr // the pod's current address
	conns []conn
	hops  []Migration
	plans map[uint32]map[string][]PlanResult
	flows map[uint32][]Flow // what each hop harvested, in plan order
}

func newChain(t *testing.T, node string, addr netip.Addr) *chain {
	return &chain{t: t, at: node, addr: addr, plans: map[uint32]map[string][]PlanResult{}, flows: map[uint32][]Flow{},
		nodes: map[string]simNode{"A": {}, "B": {}, "C": {}, "D": {}}}
}

// connect opens a connection from a client on node C to the pod's current
// address (natively: no translation yet).
func (c *chain) connect(client netip.Addr, port uint16, host bool) {
	c.conns = append(c.conns, conn{local: netip.AddrPortFrom(c.addr, chainPort),
		client: netip.AddrPortFrom(client, port), host: host})
}

// remap mirrors phantomManager.remap: OLD->NEW of the other migrations that
// are still active (here: the earlier hops of the same pod).
func (c *chain) remap() func(netip.Addr) (netip.Addr, bool) {
	m := map[netip.Addr]netip.Addr{}
	for _, h := range c.hops {
		m[h.OldIP] = h.NewIP
	}
	return func(a netip.Addr) (netip.Addr, bool) { n, ok := m[a]; return n, ok }
}

// migrate moves the pod to node with address new: the target first, then
// every other node (each with its own view: node C has the clients).
func (c *chain) migrate(node string, new netip.Addr) Migration {
	c.t.Helper()
	id := uint32(len(c.hops) + 1)
	m := Migration{ID: id, OldIP: c.addr, NewIP: new}
	flows := make([]Flow, 0, len(c.conns))
	for _, k := range c.conns {
		flows = append(flows, k.flow())
	}
	c.plans[id] = map[string][]PlanResult{}
	c.flows[id] = flows
	for _, n := range []string{node, "A", "B", "C", "D"} {
		if _, done := c.plans[id][n]; done {
			continue
		}
		nc := NodeContext{Remap: c.remap(), HostDevices: []string{"eth0"},
			LocalPods: map[netip.Addr]PodEndpoint{}, HostIPs: map[netip.Addr]bool{}}
		if n == node {
			nc.IsTarget = true
			nc.Migrated = PodEndpoint{Netns: fmt.Sprintf("/run/netns/pod-hop%d", id), Ifname: "eth0", HostIfname: "eni1"}
		}
		if n == clientsNode {
			nc.LocalPods[clientPod1] = PodEndpoint{Netns: "/run/netns/c1", Ifname: "eth0"}
			nc.LocalPods[clientPod2] = PodEndpoint{Netns: "/run/netns/c2", Ifname: "eth0"}
			nc.HostIPs[clientHost] = true
		}
		plans, err := PlanFlows(m, flows, nc)
		if err != nil {
			c.t.Fatalf("hop %d on %s: %v", id, n, err)
		}
		c.plans[id][n] = plans
		c.nodes[n].install(plans)
	}
	c.hops = append(c.hops, m)
	c.at, c.addr = node, new
	return m
}

// release removes an earlier hop's rules on every node, by owner (as
// phantomManager.release does once its connections are gone on its target).
func (c *chain) release(m Migration) {
	for _, n := range c.nodes {
		n.deleteOwner(m.ID)
	}
	c.hops = slices.DeleteFunc(c.hops, func(h Migration) bool { return h.ID == m.ID })
}

// check pushes a packet of every connection through the tables in both
// directions: the client's socket and the pod's socket must see exactly
// their own tuples, and the wire only the pod's current address.
func (c *chain) check(when string) {
	c.t.Helper()
	for _, p := range c.problems() {
		c.t.Errorf("%s: %s", when, p)
	}
}

func (c *chain) problems() []string {
	var out []string
	pod, peer := c.nodes[c.at], c.nodes[clientsNode]
	for _, k := range c.conns {
		scope := ScopePod
		if k.host {
			scope = ScopeHost
		}
		// The client's socket is connected to the address it opened the
		// connection to, which is the pod socket's local address.
		up := peer.xlate(scope, Out, Tuple{TCP, k.client, k.local})
		if up.Dst.Addr() != c.addr {
			out = append(out, fmt.Sprintf("%v: client packet on the wire to %v, the pod is at %v", k.local, up.Dst, c.addr))
		}
		if got := pod.xlate(ScopePod, In, up); got != (Tuple{TCP, k.client, k.local}) {
			out = append(out, fmt.Sprintf("%v<-%v: pod socket gets %v", k.local, k.client, got))
		}
		down := pod.xlate(ScopePod, Out, Tuple{TCP, k.local, k.client})
		if down.Src.Addr() != c.addr {
			out = append(out, fmt.Sprintf("%v: reply on the wire from %v, the pod is at %v", k.local, down.Src, c.addr))
		}
		if got := peer.xlate(scope, In, down); got != (Tuple{TCP, k.local, k.client}) {
			out = append(out, fmt.Sprintf("%v->%v: client socket gets %v", k.local, k.client, got))
		}
	}
	return out
}

// conntrackOf returns node C's conntrack placeholders of a hop.
func (c *chain) conntrackOf(m Migration) []Tuple {
	var out []Tuple
	for _, p := range c.plans[m.ID][clientsNode] {
		out = append(out, p.ConntrackReservations...)
	}
	return out
}

// close ends a connection (its socket is gone on the pod).
func (c *chain) close(client netip.AddrPort) {
	c.conns = slices.DeleteFunc(c.conns, func(k conn) bool { return k.client == client })
}

// dropDead mirrors phantomManager.dropDead: a hop's target reports some of its
// flows ended (status.target.phantom.deadFlows), and every node removes their
// rules – only those the hop still owns (Translator.RevertOwned). byKey
// removes them by key alone, as before that rule.
func (c *chain) dropDead(m Migration, byKey bool, clients ...netip.AddrPort) {
	c.t.Helper()
	var idx []int
	for i, f := range c.flows[m.ID] {
		if slices.Contains(clients, f.Remote) {
			idx = append(idx, i)
		}
	}
	if len(idx) != len(clients) {
		c.t.Fatalf("hop %d did not harvest all of %v", m.ID, clients)
	}
	for name, n := range c.nodes {
		var gone []Rule
		for _, i := range idx {
			gone = append(gone, c.plans[m.ID][name][i].Rules...)
		}
		if !byKey {
			var err error
			gone, err = stillOwned(m.ID, gone, func(r Rule) (uint32, bool, error) {
				cur, ok := n[simKey{r.Scope, r.Dir, r.Match}]
				return cur.Owner, ok, nil
			})
			if err != nil {
				c.t.Fatal(err)
			}
		}
		for _, r := range gone {
			delete(n, simKey{r.Scope, r.Dir, r.Match})
		}
	}
}

// rulesFor returns node C's rules that match packets of a client.
func (c *chain) rulesFor(client netip.AddrPort) []Rule {
	var out []Rule
	for _, r := range c.nodes[clientsNode] {
		if r.Match.Src == client || r.Match.Dst == client {
			out = append(out, r)
		}
	}
	return out
}

func (c *chain) releaseAll(hops ...Migration) {
	for _, h := range hops {
		c.release(h)
		c.check(fmt.Sprintf("after releasing hop %d", h.ID))
	}
}

// A→B→C with new addresses: the connections opened before the first hop
// keep X on both ends, the one opened after it keeps Y.
func TestChainThreeNodes(t *testing.T) {
	c := newChain(t, "A", addrX)
	c.connect(clientPod1, 40001, false)
	c.connect(clientHost, 50001, true)
	c.check("before")
	h1 := c.migrate("B", addrY)
	c.check("hop 1")
	c.connect(clientPod2, 40002, false) // to Y, natively
	c.migrate("D", addrZ)
	c.check("hop 2")
	c.releaseAll(h1)
}

// A→B→A, the pod gets a new address on A (no reuse).
func TestChainBackToTheFirstNode(t *testing.T) {
	c := newChain(t, "A", addrX)
	c.connect(clientPod1, 40001, false)
	c.connect(clientPod2, 40002, false)
	c.connect(clientHost, 50001, true)
	h1 := c.migrate("B", addrY)
	c.check("hop 1")
	c.migrate("A", addrZ)
	c.check("hop 2")
	c.releaseAll(h1)
}

// A→B→A, and the CNI gives the pod its first address back (AWS VPC CNI
// after the IP cooldown): the connections from before the first hop are on
// the wire with their own tuples again – identity rules replace the first
// hop's on node C – and the one opened during the first hop is translated
// from Y to X. No conntrack placeholder for a tuple that the connection's
// own entry holds.
func TestChainBackToTheFirstAddress(t *testing.T) {
	c := newChain(t, "A", addrX)
	c.connect(clientPod1, 40001, false)
	c.connect(clientHost, 50001, true)
	h1 := c.migrate("B", addrY)
	c.connect(clientPod2, 40002, false) // to Y, natively
	c.connect(clientHost, 50002, true)  // NodePort to Y
	c.check("hop 1")
	h2 := c.migrate("A", addrX)
	c.check("hop 2")

	want := []Tuple{{TCP, ap("192.168.78.222:50002"), ap("192.168.93.41:25565")}}
	if got := c.conntrackOf(h2); !slices.Equal(got, want) {
		t.Errorf("node C, hop 2: conntrack placeholders %v, want only %v", got, want)
	}
	if got := c.conntrackOf(h1); len(got) != 1 || got[0] != (Tuple{TCP, ap("192.168.78.222:50001"), ap("192.168.86.98:25565")}) {
		t.Errorf("node C, hop 1: conntrack placeholders %v", got)
	}
	// The identity rules carry the second hop's id: releasing the first
	// hop leaves them.
	for _, r := range c.nodes[clientsNode] {
		if r.Match.Dst == ap("192.168.93.41:25565") && r.Dir == Out && r.Owner != h2.ID {
			t.Errorf("node C: %v not taken over by hop 2", r)
		}
	}
	c.releaseAll(h1)
}

// X→Y→Z→Y: the pod comes back to an address that was on the wire for the
// connections from before the first hop and that the connection opened
// during the first hop is bound to.
func TestChainBackToAnEarlierWireAddress(t *testing.T) {
	c := newChain(t, "A", addrX)
	c.connect(clientPod1, 40001, false)
	c.connect(clientHost, 50001, true)
	h1 := c.migrate("B", addrY)
	c.connect(clientPod2, 40002, false)
	c.connect(clientHost, 50002, true)
	h2 := c.migrate("A", addrZ)
	c.check("hop 2")
	h3 := c.migrate("B", addrY)
	c.check("hop 3")
	for _, w := range c.conntrackOf(h3) {
		if w == (Tuple{TCP, ap("192.168.78.222:50002"), ap("192.168.86.98:25565")}) {
			t.Errorf("node C, hop 3: placeholder %v for a connection that is on the wire as itself", w)
		}
	}
	c.releaseAll(h1, h2)
}

// The placeholder is refreshed when it is there, and a tuple that another
// entry holds in its reply direction counts as reserved.
func TestConntrackPlaceholderTakenTuple(t *testing.T) {
	cases := []struct {
		name           string
		create, update []error
		want           error
		creates        int
	}{
		{"created", []error{nil}, nil, nil, 1},
		{"refreshed", []error{syscall.EEXIST}, []error{nil}, nil, 1},
		{"taken by a NAT entry", []error{syscall.EEXIST, syscall.EEXIST}, []error{syscall.ENOENT, syscall.ENOENT}, nil, 2},
		{"gone in between", []error{syscall.EEXIST, nil}, []error{syscall.ENOENT}, nil, 2},
		{"other error", []error{syscall.EPERM}, nil, syscall.EPERM, 1},
		{"update fails", []error{syscall.EEXIST}, []error{syscall.EINVAL}, syscall.EINVAL, 1},
	}
	for _, c := range cases {
		ci, ui := 0, 0
		err := placeholder(
			func() error { ci++; return c.create[ci-1] },
			func() error { ui++; return c.update[ui-1] })
		if !errors.Is(err, c.want) || (c.want == nil && err != nil) || ci != c.creates {
			t.Errorf("%s: err %v after %d creates, want %v after %d", c.name, err, ci, c.want, c.creates)
		}
	}
}

// The previous hop's target reports flows ended after the next hop took
// them over: when the pod moves on, its sockets on that target go away
// with the next hop's source, and its garbage collector may see some of
// them gone in one tick and the rest in the next. Removing the reported
// flows' rules by key would remove the next hop's rules for the same
// connections; only the previous hop's own rules may go. A connection
// that really ended during the previous hop loses its rules as before.
func TestChainPreviousHopReportsTakenOverFlowsDead(t *testing.T) {
	ended := ap("192.168.67.49:40009")
	for _, tt := range []struct {
		name string
		hops []netip.Addr // addresses of the hops after X
		// byKeyBreaks: removing by key breaks taken-over connections. Not
		// when the pod is back at their address: the later hop's rules
		// are identities there, and losing one changes nothing.
		byKeyBreaks bool
	}{
		{"A->B->C", []netip.Addr{addrY, addrZ}, true},
		{"A->B->A, first address back", []netip.Addr{addrY, addrX}, false},
		{"X->Y->Z->Y", []netip.Addr{addrY, addrZ, addrY}, true},
	} {
		for _, byKey := range []bool{false, true} {
			name := tt.name
			if byKey {
				name += " (by key)"
			}
			c := newChain(t, "A", addrX)
			c.connect(clientPod1, 40001, false)
			c.connect(clientHost, 50001, true)
			c.connect(ended.Addr(), ended.Port(), false)
			nodes := []string{"B", "A", "B"}
			h1 := c.migrate(nodes[0], tt.hops[0])
			c.connect(clientPod2, 40002, false)
			c.close(ended)
			for i, a := range tt.hops[1:] {
				c.migrate(nodes[i+1], a)
			}
			c.check(name + ": before")
			// Hop 1 reports, late, the connection that ended during it and
			// two that the later hops took over.
			c.dropDead(h1, byKey, ended, ap("192.168.67.49:40001"), ap("192.168.78.222:50001"))
			if byKey {
				// The negative control: the old way breaks the chain.
				if broke := len(c.problems()) > 0; broke != tt.byKeyBreaks {
					t.Errorf("%s: connections broken: %v, want %v", name, broke, tt.byKeyBreaks)
				}
				continue
			}
			c.check(name + ": after hop 1 reported flows dead")
			if rs := c.rulesFor(ended); len(rs) != 0 {
				t.Errorf("%s: node C keeps rules of the ended connection: %v", name, rs)
			}
		}
	}
}

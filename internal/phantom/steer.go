// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Steering: only the migrated connections take the routes of SteerTable
// (route.go). New connections to an old address – a pod that received it
// later – take the CNI's routes.
//
// A flow is steered by the tuple the kernel routes it by: for a host
// socket its own; for a pod behind a kernel DNAT (kube-proxy ClusterIP) the
// destination after the DNAT – routing comes after PREROUTING; for a
// NodePort entry node the source before the masquerade – routing comes
// before POSTROUTING (RoutingTuples).
//
// The kernel walks its policy rules one by one for every route lookup, and
// a node forwards a route lookup's worth of packets for every pod on it. A
// rule per flow would make every forwarded packet of the node – also of
// pods that have nothing to do with the migration – walk all of them: a
// database migrated with a few thousand pooled connections from the pods of
// one node would cost each packet that node forwards thousands of rule
// matches, for as long as the connections live. So the number of rules a
// forwarded packet passes does not grow with the flows:
//
//   - Forwarded flows (host namespace: pods behind a ClusterIP, NodePort
//     clients on their entry node) are steered by a bit of the packet mark.
//     An nftables set of Paguro's own table holds their tuples; a
//     prerouting chain (after the DNAT, before routing) sets the bit on
//     their packets – one hash lookup – and one rule per address family
//     (fwmark → SteerTable, SteerMarkPriority) selects the table. A chain in
//     the forward hook clears the bit again right after routing, so that
//     nothing downstream (the CNI's programs, tunnels, other rules) sees it.
//   - Flows of local sockets – host sockets, and every flow in a peer pod's
//     namespace – keep one rule per flow (SteerPriority): their route is
//     looked up before any netfilter hook, by the socket itself (with
//     Calico, the old node's blackhole for the old block refuses that
//     lookup, and the packet never reaches a hook that could mark it). In a
//     host namespace a gate before them (SteerGatePriority: everything not
//     from a local socket jumps to SteerMarkPriority) keeps forwarded
//     packets from walking them; only route lookups of the host's own
//     sockets do. In a pod's namespace the rules cost only that pod.
//
// The rules with ports exist since Linux 4.17; the kernel dissects the
// ports of the packets it routes while one exists. Should nftables not be
// usable, forwarded flows are steered by a rule each, as local ones are.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// SteerGatePriority: forwarded packets jump over the per-flow rules.
	SteerGatePriority = SteerPriority - 1
	// SteerMarkPriority: the rule that selects SteerTable for marked packets.
	SteerMarkPriority = SteerPriority + 1

	// DefaultSteerMark is the bit of the packet mark that steers forwarded
	// flows. Outside the bits kube-proxy (0x4000 masquerade, 0x8000 drop),
	// Cilium (0x0F00 and 0x1E00 magic values, identities in the upper 16 bits
	// and the low byte), the AWS VPC CNI (0x80) and Calico (its default mask
	// 0xffff0000) use. It is set only between the prerouting chain and the
	// routing decision, and only on packets of migrated connections.
	DefaultSteerMark uint32 = 0x2000

	// steerNftTable is Paguro's nftables table (family inet) in a node's host
	// namespace while forwarded flows are steered.
	steerNftTable = "paguro_phantom_steer"
	// steerRefresh: the table is written again at least this often while it
	// is needed (it may have been flushed – a firewall reload).
	steerRefresh = 25 * time.Second
)

// Steering keeps Paguro's steering in network namespaces. Not safe for
// concurrent use.
type Steering struct {
	// Mark is the bit (or bits) of the packet mark that steers forwarded
	// flows; 0 means DefaultSteerMark.
	Mark uint32
	// Run runs nft; nil means ExecRunner.
	Run Runner
	// nft: per namespace, what is known of Paguro's table.
	nft map[string]*nftState
}

// nftState is what is known of Paguro's nftables table in a namespace.
type nftState struct {
	// known: whether there is a table (present) is known.
	known, present bool
	// script, at, fwd: the table written last, when, and for which flows.
	script string
	at     time.Time
	fwd    []Tuple
	// failed, failedAt, err: the last write or removal that failed.
	failed   string
	failedAt time.Time
	err      error
}

func (s *Steering) state(netnsPath string) *nftState {
	if s.nft == nil {
		s.nft = map[string]*nftState{}
	}
	st := s.nft[netnsPath]
	if st == nil {
		st = &nftState{}
		s.nft[netnsPath] = st
	}
	return st
}

func (s *Steering) mark() uint32 {
	if s.Mark == 0 {
		return DefaultSteerMark
	}
	return s.Mark
}

// Sync makes Paguro's steering in netnsPath ("" = this namespace) exactly
// want – those of want whose old address has a route in SteerTable there:
// where the CNI's own route takes the old address (EnsureOffLinkRoute),
// steering would only cost time. host: netnsPath is a node's host
// namespace, where flows from other sources than its own addresses are
// forwarded and steered by the mark.
func (s *Steering) Sync(netnsPath string, host bool, want []Tuple) error {
	return s.sync(netnsPath, host, want, false)
}

// Extend is Sync that removes nothing: what is steered stays, want is
// added. For a want that may be incomplete or wrong – the conntrack table
// that maps flows to the tuples the kernel routes them by could not be read.
func (s *Steering) Extend(netnsPath string, host bool, want []Tuple) error {
	return s.sync(netnsPath, host, want, true)
}

func (s *Steering) sync(netnsPath string, host bool, want []Tuple, keep bool) error {
	var cur steerState
	if err := inNetns(netnsPath, func() (err error) { cur, err = readSteering(host); return err }); err != nil {
		return err
	}
	want = slices.DeleteFunc(slices.Clone(want), func(t Tuple) bool { return !cur.steered[t.Dst.Addr().Unmap()] })
	local, fwd := want, []Tuple(nil)
	if host {
		local, fwd = splitLocal(want, cur.local)
	}
	if keep {
		local = union(local, cur.flows)
		if st := s.nft[netnsPath]; st != nil && st.present {
			fwd = union(fwd, st.fwd)
		}
	}
	gated := host
	var errs []error
	if len(fwd) > 0 {
		if err := s.writeNft(netnsPath, fwd); err != nil {
			// Steered as local flows are: a rule each, no gate.
			errs = append(errs, fmt.Errorf("phantom: forwarded connections steered by a rule each – nftables: %w", err))
			local, fwd, gated = want, nil, false
		}
	}
	mark := s.mark()
	if err := inNetns(netnsPath, func() error { return syncSteerRules(cur, local, fwd, gated, mark) }); err != nil {
		errs = append(errs, err)
	}
	if host && len(fwd) == 0 {
		if err := s.removeNft(netnsPath); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// steerState is what a namespace has of Paguro's steering.
type steerState struct {
	// steered: old addresses with a route in SteerTable.
	steered map[netip.Addr]bool
	// local: the namespace's own addresses (host namespaces only).
	local map[netip.Addr]bool
	// flows: the per-flow rules; gates and marks: the gate and the mark
	// rules, by family.
	flows []Tuple
	gates map[int][]netlink.Rule
	marks map[int][]netlink.Rule
}

var steerFamilies = []int{netlink.FAMILY_V4, netlink.FAMILY_V6}

func readSteering(host bool) (steerState, error) {
	st := steerState{steered: map[netip.Addr]bool{}, local: map[netip.Addr]bool{},
		gates: map[int][]netlink.Rule{}, marks: map[int][]netlink.Rule{}}
	for _, fam := range steerFamilies {
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: SteerTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return st, fmt.Errorf("phantom: listing routes: %w", err)
		}
		for _, r := range routes {
			if r.Dst == nil {
				continue
			}
			if a, ok := hostAddr(r.Dst); ok {
				st.steered[a] = true
			}
		}
		rules, err := netlink.RuleList(fam)
		if err != nil {
			return st, fmt.Errorf("phantom: listing rules: %w", err)
		}
		for _, r := range rules {
			switch {
			case isSteerGate(r):
				st.gates[fam] = append(st.gates[fam], r)
			case isSteerMarkRule(r):
				st.marks[fam] = append(st.marks[fam], r)
			default:
				if t, ok := steerTupleOf(r); ok {
					st.flows = append(st.flows, t)
				}
			}
		}
	}
	if host {
		addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
		if err != nil {
			return st, fmt.Errorf("phantom: listing addresses: %w", err)
		}
		for _, a := range addrs {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				st.local[ip.Unmap()] = true
			}
		}
	}
	return st, nil
}

// union returns a with the tuples of b it lacks.
func union(a, b []Tuple) []Tuple {
	out := slices.Clone(a)
	for _, t := range b {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// splitLocal separates the flows of local sockets (their source is an
// address of the namespace) from forwarded ones.
func splitLocal(want []Tuple, local map[netip.Addr]bool) (own, fwd []Tuple) {
	for _, t := range want {
		if local[t.Src.Addr().Unmap()] {
			own = append(own, t)
		} else {
			fwd = append(fwd, t)
		}
	}
	return own, fwd
}

func familyOf(t Tuple) int {
	if t.Dst.Addr().Unmap().Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// syncSteerRules makes the namespace's rules local (one per flow) plus, for
// every family with steering when gated, the gate and the mark rule.
// Additions come first, so that a flow is never without its rule while it
// changes from one kind of steering to the other.
func syncSteerRules(cur steerState, local, fwd []Tuple, gated bool, mark uint32) error {
	needs := map[int]bool{}
	if gated {
		for _, t := range slices.Concat(local, fwd) {
			needs[familyOf(t)] = true
		}
	}
	var errs []error
	add := func(r *netlink.Rule, what string) {
		if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			errs = append(errs, fmt.Errorf("phantom: %s: %w", what, err))
		}
	}
	del := func(r *netlink.Rule, what string) {
		if err := netlink.RuleDel(r); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("phantom: removing %s: %w", what, err))
		}
	}
	for _, fam := range steerFamilies {
		if !needs[fam] {
			continue
		}
		if !slices.ContainsFunc(cur.marks[fam], func(r netlink.Rule) bool { return markOf(r) == mark }) {
			add(steerMarkRule(fam, mark), "mark rule")
		}
		if len(cur.gates[fam]) == 0 {
			add(steerGate(fam), "gate rule")
		}
	}
	addFlows, delFlows := steerDiff(cur.flows, local)
	for _, t := range addFlows {
		add(steerRule(t), fmt.Sprintf("rule for %v", t))
	}
	for _, t := range delFlows {
		del(steerRule(t), fmt.Sprintf("rule for %v", t))
	}
	for _, fam := range steerFamilies {
		for _, r := range cur.gates[fam] {
			if !needs[fam] {
				del(&r, "gate rule")
			}
		}
		for _, r := range cur.marks[fam] {
			if !needs[fam] || markOf(r) != mark {
				del(&r, "mark rule")
			}
		}
	}
	return errors.Join(errs...)
}

// steerRule is the rule for one routing tuple.
func steerRule(t Tuple) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = familyOf(t)
	r.Priority = SteerPriority
	r.Table = SteerTable
	r.Src = prefixOf(t.Src.Addr().Unmap())
	r.Dst = prefixOf(t.Dst.Addr().Unmap())
	r.IPProto = int(t.Proto)
	r.Sport = netlink.NewRulePortRange(t.Src.Port(), t.Src.Port())
	r.Dport = netlink.NewRulePortRange(t.Dst.Port(), t.Dst.Port())
	r.Protocol = uint8(RouteProtocol)
	return r
}

// steerGate: whatever is not a local socket's route lookup jumps over the
// per-flow rules to the mark rule ("not iif lo goto SteerMarkPriority").
func steerGate(fam int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = fam
	r.Priority = SteerGatePriority
	r.IifName = "lo"
	r.Invert = true
	r.Goto = SteerMarkPriority
	r.Protocol = uint8(RouteProtocol)
	return r
}

// steerMarkRule selects SteerTable for packets with the mark.
func steerMarkRule(fam int, mark uint32) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = fam
	r.Priority = SteerMarkPriority
	r.Table = SteerTable
	r.Mark = mark
	r.Mask = &mark
	r.Protocol = uint8(RouteProtocol)
	return r
}

func isSteerGate(r netlink.Rule) bool {
	return r.Priority == SteerGatePriority && r.Protocol == uint8(RouteProtocol) && r.Goto == SteerMarkPriority
}

func isSteerMarkRule(r netlink.Rule) bool {
	return r.Priority == SteerMarkPriority && r.Protocol == uint8(RouteProtocol) && r.Table == SteerTable
}

// markOf: the mark a mark rule matches (all bits of its mask set).
func markOf(r netlink.Rule) uint32 {
	if r.Mask == nil || *r.Mask != r.Mark {
		return 0
	}
	return r.Mark
}

// steerTupleOf reads a rule back; ok only for Paguro's steering rules.
func steerTupleOf(r netlink.Rule) (Tuple, bool) {
	if r.Table != SteerTable || r.Priority != SteerPriority || r.Src == nil || r.Dst == nil || r.Sport == nil || r.Dport == nil {
		return Tuple{}, false
	}
	src, ok1 := hostAddr(r.Src)
	dst, ok2 := hostAddr(r.Dst)
	if !ok1 || !ok2 || r.Sport.Start != r.Sport.End || r.Dport.Start != r.Dport.End {
		return Tuple{}, false
	}
	return Tuple{Proto(r.IPProto), netip.AddrPortFrom(src, r.Sport.Start), netip.AddrPortFrom(dst, r.Dport.Start)}, true
}

// hostAddr: the address of a /32 or /128.
func hostAddr(n *net.IPNet) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	ones, bits := n.Mask.Size()
	return a, ones == bits && ones == a.BitLen()
}

// steerDiff returns the rules to add and to remove.
func steerDiff(have, want []Tuple) (add, del []Tuple) {
	haveSet := make(map[Tuple]bool, len(have))
	for _, t := range have {
		haveSet[t] = true
	}
	wantSet := make(map[Tuple]bool, len(want))
	for _, t := range want {
		if !haveSet[t] && !wantSet[t] {
			add = append(add, t)
		}
		wantSet[t] = true
	}
	seen := map[Tuple]bool{}
	for _, t := range have {
		if !wantSet[t] && !seen[t] {
			del = append(del, t)
		}
		seen[t] = true
	}
	return add, del
}

// steerRuleset renders Paguro's nftables table for the forwarded flows fwd
// (one atomic transaction, nft -f): the sets of their tuples, the chain that
// marks their packets before routing and the one that clears the mark after
// it.
func steerRuleset(mark uint32, fwd []Tuple) string {
	var b strings.Builder
	t := steerNftTable
	fmt.Fprintf(&b, "add table inet %s\n", t)
	fmt.Fprintf(&b, "add set inet %s v4 { type inet_proto . ipv4_addr . inet_service . ipv4_addr . inet_service; }\n", t)
	fmt.Fprintf(&b, "add set inet %s v6 { type inet_proto . ipv6_addr . inet_service . ipv6_addr . inet_service; }\n", t)
	// After the DNAT (dstnat = -100): the header the routing decision sees.
	fmt.Fprintf(&b, "add chain inet %s steer { type filter hook prerouting priority 100; policy accept; }\n", t)
	// Right after routing, before every other chain of the forward hook.
	fmt.Fprintf(&b, "add chain inet %s unsteer { type filter hook forward priority -300; policy accept; }\n", t)
	fmt.Fprintf(&b, "flush chain inet %s steer\nflush chain inet %s unsteer\n", t, t)
	fmt.Fprintf(&b, "flush set inet %s v4\nflush set inet %s v6\n", t, t)
	for _, f := range []struct{ ip, set string }{{"ip", "v4"}, {"ip6", "v6"}} {
		key := fmt.Sprintf("meta l4proto . %[1]s saddr . th sport . %[1]s daddr . th dport @%[2]s", f.ip, f.set)
		fmt.Fprintf(&b, "add rule inet %s steer %s meta mark set meta mark | 0x%08x\n", t, key, mark)
		fmt.Fprintf(&b, "add rule inet %s unsteer %s meta mark set meta mark & 0x%08x\n", t, key, ^mark)
	}
	elems := map[string][]string{}
	for _, f := range fwd {
		set := "v4"
		if familyOf(f) == netlink.FAMILY_V6 {
			set = "v6"
		}
		elems[set] = append(elems[set], fmt.Sprintf("%d . %s . %d . %s . %d",
			f.Proto, f.Src.Addr().Unmap(), f.Src.Port(), f.Dst.Addr().Unmap(), f.Dst.Port()))
	}
	for _, set := range []string{"v4", "v6"} {
		e := elems[set]
		slices.Sort(e)
		e = slices.Compact(e)
		for len(e) > 0 {
			n := min(len(e), 256)
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", t, set, strings.Join(e[:n], ", "))
			e = e[n:]
		}
	}
	return b.String()
}

func (s *Steering) runner() Runner {
	if s.Run == nil {
		return ExecRunner
	}
	return s.Run
}

// nft runs nft in netnsPath ("" = the runner's own namespace).
func (s *Steering) nftIn(netnsPath, stdin string, args ...string) (string, error) {
	if netnsPath == "" {
		return s.runner()(stdin, "nft", args...)
	}
	return s.runner()(stdin, "nsenter", append([]string{"--net=" + netnsPath, "nft"}, args...)...)
}

// writeNft writes the table for fwd – unless exactly that table was written
// within steerRefresh. A failed write is not retried before steerRefresh
// either: the flows are steered by rules meanwhile.
func (s *Steering) writeNft(netnsPath string, fwd []Tuple) error {
	script := steerRuleset(s.mark(), fwd)
	st := s.state(netnsPath)
	if st.present && st.script == script && time.Since(st.at) < steerRefresh {
		return nil
	}
	if st.failed == script && time.Since(st.failedAt) < steerRefresh {
		return st.err
	}
	if _, err := s.nftIn(netnsPath, script, "-f", "-"); err != nil {
		// nft -f is one transaction: the table is as it was.
		st.failed, st.failedAt, st.err = script, time.Now(), err
		return err
	}
	*st = nftState{known: true, present: true, script: script, at: time.Now(), fwd: slices.Clone(fwd)}
	return nil
}

// removeNft deletes the table if there may be one: written by this process,
// or left by a previous one (the first call). A failed removal is retried
// after steerRefresh.
func (s *Steering) removeNft(netnsPath string) error {
	const removal = "delete"
	st := s.state(netnsPath)
	if st.known && !st.present {
		return nil
	}
	if st.failed == removal && time.Since(st.failedAt) < steerRefresh {
		return nil // reported already
	}
	out, err := s.nftIn(netnsPath, "", "delete", "table", "inet", steerNftTable)
	if err != nil && (strings.Contains(out, "No such file") || strings.Contains(out, "does not exist")) {
		err = nil
	}
	if err != nil {
		if !st.known {
			// Nothing this process wrote; a table a previous one left stays.
			st.known = true
		}
		st.failed, st.failedAt, st.err = removal, time.Now(), err
		return fmt.Errorf("phantom: removing the steering table: %w", err)
	}
	*st = nftState{known: true}
	return nil
}

// RoutingTuples maps the tuples of host-scope flows as the host programs
// see them (Rule.Match of an Out rule: after every NAT of this node) to the
// tuples the kernel routes them by, from this namespace's conntrack table:
// the destination after DNAT (the reply's source) and the source before
// SNAT (the original source). A flow without a conntrack entry is missing
// from the map: it is routed by its own tuple. After an error the map holds
// what could be read (an interrupted dump: what came before the
// interruption), and a missing flow says nothing.
func RoutingTuples(ts []Tuple) (map[Tuple]Tuple, error) {
	orig, err := OriginalTuples(ts)
	out := make(map[Tuple]Tuple, len(orig))
	for t, o := range orig {
		out[t] = Tuple{t.Proto, o.Src, t.Dst}
	}
	return out, err
}

// OriginalTuples returns, for those of ts that have a conntrack entry in
// this namespace, the entry's original tuple: what the connection's socket
// sees (its source before SNAT, its destination before DNAT – a ClusterIP).
// ts are tuples after every NAT of this node, as in RoutingTuples; errors
// as there.
func OriginalTuples(ts []Tuple) (map[Tuple]Tuple, error) {
	if len(ts) == 0 {
		return map[Tuple]Tuple{}, nil
	}
	var entries []ctPair
	var errs []error
	for _, fam := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		list, err := netlink.ConntrackTableList(netlink.ConntrackTable, fam)
		if err != nil {
			errs = append(errs, fmt.Errorf("phantom: conntrack dump: %w", err))
		}
		for _, c := range list {
			osrc, ok1 := addrPort(c.Forward.SrcIP, c.Forward.SrcPort)
			odst, ok2 := addrPort(c.Forward.DstIP, c.Forward.DstPort)
			rs, ok3 := addrPort(c.Reverse.SrcIP, c.Reverse.SrcPort)
			rd, ok4 := addrPort(c.Reverse.DstIP, c.Reverse.DstPort)
			if ok1 && ok2 && ok3 && ok4 {
				entries = append(entries, ctPair{Tuple{Proto(c.Forward.Protocol), osrc, odst}, Tuple{Proto(c.Reverse.Protocol), rs, rd}})
			}
		}
	}
	return originals(ts, entries), errors.Join(errs...)
}

// ctPair is one conntrack entry: its original and its reply tuple.
type ctPair struct {
	orig, reply Tuple
}

func originals(ts []Tuple, entries []ctPair) map[Tuple]Tuple {
	byReply := map[Tuple]Tuple{}
	for _, e := range entries {
		byReply[e.reply] = e.orig
	}
	out := map[Tuple]Tuple{}
	for _, t := range ts {
		if o, ok := byReply[t.Reverse()]; ok {
			out[t] = o
		}
	}
	return out
}

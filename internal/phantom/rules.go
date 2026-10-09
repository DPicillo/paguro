// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Scope selects which programs apply a rule.
type Scope uint8

const (
	// ScopePod rules are applied at pod interfaces (xl_pod_out/xl_pod_in).
	ScopePod Scope = 1
	// ScopeHost rules are applied at node devices (xl_host_*) for the host
	// network stack: host-network clients and NAT done by netfilter.
	ScopeHost Scope = 2
)

// Direction of a rule relative to the endpoint.
type Direction uint8

const (
	// Out rules match packets leaving the endpoint (inside view) and
	// rewrite them to the wire tuple.
	Out Direction = 1
	// In rules match packets arriving at the endpoint (wire view) and
	// rewrite them to the inside tuple.
	In Direction = 2
)

// Flags modify how a rule is applied.
type Flags uint32

const (
	// FlagPending drops matching inbound packets (pod scope): the restored
	// socket does not exist yet; the peer retransmits.
	FlagPending Flags = 1 << 0
	// FlagReroute: after rewriting the destination at a host device egress,
	// re-run the FIB lookup and redirect if the next hop changed.
	FlagReroute Flags = 1 << 1
	// FlagLocal: host-scope In rule served by xl_host_local on the migrated
	// pod's host-side veth (host endpoint on the target node).
	FlagLocal Flags = 1 << 2
	// FlagTunnel: rewrite the collect_md tunnel remote to TunnelRemote.
	FlagTunnel Flags = 1 << 3
	// FlagNeigh: inside a pod, after rewriting the destination, address the
	// frame to the next hop of the new destination (IPv4).
	FlagNeigh Flags = 1 << 4
)

// Proto is the L4 protocol.
type Proto uint8

const (
	TCP Proto = unix.IPPROTO_TCP
	UDP Proto = unix.IPPROTO_UDP
)

func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return fmt.Sprintf("proto%d", uint8(p))
}

// Tuple is a directed 5-tuple (as seen in one packet).
type Tuple struct {
	Proto Proto
	Src   netip.AddrPort
	Dst   netip.AddrPort
}

// Reverse returns the tuple of packets in the opposite direction.
func (t Tuple) Reverse() Tuple { return Tuple{t.Proto, t.Dst, t.Src} }

func (t Tuple) String() string { return fmt.Sprintf("%s %s->%s", t.Proto, t.Src, t.Dst) }

func (t Tuple) valid() error {
	if !t.Src.IsValid() || !t.Dst.IsValid() {
		return fmt.Errorf("invalid tuple %v", t)
	}
	if t.Src.Addr().Unmap().Is4() != t.Dst.Addr().Unmap().Is4() {
		return fmt.Errorf("mixed address families in %v", t)
	}
	if t.Proto != TCP && t.Proto != UDP {
		return fmt.Errorf("unsupported protocol in %v", t)
	}
	return nil
}

// Rule is one exact-match rewrite.
type Rule struct {
	Scope        Scope
	Dir          Direction
	Match        Tuple
	Rewrite      Tuple
	Flags        Flags
	TunnelRemote netip.Addr // IPv4 node address for FlagTunnel
	Owner        uint32     // migration id, used for bulk removal
}

func (r Rule) String() string {
	s := "pod"
	if r.Scope == ScopeHost {
		s = "host"
	}
	d := "out"
	if r.Dir == In {
		d = "in"
	}
	return fmt.Sprintf("%s/%s %v => %v flags=%#x owner=%d", s, d, r.Match, r.Rewrite, r.Flags, r.Owner)
}

// RuleState is a rule plus its datapath counters.
type RuleState struct {
	Rule
	Packets uint64
	// Idle is the time since the datapath last hit the rule (resolution
	// ~1s). Zero LastSeen means "never".
	Idle     time.Duration
	LastSeen uint64
}

func putAddr(dst *[16]uint8, a netip.Addr) {
	a = a.Unmap()
	*dst = [16]uint8{}
	if a.Is4() {
		b := a.As4()
		copy(dst[:4], b[:])
	} else {
		b := a.As16()
		copy(dst[:], b[:])
	}
}

func getAddr(src [16]uint8, family uint8) netip.Addr {
	if family == 4 {
		return netip.AddrFrom4([4]byte(src[:4]))
	}
	return netip.AddrFrom16(src)
}

// be16 converts a host-order port into the in-memory representation of a
// __be16 field.
func be16(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

func fromBe16(v uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}

func family(t Tuple) uint8 {
	if t.Src.Addr().Unmap().Is4() {
		return 4
	}
	return 6
}

func (r Rule) key() (phantomXlKey, error) {
	if err := r.Match.valid(); err != nil {
		return phantomXlKey{}, err
	}
	k := phantomXlKey{
		Scope:  uint8(r.Scope),
		Proto:  uint8(r.Match.Proto),
		Family: family(r.Match),
		Sport:  be16(r.Match.Src.Port()),
		Dport:  be16(r.Match.Dst.Port()),
	}
	putAddr(&k.Saddr, r.Match.Src.Addr())
	putAddr(&k.Daddr, r.Match.Dst.Addr())
	return k, nil
}

func (r Rule) value() (phantomXlVal, error) {
	if err := r.Rewrite.valid(); err != nil {
		return phantomXlVal{}, err
	}
	if family(r.Rewrite) != family(r.Match) || r.Rewrite.Proto != r.Match.Proto {
		return phantomXlVal{}, fmt.Errorf("rule %v changes family or protocol", r)
	}
	v := phantomXlVal{
		Sport: be16(r.Rewrite.Src.Port()),
		Dport: be16(r.Rewrite.Dst.Port()),
		Flags: uint32(r.Flags),
		Owner: r.Owner,
	}
	putAddr(&v.Saddr, r.Rewrite.Src.Addr())
	putAddr(&v.Daddr, r.Rewrite.Dst.Addr())
	if r.Flags&FlagTunnel != 0 {
		a := r.TunnelRemote.Unmap()
		if !a.Is4() {
			return v, fmt.Errorf("rule %v: FlagTunnel needs an IPv4 TunnelRemote", r)
		}
		b := a.As4()
		v.TunnelRemote4 = binary.BigEndian.Uint32(b[:])
	}
	return v, nil
}

func (t *Translator) mapFor(d Direction) (*ebpf.Map, error) {
	switch d {
	case Out:
		return t.maps.PaguroXlOut, nil
	case In:
		return t.maps.PaguroXlIn, nil
	}
	return nil, fmt.Errorf("phantom: invalid direction %d", d)
}

// Upsert installs or replaces rules. Counters of replaced rules are reset.
func (t *Translator) Upsert(rules ...Rule) error {
	for _, r := range rules {
		m, err := t.mapFor(r.Dir)
		if err != nil {
			return err
		}
		k, err := r.key()
		if err != nil {
			return fmt.Errorf("phantom: %w", err)
		}
		v, err := r.value()
		if err != nil {
			return fmt.Errorf("phantom: %w", err)
		}
		if err := m.Update(&k, &v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("phantom: install %v: %w", r, err)
		}
	}
	return nil
}

// Delete removes rules by their match key. Missing rules are ignored.
func (t *Translator) Delete(rules ...Rule) error {
	for _, r := range rules {
		m, err := t.mapFor(r.Dir)
		if err != nil {
			return err
		}
		k, err := r.key()
		if err != nil {
			return fmt.Errorf("phantom: %w", err)
		}
		if err := m.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("phantom: delete %v: %w", r, err)
		}
	}
	return nil
}

// DeleteOwned removes rules by their match key, but only where the
// installed rule still belongs to owner. A later migration of the same pod
// re-installs rules for the same connections under the same keys (its own
// id as owner, docs/PHANTOM-MODE.md 3.3); cleaning up an earlier migration's
// ended flows must not remove them. Callers serialize rule changes.
func (t *Translator) DeleteOwned(owner uint32, rules ...Rule) error {
	mine, err := stillOwned(owner, rules, func(r Rule) (uint32, bool, error) {
		m, err := t.mapFor(r.Dir)
		if err != nil {
			return 0, false, err
		}
		k, err := r.key()
		if err != nil {
			return 0, false, fmt.Errorf("phantom: %w", err)
		}
		var v phantomXlVal
		if err := m.Lookup(&k, &v); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return 0, false, nil
			}
			return 0, false, fmt.Errorf("phantom: lookup %v: %w", r, err)
		}
		return v.Owner, true, nil
	})
	if err != nil {
		return err
	}
	return t.Delete(mine...)
}

// stillOwned returns the rules whose installed version (installed: owner
// of the rule under the same key, and whether there is one) belongs to
// owner.
func stillOwned(owner uint32, rules []Rule, installed func(Rule) (uint32, bool, error)) ([]Rule, error) {
	var out []Rule
	for _, r := range rules {
		cur, ok, err := installed(r)
		if err != nil {
			return out, err
		}
		if ok && cur == owner {
			out = append(out, r)
		}
	}
	return out, nil
}

// SetFlags changes the flags of installed rules in place (counters kept),
// e.g. to clear FlagPending once the pod is restored. Rules not installed
// are skipped.
func (t *Translator) SetFlags(set, clear Flags, rules ...Rule) error {
	for _, r := range rules {
		m, err := t.mapFor(r.Dir)
		if err != nil {
			return err
		}
		k, err := r.key()
		if err != nil {
			return err
		}
		var v phantomXlVal
		if err := m.Lookup(&k, &v); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return err
		}
		v.Flags = (v.Flags | uint32(set)) &^ uint32(clear)
		if err := m.Update(&k, &v, ebpf.UpdateExist); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func monoNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

// Rules lists all installed rules with counters.
func (t *Translator) Rules() ([]RuleState, error) {
	now := monoNow()
	var out []RuleState
	for _, d := range []Direction{Out, In} {
		m, _ := t.mapFor(d)
		var k phantomXlKey
		var v phantomXlVal
		it := m.Iterate()
		for it.Next(&k, &v) {
			fam := k.Family
			r := Rule{
				Scope: Scope(k.Scope),
				Dir:   d,
				Match: Tuple{Proto(k.Proto),
					netip.AddrPortFrom(getAddr(k.Saddr, fam), fromBe16(k.Sport)),
					netip.AddrPortFrom(getAddr(k.Daddr, fam), fromBe16(k.Dport))},
				Rewrite: Tuple{Proto(k.Proto),
					netip.AddrPortFrom(getAddr(v.Saddr, fam), fromBe16(v.Sport)),
					netip.AddrPortFrom(getAddr(v.Daddr, fam), fromBe16(v.Dport))},
				Flags: Flags(v.Flags),
				Owner: v.Owner,
			}
			if v.TunnelRemote4 != 0 {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], v.TunnelRemote4)
				r.TunnelRemote = netip.AddrFrom4(b)
			}
			rs := RuleState{Rule: r, Packets: v.Packets, LastSeen: v.LastSeenNs}
			if v.LastSeenNs != 0 && now > v.LastSeenNs {
				rs.Idle = time.Duration(now - v.LastSeenNs)
			}
			out = append(out, rs)
		}
		if err := it.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DeleteOwner removes all rules with the given owner (migration id).
func (t *Translator) DeleteOwner(owner uint32) (int, error) {
	rs, err := t.Rules()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rs {
		if r.Owner == owner {
			if err := t.Delete(r.Rule); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

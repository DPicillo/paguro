// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Wire-tuple reservation.
//
// A migrated flow appears on the wire as (peer:p <-> NEW:L). Nothing stops
// the client side of that flow from opening a NEW connection with the very
// same 4-tuple while the migrated flow is alive: the peer's socket of the
// old flow is connected to OLD:L, so the kernel considers peer:p free for
// NEW:L. Both connections would then be indistinguishable on the wire. With
// k migrated flows from one client to one port, the chance per new
// connection is about k/28000 (ephemeral range), i.e. it WILL happen for
// connection pools that reconnect through the Service after the migration.
//
// Reservation removes the possibility at the source:
//   - sockets: the client-side port goes into net.ipv4.ip_local_reserved_ports
//     of the client's network namespace (peer pod, node host netns, or the
//     new pod for flows it initiated). connect() autobind never picks a
//     reserved port; explicit bind() (CRIU restore) still works.
//   - netfilter SNAT (kube-proxy NodePort/LoadBalancer with masquerade on an
//     entry node): a placeholder conntrack entry for the wire tuple makes
//     nf_nat choose another port for a new connection.
// Both are released by garbage collection together with the rules.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const reservedPortsPath = "/proc/sys/net/ipv4/ip_local_reserved_ports"

var reserveMu sync.Mutex

// Reservation is one port to reserve in one network namespace (Netns ""
// = host network namespace of this node).
type Reservation struct {
	Netns string
	Port  uint16
}

func parsePortList(s string) (map[uint16]bool, error) {
	set := map[uint16]bool{}
	s = strings.TrimSpace(s)
	if s == "" {
		return set, nil
	}
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("bad port list %q", s)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("bad port list %q", s)
			}
		}
		for p := a; p <= b; p++ {
			set[uint16(p)] = true
		}
	}
	return set, nil
}

func formatPortList(set map[uint16]bool) string {
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, int(p))
	}
	sort.Ints(ports)
	var parts []string
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if i == j {
			parts = append(parts, strconv.Itoa(ports[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", ports[i], ports[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// updateReservedPorts adds (add=true) or removes ports in the netns.
// /proc/sys/net is resolved against the network namespace of the opening
// thread, hence inNetns.
func updateReservedPorts(netnsPath string, ports []uint16, add bool) error {
	reserveMu.Lock()
	defer reserveMu.Unlock()
	return inNetns(netnsPath, func() error {
		b, err := os.ReadFile(reservedPortsPath)
		if err != nil {
			return err
		}
		set, err := parsePortList(string(b))
		if err != nil {
			return err
		}
		for _, p := range ports {
			if add {
				set[p] = true
			} else {
				delete(set, p)
			}
		}
		v := formatPortList(set)
		if v == "" {
			v = "\n" // the kernel accepts an empty list as a newline
		}
		return os.WriteFile(reservedPortsPath, []byte(v), 0o644)
	})
}

// ReservePorts reserves client ports in a network namespace.
func ReservePorts(netnsPath string, ports ...uint16) error {
	return updateReservedPorts(netnsPath, ports, true)
}

// ReleasePorts undoes ReservePorts.
func ReleasePorts(netnsPath string, ports ...uint16) error {
	return updateReservedPorts(netnsPath, ports, false)
}

// ReservedPorts returns the reserved ports of a network namespace.
func ReservedPorts(netnsPath string) (map[uint16]bool, error) {
	var set map[uint16]bool
	err := inNetns(netnsPath, func() error {
		b, err := os.ReadFile(reservedPortsPath)
		if err != nil {
			return err
		}
		set, err = parsePortList(string(b))
		return err
	})
	return set, err
}

// placeholderTimeout keeps a placeholder entry for 5 days; the agent's GC
// refreshes or deletes it (conntrack has no "infinite").
const placeholderTimeout = 5 * 24 * 3600

func ctFlow(t Tuple, timeout uint32) *netlink.ConntrackFlow {
	ip := func(a netip.Addr) net.IP { return net.IP(a.Unmap().AsSlice()) }
	f := &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Forward: netlink.IPTuple{Protocol: uint8(t.Proto),
			SrcIP: ip(t.Src.Addr()), SrcPort: t.Src.Port(),
			DstIP: ip(t.Dst.Addr()), DstPort: t.Dst.Port()},
		Reverse: netlink.IPTuple{Protocol: uint8(t.Proto),
			SrcIP: ip(t.Dst.Addr()), SrcPort: t.Dst.Port(),
			DstIP: ip(t.Src.Addr()), DstPort: t.Src.Port()},
		TimeOut: timeout,
	}
	if !t.Src.Addr().Unmap().Is4() {
		f.FamilyType = unix.AF_INET6
	}
	if t.Proto == TCP {
		f.ProtoInfo = &netlink.ProtoInfoTCP{State: 3 /* ESTABLISHED */}
	}
	return f
}

// ReserveConntrack installs a placeholder conntrack entry for the wire
// tuple (orig direction = from the client side), so netfilter's NAT never
// allocates that tuple for another connection. Netns "" = host. Packets of
// the migrated flow never hit the placeholder: the host-scope programs
// translate them outside netfilter's view (egress after POSTROUTING,
// ingress before PREROUTING).
func ReserveConntrack(netnsPath string, wire Tuple) error {
	return inNetns(netnsPath, func() error {
		f := ctFlow(wire, placeholderTimeout)
		fam := netlink.InetFamily(f.FamilyType)
		return placeholder(
			func() error { return netlink.ConntrackCreate(netlink.ConntrackTable, fam, f) },
			func() error { return netlink.ConntrackUpdate(netlink.ConntrackTable, fam, f) })
	})
}

// placeholder creates a placeholder entry, or refreshes the one there.
// EEXIST on create and ENOENT on update mean that another entry holds the
// tuple in its reply direction – for example kube-proxy's NodePort entry
// of the very connection, when the pod came back to the address the
// connection was opened to. The tuple is taken then, which is what the
// placeholder is for: nf_nat does not allocate it either. Failing here
// failed the whole node's programming (measured on EKS). One retry covers
// an entry that went away between the two calls.
func placeholder(create, update func() error) error {
	for try := 0; ; try++ {
		err := create()
		if !errors.Is(err, syscall.EEXIST) {
			return err
		}
		err = update()
		if !errors.Is(err, syscall.ENOENT) {
			return err
		}
		if try == 1 {
			return nil // taken by an entry of its own
		}
	}
}

// ReleaseConntrack removes a placeholder created by ReserveConntrack.
func ReleaseConntrack(netnsPath string, wire Tuple) error {
	return inNetns(netnsPath, func() error {
		f := ctFlow(wire, 0)
		filter := &netlink.ConntrackFilter{}
		_ = filter.AddIP(netlink.ConntrackOrigSrcIP, f.Forward.SrcIP)
		_ = filter.AddIP(netlink.ConntrackOrigDstIP, f.Forward.DstIP)
		_ = filter.AddProtocol(f.Forward.Protocol)
		_ = filter.AddPort(netlink.ConntrackOrigSrcPort, f.Forward.SrcPort)
		_ = filter.AddPort(netlink.ConntrackOrigDstPort, f.Forward.DstPort)
		_, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, netlink.InetFamily(f.FamilyType), filter)
		return err
	})
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package ctguard

// Root tests against the kernel's conntrack table, each in a network
// namespace of its own (go test -c, then run the binary as root).

import (
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// inFreshNetns runs fn on a thread of its own in a new network namespace
// and fails the test if it does not return within 10 s.
func inFreshNetns(t *testing.T, fn func() error) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if caps := effectiveCaps(); caps&(1<<unix.CAP_NET_ADMIN) == 0 || caps&(1<<unix.CAP_SYS_ADMIN) == 0 {
		t.Skip("needs CAP_NET_ADMIN and CAP_SYS_ADMIN")
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		orig, err := netns.Get()
		if err != nil {
			done <- err
			return
		}
		defer orig.Close()
		ns, err := netns.New() // switches this thread
		if err != nil {
			done <- err
			return
		}
		defer ns.Close()
		done <- fn()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hangs")
	}
}

func effectiveCaps() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, _ := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return caps
		}
	}
	return 0
}

func tableEntries(t *testing.T) []Entry {
	t.Helper()
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET)
	if err != nil {
		t.Error(err)
	}
	var out []Entry
	for _, f := range flows {
		if e, ok := flowEntry(f); ok {
			out = append(out, e)
		}
	}
	return out
}

var (
	kOld = Entry{Proto: unix.IPPROTO_UDP,
		OrigSrc: netip.MustParseAddrPort("192.168.51.100:48771"), OrigDst: netip.MustParseAddrPort("192.168.51.1:30260"),
		ReplySrc: netip.MustParseAddrPort("10.245.2.10:26000"), ReplyDst: netip.MustParseAddrPort("192.168.51.1:31359")}
	kWant = Retarget([]Entry{kOld}, netip.MustParseAddr("10.245.3.20"))[0]
	// The client's datagram NATed afresh, and the server's datagram on the
	// binding's reply tuple.
	kFresh = Entry{Proto: unix.IPPROTO_UDP, OrigSrc: kOld.OrigSrc, OrigDst: kOld.OrigDst,
		ReplySrc: kWant.ReplySrc, ReplyDst: netip.MustParseAddrPort("192.168.51.1:34700")}
	kClash = Entry{Proto: unix.IPPROTO_UDP, OrigSrc: kWant.ReplySrc, OrigDst: kWant.ReplyDst,
		ReplySrc: kWant.ReplyDst, ReplyDst: kWant.ReplySrc}
)

func TestKernelLookupTuple(t *testing.T) {
	inFreshNetns(t, func() error {
		if err := create(kOld); err != nil {
			return err
		}
		for _, tuple := range [][2]netip.AddrPort{{kOld.OrigSrc, kOld.OrigDst}, {kOld.ReplySrc, kOld.ReplyDst}} {
			e, id, ok := lookupTuple(nil, kOld.Proto, tuple[0], tuple[1])
			if !ok || e != kOld || id == 0 {
				t.Errorf("lookup %v: %v %v %d", tuple, ok, e, id)
			}
		}
		if _, _, ok := lookupTuple(nil, kOld.Proto, kWant.ReplySrc, kWant.ReplyDst); ok {
			t.Error("lookup of a free tuple found an entry")
		}
		e, id, _ := lookupTuple(nil, kOld.Proto, kOld.OrigSrc, kOld.OrigDst)
		if err := deleteByID(nil, e, id+1); err == nil {
			t.Error("delete with another id removed the entry")
		}
		if err := deleteByID(nil, e, id); err != nil {
			t.Errorf("delete by id: %v", err)
		}
		if n := len(tableEntries(t)); n != 0 {
			t.Errorf("%d entries left", n)
		}
		return nil
	})
}

// Both obstacles at once: the client NATed afresh and the server's entry
// on the reply tuple.
func TestKernelInstallExclusive(t *testing.T) {
	for _, shared := range []bool{false, true} {
		inFreshNetns(t, func() error {
			var c *conn
			if shared {
				var err error
				if c, err = openConn(); err != nil {
					return err
				}
				defer c.close()
			}
			for _, e := range []Entry{kFresh, kClash} {
				if err := create(e); err != nil {
					return err
				}
			}
			if err := createPinned(c, kWant); err == nil {
				t.Fatal("pinned create succeeded next to both obstacles")
			}
			start := time.Now()
			if err := installExclusive(c, kWant); err != nil {
				return err
			}
			t.Logf("shared socket %v: install with two obstacles in %v", shared, time.Since(start))
			if got := tableEntries(t); len(got) != 1 || got[0] != kWant {
				t.Errorf("table %v, want only %v", got, kWant)
			}
			if err := installExclusive(c, kWant); err != nil {
				t.Errorf("second install: %v", err)
			}
			return nil
		})
	}
}

// Another client that a fresh masquerade happened to give the moved
// binding's port towards the new address keeps its binding: the move fails
// instead of taking it.
func TestKernelInstallExclusiveSparesOtherClient(t *testing.T) {
	inFreshNetns(t, func() error {
		other := Entry{Proto: unix.IPPROTO_UDP,
			OrigSrc: netip.MustParseAddrPort("192.168.51.101:40000"), OrigDst: kWant.OrigDst,
			ReplySrc: kWant.ReplySrc, ReplyDst: kWant.ReplyDst}
		if err := create(other); err != nil {
			return err
		}
		if err := installExclusive(nil, kWant); err == nil {
			t.Error("installed over another client's binding")
		}
		if got := tableEntries(t); len(got) != 1 || got[0] != other {
			t.Errorf("table %v, want only the other client's binding", got)
		}
		return nil
	})
}

// The move itself: the old binding becomes the new one, and a ClusterIP
// client without masquerade keeps its port even when its reply tuple is
// taken – pinned, not a silent new port.
func TestKernelEnsureRetargeted(t *testing.T) {
	inFreshNetns(t, func() error {
		clusterIP := Entry{Proto: unix.IPPROTO_UDP,
			OrigSrc: netip.MustParseAddrPort("10.245.1.10:59880"), OrigDst: netip.MustParseAddrPort("10.97.0.20:26000"),
			ReplySrc: netip.MustParseAddrPort("10.245.2.10:26000"), ReplyDst: netip.MustParseAddrPort("10.245.1.10:59880")}
		clusterIPWant := Retarget([]Entry{clusterIP}, kWant.ReplySrc.Addr())[0]
		serverFirst := Entry{Proto: unix.IPPROTO_UDP, OrigSrc: clusterIPWant.ReplySrc, OrigDst: clusterIPWant.ReplyDst,
			ReplySrc: clusterIPWant.ReplyDst, ReplyDst: clusterIPWant.ReplySrc}
		for _, e := range []Entry{kOld, clusterIP, serverFirst} {
			if err := create(e); err != nil {
				return err
			}
		}
		fixed, err := EnsureRetargeted([]Entry{kWant, clusterIPWant})
		if err != nil || len(fixed) != 2 {
			t.Errorf("fixed %v err %v", fixed, err)
		}
		got := tableEntries(t)
		if len(got) != 2 || !((got[0] == kWant && got[1] == clusterIPWant) || (got[1] == kWant && got[0] == clusterIPWant)) {
			t.Errorf("table %v, want %v and %v", got, kWant, clusterIPWant)
		}
		return nil
	})
}

// The same move for IPv6 (kube-proxy's ip6tables masquerade).
func TestKernelIPv6Move(t *testing.T) {
	inFreshNetns(t, func() error {
		old := Entry{Proto: unix.IPPROTO_UDP,
			OrigSrc: netip.MustParseAddrPort("[2001:db8::100]:48771"), OrigDst: netip.MustParseAddrPort("[fd00:51::1]:30260"),
			ReplySrc: netip.MustParseAddrPort("[fd00:245:2::10]:26000"), ReplyDst: netip.MustParseAddrPort("[fd00:51::1]:31359")}
		if err := create(old); err != nil {
			return err
		}
		want := Retarget([]Entry{old}, netip.MustParseAddr("fd00:245:3::20"))
		if _, err := EnsureRetargeted(want); err != nil {
			return err
		}
		flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET6)
		if err != nil {
			return err
		}
		if len(flows) != 1 {
			t.Fatalf("%d IPv6 entries", len(flows))
		}
		if e, _ := flowEntry(flows[0]); e != want[0] {
			t.Errorf("entry %v, want %v", e, want[0])
		}
		if e, id, ok := lookupTuple(nil, want[0].Proto, want[0].ReplySrc, want[0].ReplyDst); !ok || e != want[0] || id == 0 {
			t.Errorf("lookup by the reply tuple: %v %v", ok, e)
		}
		return nil
	})
}

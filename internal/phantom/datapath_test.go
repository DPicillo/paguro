// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// Root-only tests of the eBPF datapath. They load the programs, create
// throw-away network namespaces (prefix "pgrt") and pin under
// /sys/fs/bpf/paguro-test-*. Run with:
//
//	go test -c -o /tmp/phantom.test ./internal/phantom && sudo /tmp/phantom.test -test.v
//
// Without root (or without bpffs) they are skipped.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// needRoot skips unless the test may load eBPF programs and change network
// namespaces: uid 0 alone is not enough – in an unprivileged container
// (CI jobs) root lacks the capabilities.
func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const capNetAdmin, capSysAdmin = 12, 21
	if caps := effectiveCaps(); caps&(1<<capNetAdmin) == 0 || caps&(1<<capSysAdmin) == 0 {
		t.Skip("needs CAP_NET_ADMIN and CAP_SYS_ADMIN (a privileged environment)")
	}
	dir, err := os.MkdirTemp("/sys/fs/bpf", "paguro-probe-")
	if err != nil {
		t.Skip("no writable bpffs")
	}
	_ = os.Remove(dir)
}

// effectiveCaps reads this process's effective capability set.
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

func newTestTranslator(t *testing.T, opts ...Options) (*Translator, string) {
	t.Helper()
	pin := fmt.Sprintf("/sys/fs/bpf/paguro-test-%d-%s", os.Getpid(), strings.ReplaceAll(t.Name(), "/", "_"))
	_ = Cleanup(pin)
	tr, err := New(pin, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tr.Close()
		if err := Cleanup(pin); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return tr, pin
}

// ---------------------------------------------------------------------------
// Packet-level tests via BPF_PROG_TEST_RUN: exact rewrite and checksums.
// ---------------------------------------------------------------------------

func csumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func csumAdd(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// buildPacket returns an Ethernet frame with correct IP/L4 checksums. For
// UDP, zeroCsum leaves the UDP checksum 0 (IPv4 only).
func buildPacket(tu Tuple, payload []byte, zeroCsum bool) []byte {
	src, dst := tu.Src.Addr().Unmap(), tu.Dst.Addr().Unmap()
	var l4 []byte
	if tu.Proto == TCP {
		l4 = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:], tu.Src.Port())
		binary.BigEndian.PutUint16(l4[2:], tu.Dst.Port())
		binary.BigEndian.PutUint32(l4[4:], 1000)
		binary.BigEndian.PutUint32(l4[8:], 2000)
		l4[12] = 5 << 4
		l4[13] = 0x18 // PSH|ACK
		binary.BigEndian.PutUint16(l4[14:], 501)
		copy(l4[20:], payload)
	} else {
		l4 = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:], tu.Src.Port())
		binary.BigEndian.PutUint16(l4[2:], tu.Dst.Port())
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
		copy(l4[8:], payload)
	}
	var ip []byte
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(eth[6:12], []byte{2, 0, 0, 0, 0, 2})
	var pseudo uint32
	if src.Is4() {
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		ip[8] = 64
		ip[9] = byte(tu.Proto)
		s4, d4 := src.As4(), dst.As4()
		copy(ip[12:], s4[:])
		copy(ip[16:], d4[:])
		binary.BigEndian.PutUint16(ip[10:], csumFold(csumAdd(0, ip)))
		pseudo = csumAdd(0, s4[:])
		pseudo = csumAdd(pseudo, d4[:])
	} else {
		binary.BigEndian.PutUint16(eth[12:], 0x86dd)
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
		ip[6] = byte(tu.Proto)
		ip[7] = 64
		s16, d16 := src.As16(), dst.As16()
		copy(ip[8:], s16[:])
		copy(ip[24:], d16[:])
		pseudo = csumAdd(0, s16[:])
		pseudo = csumAdd(pseudo, d16[:])
	}
	pseudo += uint32(tu.Proto) + uint32(len(l4))
	csOff := 16
	if tu.Proto == UDP {
		csOff = 6
	}
	if !(tu.Proto == UDP && zeroCsum) {
		c := csumFold(csumAdd(pseudo, l4))
		if c == 0 && tu.Proto == UDP {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(l4[csOff:], c)
	}
	return append(append(eth, ip...), l4...)
}

// parsePacket returns the tuple and whether all checksums verify.
func parsePacket(t *testing.T, b []byte) (Tuple, bool, uint16) {
	t.Helper()
	et := binary.BigEndian.Uint16(b[12:])
	var tu Tuple
	var l4 []byte
	var pseudo uint32
	ok := true
	if et == 0x0800 {
		ip := b[14:34]
		if csumFold(csumAdd(0, ip)) != 0 {
			ok = false
		}
		tu.Proto = Proto(ip[9])
		s, d := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
		l4 = b[34:]
		pseudo = csumAdd(csumAdd(0, ip[12:16]), ip[16:20])
		tu.Src = netip.AddrPortFrom(s, binary.BigEndian.Uint16(l4[0:]))
		tu.Dst = netip.AddrPortFrom(d, binary.BigEndian.Uint16(l4[2:]))
	} else {
		ip := b[14:54]
		tu.Proto = Proto(ip[6])
		s, d := netip.AddrFrom16([16]byte(ip[8:24])), netip.AddrFrom16([16]byte(ip[24:40]))
		l4 = b[54:]
		pseudo = csumAdd(csumAdd(0, ip[8:24]), ip[24:40])
		tu.Src = netip.AddrPortFrom(s, binary.BigEndian.Uint16(l4[0:]))
		tu.Dst = netip.AddrPortFrom(d, binary.BigEndian.Uint16(l4[2:]))
	}
	pseudo += uint32(tu.Proto) + uint32(len(l4))
	csOff := 16
	if tu.Proto == UDP {
		csOff = 6
	}
	l4cs := binary.BigEndian.Uint16(l4[csOff:])
	if !(tu.Proto == UDP && l4cs == 0) && csumFold(csumAdd(pseudo, l4)) != 0 {
		ok = false
	}
	return tu, ok, l4cs
}

const (
	retNext = 0xffffffff // TCX_NEXT / TC_ACT_UNSPEC
	retShot = 2          // TC_ACT_SHOT
)

func runProg(t *testing.T, p *ebpf.Program, pkt []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(pkt)+256)
	ret, err := p.Run(&ebpf.RunOptions{Data: pkt, DataOut: out})
	if err != nil {
		t.Fatalf("prog run: %v", err)
	}
	return ret, out[:len(pkt)]
}

func TestDatapathRewriteAndChecksums(t *testing.T) {
	needRoot(t)
	tr, _ := newTestTranslator(t)
	progOut := tr.progs[14].XlPodOut
	progIn := tr.progs[14].XlPodIn
	payload := []byte("paguro-phantom-payload-0123456789")

	cases := []struct {
		name     string
		match    Tuple
		rewrite  Tuple
		zeroCsum bool
	}{
		{"tcp4-dst", Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.2.10:7000")}, Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.3.20:7000")}, false},
		{"tcp4-src+ports", Tuple{TCP, ap("10.244.2.10:7000"), ap("10.96.0.10:80")}, Tuple{TCP, ap("10.244.3.20:7001"), ap("10.244.1.10:8080")}, false},
		{"udp4", Tuple{UDP, ap("10.244.1.10:5353"), ap("10.244.2.10:53")}, Tuple{UDP, ap("10.244.1.10:5353"), ap("10.244.3.20:53")}, false},
		{"udp4-zero-csum", Tuple{UDP, ap("10.244.1.10:5354"), ap("10.244.2.10:53")}, Tuple{UDP, ap("10.244.1.10:5354"), ap("10.244.3.20:53")}, true},
		{"tcp6", Tuple{TCP, ap("[fd00:244:1::10]:40000"), ap("[fd00:244:2::10]:7000")}, Tuple{TCP, ap("[fd00:244:1::10]:40000"), ap("[fd00:244:3::20]:7000")}, false},
		{"udp6-both", Tuple{UDP, ap("[fd00:244:2::10]:443"), ap("[fd00:244:1::10]:50000")}, Tuple{UDP, ap("[fd00:244:3::20]:443"), ap("[fd00:244:1::10]:50000")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, dir := range []Direction{Out, In} {
				r := Rule{Scope: ScopePod, Dir: dir, Match: c.match, Rewrite: c.rewrite}
				if err := tr.Upsert(r); err != nil {
					t.Fatal(err)
				}
				prog := progOut
				if dir == In {
					prog = progIn
				}
				pkt := buildPacket(c.match, payload, c.zeroCsum)
				if _, ok, _ := parsePacket(t, pkt); !ok {
					t.Fatal("test packet has bad checksums")
				}
				ret, out := runProg(t, prog, pkt)
				if ret != retNext {
					t.Fatalf("ret %#x", ret)
				}
				got, ok, l4cs := parsePacket(t, out)
				if got != c.rewrite {
					t.Errorf("dir %d: rewrote to %v, want %v", dir, got, c.rewrite)
				}
				if !ok {
					t.Errorf("dir %d: bad checksum after rewrite", dir)
				}
				if c.zeroCsum && l4cs != 0 {
					t.Errorf("zero UDP checksum must stay zero, got %#x", l4cs)
				}
				if string(out[len(out)-len(payload):]) != string(payload) {
					t.Error("payload changed")
				}
				if err := tr.Delete(r); err != nil {
					t.Fatal(err)
				}
				// Without the rule the packet passes untouched.
				_, out = runProg(t, prog, pkt)
				if string(out) != string(pkt) {
					t.Error("unmatched packet modified")
				}
			}
		})
	}

	t.Run("scope-isolation", func(t *testing.T) {
		m := Tuple{TCP, ap("10.0.0.1:1"), ap("10.0.0.2:2")}
		r := Rule{Scope: ScopeHost, Dir: Out, Match: m, Rewrite: Tuple{TCP, ap("10.0.0.1:1"), ap("10.0.0.3:2")}}
		if err := tr.Upsert(r); err != nil {
			t.Fatal(err)
		}
		defer tr.Delete(r)
		pkt := buildPacket(m, payload, false)
		if _, out := runProg(t, progOut, pkt); string(out) != string(pkt) {
			t.Error("pod program applied a host-scope rule")
		}
		if _, out := runProg(t, tr.progs[14].XlHostOut, pkt); string(out) == string(pkt) {
			t.Error("host program ignored a host-scope rule")
		}
	})

	t.Run("pending-drop-and-kill-switch", func(t *testing.T) {
		m := Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.3.20:7000")}
		r := Rule{Scope: ScopePod, Dir: In, Match: m, Rewrite: Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.2.10:7000")}, Flags: FlagPending}
		if err := tr.Upsert(r); err != nil {
			t.Fatal(err)
		}
		defer tr.Delete(r)
		pkt := buildPacket(m, payload, false)
		if ret, _ := runProg(t, progIn, pkt); ret != retShot {
			t.Errorf("pending rule: ret %#x, want drop", ret)
		}
		if err := tr.SetFlags(0, FlagPending, r); err != nil {
			t.Fatal(err)
		}
		if ret, out := runProg(t, progIn, pkt); ret != retNext || string(out) == string(pkt) {
			t.Errorf("after clearing pending: ret %#x, translated=%v", ret, string(out) != string(pkt))
		}
		if err := tr.SetEnabled(false); err != nil {
			t.Fatal(err)
		}
		if _, out := runProg(t, progIn, pkt); string(out) != string(pkt) {
			t.Error("kill switch off: packet modified")
		}
		if err := tr.SetEnabled(true); err != nil {
			t.Fatal(err)
		}
		st, err := tr.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if st.PendingDrops == 0 || st.Translated == 0 || st.Errors != 0 {
			t.Errorf("stats %+v", st)
		}
		rs, _ := tr.Rules()
		if len(rs) != 1 || rs[0].Packets == 0 {
			t.Errorf("rule counters: %+v", rs)
		}
	})

	t.Run("non-candidates-pass", func(t *testing.T) {
		// ARP, ICMP and fragments are never touched.
		arp := make([]byte, 60)
		binary.BigEndian.PutUint16(arp[12:], 0x0806)
		if ret, out := runProg(t, progOut, arp); ret != retNext || string(out) != string(arp) {
			t.Error("ARP modified")
		}
		frag := buildPacket(Tuple{TCP, ap("10.244.1.10:40000"), ap("10.244.2.10:7000")}, payload, false)
		frag[14+6] = 0x20 // MF
		if ret, out := runProg(t, progOut, frag); ret != retNext || string(out) != string(frag) {
			t.Error("fragment modified")
		}
	})
}

// ---------------------------------------------------------------------------
// Namespaces.
// ---------------------------------------------------------------------------

type nsEnv struct {
	t     *testing.T
	names []string
}

func (e *nsEnv) ns(name string) string {
	full := fmt.Sprintf("pgrt%d%s", os.Getpid()%100000, name)
	e.run("ip", "netns", "add", full)
	e.names = append(e.names, full)
	e.in(full, "ip", "link", "set", "lo", "up")
	return full
}

func (e *nsEnv) run(args ...string) {
	e.t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		e.t.Fatalf("%v: %v\n%s", args, err, out)
	}
}

func (e *nsEnv) in(ns string, args ...string) {
	e.t.Helper()
	e.run(append([]string{"ip", "netns", "exec", ns}, args...)...)
}

func (e *nsEnv) path(ns string) string { return filepath.Join("/run/netns", ns) }

func (e *nsEnv) close() {
	for _, n := range e.names {
		_ = exec.Command("ip", "netns", "del", n).Run()
	}
}

func newNsEnv(t *testing.T) *nsEnv {
	e := &nsEnv{t: t}
	t.Cleanup(e.close)
	return e
}

// veth creates a veth pair a(in nsA) <-> b(in nsB).
func (e *nsEnv) veth(nsA, a, nsB, b string) {
	e.run("ip", "-n", nsA, "link", "add", a, "type", "veth", "peer", "name", b, "netns", nsB)
	e.in(nsA, "ip", "link", "set", a, "up")
	e.in(nsB, "ip", "link", "set", b, "up")
}

func countTCX(t *testing.T, nsPath, ifname string, at ebpf.AttachType) int {
	t.Helper()
	n := 0
	err := inNetns(nsPath, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			return err
		}
		res, err := link.QueryPrograms(link.QueryOptions{Target: l.Attrs().Index, Attach: at})
		if err != nil {
			return err
		}
		n = len(res.Programs)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func countLegacy(t *testing.T, ns, ifname, dir string) int {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", ns, "tc", "filter", "show", "dev", ifname, dir).CombinedOutput()
	if err != nil {
		return 0
	}
	return strings.Count(string(out), "paguro-phantom")
}

func TestAttachLifecycle(t *testing.T) {
	needRoot(t)
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			e := newNsEnv(t)
			a := e.ns("a")
			b := e.ns("b")
			e.veth(a, "eth0", b, "veth1")
			tr, pin := newTestTranslator(t, Options{ForceLegacyTC: legacy})
			att := Attachment{Netns: e.path(a), Ifname: "eth0", Kind: KindPod}

			count := func() (int, int) {
				if legacy {
					return countLegacy(t, a, "eth0", "ingress"), countLegacy(t, a, "eth0", "egress")
				}
				return countTCX(t, e.path(a), "eth0", ebpf.AttachTCXIngress), countTCX(t, e.path(a), "eth0", ebpf.AttachTCXEgress)
			}
			for i := 0; i < 3; i++ { // idempotent
				if err := tr.Attach(att); err != nil {
					t.Fatal(err)
				}
			}
			if in, eg := count(); in != 1 || eg != 1 {
				t.Fatalf("after 3x attach: ingress=%d egress=%d, want 1/1", in, eg)
			}
			as, err := tr.Attachments()
			if err != nil || len(as) != 2 {
				t.Fatalf("attachments %v %v", as, err)
			}

			if !legacy {
				// Agent restart: a second Translator on the same pins keeps
				// the links and switches them to its programs.
				before := as[0].LinkID
				tr2, err := New(pin)
				if err != nil {
					t.Fatal(err)
				}
				as2, _ := tr2.Attachments()
				if as2[0].LinkID != before {
					t.Errorf("link replaced on restart: %d -> %d", before, as2[0].LinkID)
				}
				if in, eg := count(); in != 1 || eg != 1 {
					t.Errorf("after restart: %d/%d", in, eg)
				}
				tr2.Close()
			}

			// A host-side attachment on the peer end, then detach twice.
			hatt := Attachment{Netns: e.path(b), Ifname: "veth1", Kind: KindPodHostSide}
			if err := tr.Attach(hatt); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := tr.Detach(att); err != nil {
					t.Fatal(err)
				}
				if err := tr.Detach(hatt); err != nil {
					t.Fatal(err)
				}
			}
			if in, eg := count(); in != 0 || eg != 0 {
				t.Errorf("after detach: %d/%d", in, eg)
			}
			if as, _ := tr.Attachments(); len(as) != 0 {
				t.Errorf("pins left: %v", as)
			}

			if !legacy {
				// Interface deleted under an attachment: the link turns
				// defunct and PruneDefunct removes the pins.
				if err := tr.Attach(att); err != nil {
					t.Fatal(err)
				}
				e.in(a, "ip", "link", "del", "eth0")
				n, err := tr.PruneDefunct()
				if err != nil || n != 2 {
					t.Errorf("prune: %d %v", n, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Real sockets: peer <-> router <-> migrated pod.
// ---------------------------------------------------------------------------

type migEnv struct {
	e          *nsEnv
	peer, pod  string
	tr         *Translator
	old4, new4 netip.Addr
	old6, new6 netip.Addr
}

// newMigEnv builds  peer(10.250.1.10) -- router -- pod(eth0 NEW 10.250.3.20,
// lo OLD 10.250.2.10). The router routes NEW to the pod and has no route
// for OLD, so an untranslated packet to OLD is lost.
func newMigEnv(t *testing.T) *migEnv {
	e := newNsEnv(t)
	m := &migEnv{e: e,
		old4: netip.MustParseAddr("10.250.2.10"), new4: netip.MustParseAddr("10.250.3.20"),
		old6: netip.MustParseAddr("fd00:250:2::10"), new6: netip.MustParseAddr("fd00:250:3::20")}
	m.peer, m.pod = e.ns("peer"), e.ns("pod")
	r := e.ns("rtr")
	e.veth(m.peer, "eth0", r, "vpeer")
	e.veth(m.pod, "eth0", r, "vpod")
	for _, c := range [][]string{
		{r, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
		{r, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"},
		{m.peer, "sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0"},
		{m.pod, "sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0"},
		{r, "sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0"},
		{m.peer, "ip", "addr", "add", "10.250.1.10/24", "dev", "eth0", "nodad"},
		{m.peer, "ip", "addr", "add", "fd00:250:1::10/64", "dev", "eth0", "nodad"},
		{r, "ip", "addr", "add", "10.250.1.1/24", "dev", "vpeer"},
		{r, "ip", "addr", "add", "fd00:250:1::1/64", "dev", "vpeer", "nodad"},
		{r, "ip", "addr", "add", "10.250.3.1/24", "dev", "vpod"},
		{r, "ip", "addr", "add", "fd00:250:3::1/64", "dev", "vpod", "nodad"},
		{m.pod, "ip", "addr", "add", "10.250.3.20/24", "dev", "eth0"},
		{m.pod, "ip", "addr", "add", "fd00:250:3::20/64", "dev", "eth0", "nodad"},
		{m.pod, "ip", "addr", "add", "10.250.2.10/32", "dev", "lo"},
		{m.pod, "ip", "addr", "add", "fd00:250:2::10/128", "dev", "lo"},
		{m.pod, "sysctl", "-qw", "net.ipv4.conf.all.arp_announce=2"},
		{m.peer, "ip", "route", "add", "default", "via", "10.250.1.1"},
		{m.peer, "ip", "-6", "route", "add", "default", "via", "fd00:250:1::1"},
		{m.pod, "ip", "route", "add", "default", "via", "10.250.3.1"},
		{m.pod, "ip", "-6", "route", "add", "default", "via", "fd00:250:3::1"},
	} {
		e.in(c[0], c[1:]...)
	}
	m.tr, _ = newTestTranslator(t)
	for _, ns := range []string{m.peer, m.pod} {
		if err := m.tr.Attach(Attachment{Netns: e.path(ns), Ifname: "eth0", Kind: KindPod}); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// program installs the rules of one flow for both ends (one Translator plays
// both nodes; the keys do not collide).
func (m *migEnv) program(t *testing.T, old, new netip.Addr, f Flow, pending bool) PlanResult {
	t.Helper()
	mig := Migration{ID: 42, OldIP: old, NewIP: new}
	tgt, err := Plan(mig, []Flow{f}, NodeContext{IsTarget: true, Pending: pending,
		Migrated: PodEndpoint{Netns: m.e.path(m.pod), Ifname: "eth0"}})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := Plan(mig, []Flow{f}, NodeContext{LocalPods: map[netip.Addr]PodEndpoint{
		f.Remote.Addr(): {Netns: m.e.path(m.peer), Ifname: "eth0"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.tr.Upsert(tgt.Rules...); err != nil {
		t.Fatal(err)
	}
	if err := m.tr.Upsert(peer.Rules...); err != nil {
		t.Fatal(err)
	}
	return tgt
}

func listenIn(t *testing.T, nsPath, network, addr string) (l net.Listener, pc net.PacketConn) {
	t.Helper()
	err := inNetns(nsPath, func() error {
		var err error
		if strings.HasPrefix(network, "udp") {
			pc, err = net.ListenPacket(network, addr)
		} else {
			l, err = net.Listen(network, addr)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return l, pc
}

func dialIn(nsPath, network, local, remote string, timeout time.Duration) (net.Conn, error) {
	var c net.Conn
	err := inNetns(nsPath, func() error {
		// local == "": no bind(), the port is chosen by connect() like a
		// normal client does (connect() may share a port across different
		// 4-tuples, bind() never does).
		d := net.Dialer{Timeout: timeout}
		if local != "" {
			la, err := net.ResolveTCPAddr("tcp", local)
			if err != nil {
				return err
			}
			d.LocalAddr = la
			if strings.HasPrefix(network, "udp") {
				ua, _ := net.ResolveUDPAddr("udp", local)
				d.LocalAddr = ua
			}
		}
		var err error
		c, err = d.Dial(network, remote)
		return err
	})
	return c, err
}

func TestTranslationSockets(t *testing.T) {
	needRoot(t)
	m := newMigEnv(t)

	for _, fam := range []string{"4", "6"} {
		old, new := m.old4, m.new4
		peerIP := netip.MustParseAddr("10.250.1.10")
		if fam == "6" {
			old, new, peerIP = m.old6, m.new6, netip.MustParseAddr("fd00:250:1::10")
		}

		t.Run("tcp"+fam, func(t *testing.T) {
			l, _ := listenIn(t, m.e.path(m.pod), "tcp"+fam, netip.AddrPortFrom(old, 7000).String())
			defer l.Close()
			peerAddr := netip.AddrPortFrom(peerIP, 41000)
			f := Flow{Proto: TCP, Local: netip.AddrPortFrom(old, 7000), Remote: peerAddr}

			// Without rules OLD is unreachable from the peer.
			if c, err := dialIn(m.e.path(m.peer), "tcp"+fam, netip.AddrPortFrom(peerIP, 41001).String(), f.Local.String(), 500*time.Millisecond); err == nil {
				c.Close()
				t.Fatal("OLD reachable without translation: test topology is wrong")
			}

			// Pending: the SYN is dropped at the pod (no RST), then the
			// peer's retransmission succeeds once the pending flag is gone.
			res := m.program(t, old, new, f, true)
			go func() {
				time.Sleep(300 * time.Millisecond)
				_ = m.tr.SetFlags(0, FlagPending, res.PendingRules()...)
			}()
			c, err := dialIn(m.e.path(m.peer), "tcp"+fam, peerAddr.String(), f.Local.String(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial OLD with translation: %v", err)
			}
			defer c.Close()
			s, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			// Both sockets see OLD; nobody sees NEW.
			if got := s.LocalAddr().(*net.TCPAddr).AddrPort(); got.Addr().Unmap() != old {
				t.Errorf("server local %v, want OLD", got)
			}
			if got := s.RemoteAddr().(*net.TCPAddr).AddrPort(); got.Addr().Unmap() != peerIP || got.Port() != 41000 {
				t.Errorf("server remote %v", got)
			}
			if got := c.RemoteAddr().(*net.TCPAddr).AddrPort(); got.Addr().Unmap() != old {
				t.Errorf("client remote %v, want OLD", got)
			}
			// Bulk data both ways (exercises GSO/GRO and offloads on veth).
			buf := make([]byte, 4<<20)
			for i := range buf {
				buf[i] = byte(i * 7)
			}
			errc := make(chan error, 1)
			go func() {
				_, err := s.Write(buf)
				errc <- err
			}()
			got := make([]byte, len(buf))
			if _, err := ioReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
			if string(got) != string(buf) {
				t.Error("data corrupted")
			}

			// A NEW connection to OLD (another source port) is not part of
			// the migration and is never translated: IP reuse safety.
			if c2, err := dialIn(m.e.path(m.peer), "tcp"+fam, netip.AddrPortFrom(peerIP, 41002).String(), f.Local.String(), 500*time.Millisecond); err == nil {
				c2.Close()
				t.Error("unregistered flow to OLD was translated")
			}
			// Connections to NEW are untouched (the pod also serves NEW).
			l2, _ := listenIn(t, m.e.path(m.pod), "tcp"+fam, netip.AddrPortFrom(new, 7100).String())
			defer l2.Close()
			c3, err := dialIn(m.e.path(m.peer), "tcp"+fam, netip.AddrPortFrom(peerIP, 41003).String(), netip.AddrPortFrom(new, 7100).String(), time.Second)
			if err != nil {
				t.Fatalf("plain connection to NEW: %v", err)
			}
			c3.Close()

			// Garbage collection: the socket closes -> LiveFlows reports it dead.
			live, dead, err := LiveFlows(m.e.path(m.pod), old, []Flow{f})
			if err != nil || len(live) != 1 || len(dead) != 0 {
				t.Errorf("LiveFlows while open: %v %v %v", live, dead, err)
			}
			flows, err := HarvestFlows(m.e.path(m.pod), old)
			if err != nil || len(flows) != 1 || flows[0].Remote != peerAddr {
				t.Errorf("HarvestFlows: %v %v", flows, err)
			}
		})

		t.Run("udp"+fam, func(t *testing.T) {
			_, pc := listenIn(t, m.e.path(m.pod), "udp"+fam, netip.AddrPortFrom(old, 5300).String())
			defer pc.Close()
			peerAddr := netip.AddrPortFrom(peerIP, 42000)
			m.program(t, old, new, Flow{Proto: UDP, Local: netip.AddrPortFrom(old, 5300), Remote: peerAddr}, false)
			c, err := dialIn(m.e.path(m.peer), "udp"+fam, peerAddr.String(), netip.AddrPortFrom(old, 5300).String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
			b := make([]byte, 16)
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				t.Fatalf("pod did not receive: %v", err)
			}
			if string(b[:n]) != "ping" || from.(*net.UDPAddr).AddrPort().Addr().Unmap() != peerIP {
				t.Errorf("pod got %q from %v", b[:n], from)
			}
			if _, err := pc.WriteTo([]byte("pong"), from); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			// A connected UDP socket only accepts datagrams from OLD: this
			// proves the source was translated back.
			n, err = c.Read(b)
			if err != nil || string(b[:n]) != "pong" {
				t.Errorf("peer read %q %v", b[:n], err)
			}
		})
	}

	st, err := m.tr.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Errors != 0 || st.Translated == 0 {
		t.Errorf("stats %+v", st)
	}
	t.Logf("stats %+v", st)
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	n := 0
	for n < len(b) {
		k, err := c.Read(b[n:])
		n += k
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return n, fmt.Errorf("timeout after %d bytes", n)
			}
			return n, err
		}
	}
	return n, nil
}

// TestMeasureProgramCost reports the per-packet cost of the programs
// (BPF_PROG_TEST_RUN, averaged over many runs) for a packet that matches
// no rule and for one that is translated, with 100k rules installed.
func TestMeasureProgramCost(t *testing.T) {
	needRoot(t)
	tr, _ := newTestTranslator(t)
	var rules []Rule
	for i := 0; i < 100000; i++ {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), uint16(10000+i%50000))
		rules = append(rules, Rule{Scope: ScopePod, Dir: Out,
			Match:   Tuple{TCP, src, ap("10.244.2.10:7000")},
			Rewrite: Tuple{TCP, src, ap("10.244.3.20:7000")}})
	}
	// BPF_PROG_TEST_RUN with repeat runs on the same skb, so the packet must
	// translate back and forth: add the inverse of the measured rule.
	rules = append(rules, Rule{Scope: ScopePod, Dir: Out, Match: rules[777].Rewrite, Rewrite: rules[777].Match})
	if err := tr.Upsert(rules...); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1400)
	hit := buildPacket(rules[777].Match, payload, false)
	miss := buildPacket(Tuple{TCP, ap("10.9.9.9:1234"), ap("10.244.2.10:7000")}, payload, false)
	nonIP := make([]byte, 60)
	binary.BigEndian.PutUint16(nonIP[12:], 0x0806)
	measure := func(name string, pkt []byte) {
		const n = 2000000
		var best time.Duration
		for round := 0; round < 3; round++ {
			_, d, err := tr.progs[14].XlPodOut.Benchmark(pkt, n, nil)
			if err != nil {
				t.Fatal(err)
			}
			if best == 0 || d < best {
				best = d
			}
		}
		t.Logf("%-32s %6.1f ns/packet", name, float64(best.Nanoseconds()))
	}
	measure("non-IP (ARP)", nonIP)
	measure("IPv4 TCP, no rule (miss)", miss)
	measure("IPv4 TCP, translated (hit)", hit)
	if err := tr.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	measure("kill switch off", hit)
}

// TestWireTupleReservation shows the 4-tuple collision between a migrated
// flow and a new connection to NEW from the same client port, and that
// reserving the client port prevents it.
func TestWireTupleReservation(t *testing.T) {
	needRoot(t)
	m := newMigEnv(t)
	peerIP := netip.MustParseAddr("10.250.1.10")
	l, _ := listenIn(t, m.e.path(m.pod), "tcp4", "0.0.0.0:7200")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { // echo
				b := make([]byte, 64)
				for {
					n, err := c.Read(b)
					if err != nil {
						c.Close()
						return
					}
					c.Write(b[:n])
				}
			}()
		}
	}()
	echo := func(c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("hello")); err != nil {
			return err
		}
		b := make([]byte, 5)
		_, err := ioReadFull(c, b)
		return err
	}

	const p = 41100
	f := Flow{Proto: TCP, Local: netip.AddrPortFrom(m.old4, 7200), Remote: netip.AddrPortFrom(peerIP, p), Server: true}
	mig := Migration{OldIP: m.old4, NewIP: m.new4}
	peerPlan, err := Plan(mig, []Flow{f}, NodeContext{LocalPods: map[netip.Addr]PodEndpoint{peerIP: {Netns: m.e.path(m.peer), Ifname: "eth0"}}})
	if err != nil {
		t.Fatal(err)
	}
	tgtPlan, err := Plan(mig, []Flow{f}, NodeContext{IsTarget: true, Migrated: PodEndpoint{Netns: m.e.path(m.pod), Ifname: "eth0"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.tr.Apply(tgtPlan); err != nil {
		t.Fatal(err)
	}
	// The flow exists before the migration (and before the reservation).
	if err := m.tr.Upsert(peerPlan.Rules...); err != nil {
		t.Fatal(err)
	}
	// Like any client, the peer gets its port from connect() (autobind);
	// the range forces it to p.
	m.e.in(m.peer, "sysctl", "-qw", fmt.Sprintf("net.ipv4.ip_local_port_range=%d %d", p, p))
	old, err := dialIn(m.e.path(m.peer), "tcp4", "", f.Local.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if lp := old.LocalAddr().(*net.TCPAddr).Port; lp != p {
		t.Fatalf("setup: migrated flow got port %d", lp)
	}
	if err := m.tr.Apply(peerPlan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.tr.Revert(peerPlan) })
	if err := echo(old); err != nil {
		t.Fatalf("migrated flow: %v", err)
	}
	if rs, _ := ReservedPorts(m.e.path(m.peer)); !rs[p] {
		t.Fatalf("port %d not reserved in the peer: %v", p, rs)
	}

	// The peer's ephemeral range contains only p and p+1.
	m.e.in(m.peer, "sysctl", "-qw", fmt.Sprintf("net.ipv4.ip_local_port_range=%d %d", p, p+1))
	newConn, err := dialIn(m.e.path(m.peer), "tcp4", "", netip.AddrPortFrom(m.new4, 7200).String(), time.Second)
	if err != nil {
		t.Fatalf("new connection to NEW: %v", err)
	}
	if lp := newConn.LocalAddr().(*net.TCPAddr).Port; lp == p {
		t.Fatalf("kernel picked the reserved port %d", lp)
	}
	if err := echo(newConn); err != nil {
		t.Errorf("new connection: %v", err)
	}
	if err := echo(old); err != nil {
		t.Errorf("migrated flow after new connection: %v", err)
	}
	newConn.Close()

	// Negative control: without the reservation the kernel may pick p,
	// and both connections share one wire tuple.
	if err := ReleasePorts(m.e.path(m.peer), p); err != nil {
		t.Fatal(err)
	}
	m.e.in(m.peer, "sysctl", "-qw", fmt.Sprintf("net.ipv4.ip_local_port_range=%d %d", p, p))
	bad, err := dialIn(m.e.path(m.peer), "tcp4", "", netip.AddrPortFrom(m.new4, 7200).String(), time.Second)
	if err == nil {
		lp := bad.LocalAddr().(*net.TCPAddr).Port
		eerr := echo(bad)
		bad.Close()
		t.Logf("without reservation: new connection used port %d, echo error: %v", lp, eerr)
		if lp != p {
			t.Fatalf("negative control did not force port %d", p)
		}
		if eerr == nil {
			t.Error("collision expected without reservation, but the new connection worked")
		}
	} else {
		t.Logf("without reservation: new connection failed: %v", err)
	}
	// And the migrated flow is the victim (or the new one) - either way a
	// connection breaks, which is why the reservation is mandatory.
	t.Logf("migrated flow after the collision: %v", echo(old))
}

// TestMeasureControlPlane reports how long the target-side steps take for
// a growing number of flows: attach (first time), Apply (rules +
// reservations) and clearing the pending flag (the only step on the freeze
// path).
func TestMeasureControlPlane(t *testing.T) {
	needRoot(t)
	m := newMigEnv(t)
	for _, n := range []int{10, 100, 1000, 10000} {
		var flows []Flow
		for i := 0; i < n; i++ {
			flows = append(flows, Flow{Proto: TCP, Server: i%2 == 0,
				Local:  netip.AddrPortFrom(m.old4, uint16(1000+i%50000)),
				Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 9, byte(i >> 8), byte(i)}), uint16(20000+i%40000))})
		}
		mig := Migration{ID: uint32(n), OldIP: m.old4, NewIP: m.new4}
		ctx := NodeContext{IsTarget: true, Pending: true, Migrated: PodEndpoint{Netns: m.e.path(m.pod), Ifname: "eth0"}}
		t0 := time.Now()
		res, err := Plan(mig, flows, ctx)
		if err != nil {
			t.Fatal(err)
		}
		t1 := time.Now()
		if err := m.tr.Apply(res); err != nil {
			t.Fatal(err)
		}
		t2 := time.Now()
		if err := m.tr.SetFlags(0, FlagPending, res.PendingRules()...); err != nil {
			t.Fatal(err)
		}
		t3 := time.Now()
		t.Logf("%6d flows: plan %8s  apply (attach+reserve+%d rules) %10s  clear pending %10s",
			n, t1.Sub(t0).Round(time.Microsecond), len(res.Rules), t2.Sub(t1).Round(time.Microsecond), t3.Sub(t2).Round(time.Microsecond))
		if err := m.tr.Revert(res); err != nil {
			t.Fatal(err)
		}
	}
	// A fresh attach (link create in a foreign netns + pin).
	e := m.e
	x := e.ns("x")
	y := e.ns("y")
	e.veth(x, "eth0", y, "veth9")
	t0 := time.Now()
	if err := m.tr.Attach(Attachment{Netns: e.path(x), Ifname: "eth0", Kind: KindPod}); err != nil {
		t.Fatal(err)
	}
	t.Logf("first attach of a pod (2 TCX links in its netns): %s", time.Since(t0).Round(time.Microsecond))
	t0 = time.Now()
	if err := m.tr.Attach(Attachment{Netns: e.path(x), Ifname: "eth0", Kind: KindPod}); err != nil {
		t.Fatal(err)
	}
	t.Logf("repeated attach (idempotent, link update): %s", time.Since(t0).Round(time.Microsecond))
}

// TestSelfIPFixup: a listener bound to OLD specifically is reachable via
// NEW for new connections, and a new outbound connection bound to OLD
// leaves with NEW - only with the fix-up table.
func TestSelfIPFixup(t *testing.T) {
	needRoot(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	m := newMigEnv(t)
	podNs := m.e.path(m.pod)
	l, _ := listenIn(t, podNs, "tcp4", netip.AddrPortFrom(m.old4, 7300).String())
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(c.LocalAddr().String()))
			c.Close()
		}
	}()
	ports, err := HarvestOldBoundListeners(podNs, m.old4)
	if err != nil || len(ports) != 1 || ports[0] != 7300 {
		t.Fatalf("HarvestOldBoundListeners: %v %v", ports, err)
	}
	dialNew := func() (string, error) {
		c, err := dialIn(m.e.path(m.peer), "tcp4", "", netip.AddrPortFrom(m.new4, 7300).String(), time.Second)
		if err != nil {
			return "", err
		}
		defer c.Close()
		b := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(b)
		return string(b[:n]), err
	}
	if _, err := dialNew(); err == nil {
		t.Fatal("OLD-bound listener reachable via NEW without fix-up: test is wrong")
	}
	if err := InstallSelfIPFixup(nil, podNs, m.old4, m.new4, ports); err != nil {
		t.Fatal(err)
	}
	// Idempotent (atomic replace).
	if err := InstallSelfIPFixup(nil, podNs, m.old4, m.new4, ports); err != nil {
		t.Fatal(err)
	}
	got, err := dialNew()
	if err != nil || !strings.HasPrefix(got, m.old4.String()+":") {
		t.Fatalf("via NEW with fix-up: %q %v", got, err)
	}

	// Outbound: the app binds to its stale POD_IP (OLD).
	pl, _ := listenIn(t, m.e.path(m.peer), "tcp4", "10.250.1.10:7400")
	defer pl.Close()
	from := make(chan string, 1)
	go func() {
		c, err := pl.Accept()
		if err != nil {
			from <- err.Error()
			return
		}
		from <- c.RemoteAddr().String()
		c.Close()
	}()
	c, err := dialIn(podNs, "tcp4", netip.AddrPortFrom(m.old4, 0).String(), "10.250.1.10:7400", 2*time.Second)
	if err != nil {
		t.Fatalf("outbound from OLD with fix-up: %v", err)
	}
	c.Close()
	if r := <-from; !strings.HasPrefix(r, m.new4.String()+":") {
		t.Errorf("peer saw %s, want NEW", r)
	}
	if err := RemoveSelfIPFixup(nil, podNs); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSelfIPFixup(nil, podNs); err != nil {
		t.Fatal("second remove:", err)
	}
}

// TestDualStackSockets: Go, Java and Node servers listening on ":port" accept
// IPv4 clients on AF_INET6 sockets with v4-mapped addresses. Harvest, the
// liveness check and SOCK_DESTROY must find those sockets for an IPv4 pod
// (found on the cluster: a Go echo server's connections were invisible to an
// AF_INET-only dump).
func TestDualStackSockets(t *testing.T) {
	needRoot(t)
	e := &nsEnv{t: t}
	defer e.close()
	ns := e.ns("ds")
	path := e.path(ns)
	e.in(ns, "ip", "addr", "add", "10.99.0.1/32", "dev", "lo")
	pod := netip.MustParseAddr("10.99.0.1")

	var ln net.Listener
	var cli, srv net.Conn
	if err := inNetns(path, func() error {
		var err error
		if ln, err = net.Listen("tcp", "[::]:7777"); err != nil { // dual-stack
			return err
		}
		if cli, err = net.Dial("tcp4", "10.99.0.1:7777"); err != nil {
			return err
		}
		srv, err = ln.Accept()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer cli.Close()
	defer srv.Close()

	flows, err := HarvestFlows(path, pod)
	if err != nil {
		t.Fatal(err)
	}
	var server *Flow
	for i := range flows {
		if flows[i].Local.Port() == 7777 {
			server = &flows[i]
		}
	}
	if len(flows) != 2 || server == nil || !server.Server {
		t.Fatalf("want the client and the (v4-mapped) server side, got %+v", flows)
	}
	live, dead, err := LiveFlows(path, pod, flows)
	if err != nil || len(live) != 2 || len(dead) != 0 {
		t.Fatalf("LiveFlows: live=%v dead=%v err=%v", live, dead, err)
	}
	n, err := KillFlows(path, []Flow{*server})
	if errors.Is(err, unix.EOPNOTSUPP) {
		// SOCK_DESTROY needs CONFIG_INET_DIAG_DESTROY (missing in WSL2's kernel).
		t.Skipf("kernel cannot destroy sockets: %v", err)
	}
	if err != nil || n != 1 {
		t.Fatalf("KillFlows: n=%d err=%v", n, err)
	}
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := srv.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("destroyed socket still readable: %v", err)
	}
}

// TestOffLinkRoute: an old address that is on-link (bridge CNI subnet) or
// would hit a blackhole must be routed like the new address, so packets to
// it reach the tc programs instead of failing neighbour resolution.
func TestOffLinkRoute(t *testing.T) {
	needRoot(t)
	e := &nsEnv{t: t}
	defer e.close()
	ns := e.ns("rt")
	path := e.path(ns)
	e.in(ns, "ip", "link", "add", "dummy0", "type", "dummy")
	e.in(ns, "ip", "link", "set", "dummy0", "up")
	e.in(ns, "ip", "addr", "add", "10.80.0.2/24", "dev", "dummy0")
	e.in(ns, "ip", "route", "add", "10.90.0.0/24", "via", "10.80.0.1", "dev", "dummy0")
	// mainGw: where the kernel sends any connection to a (without a
	// steering rule); gw: where Paguro's steering table sends a translated
	// one. Paguro's route must never show up in the main table.
	mainGw := func(a string) string {
		var g string
		_ = inNetns(path, func() error {
			r, err := netlink.RouteGet(net.ParseIP(a))
			if err == nil && len(r) > 0 && r[0].Gw != nil {
				g = r[0].Gw.String()
			}
			return err
		})
		return g
	}
	gw := func(a string) string {
		var g string
		_ = inNetns(path, func() error {
			rs, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: SteerTable, Dst: prefixOf(netip.MustParseAddr(a))},
				netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
			if err == nil && len(rs) == 1 && rs[0].Gw != nil {
				g = rs[0].Gw.String()
			}
			return err
		})
		return g
	}
	old, like := netip.MustParseAddr("10.80.0.50"), netip.MustParseAddr("10.90.0.5")
	if mainGw("10.80.0.50") != "" {
		t.Fatal("setup: old address should be on-link")
	}
	ok, err := EnsureOffLinkRoute(path, old, like)
	if err != nil || !ok || gw("10.80.0.50") != "10.80.0.1" {
		t.Fatalf("on-link old address not routed like the new one: ok=%v err=%v gw=%q", ok, err, gw("10.80.0.50"))
	}
	if mainGw("10.80.0.50") != "" {
		t.Fatal("Paguro's route reached the main table: every connection to the old address would follow it")
	}
	// An earlier version's route in the main table goes.
	e.in(ns, "ip", "route", "add", "10.80.0.50/32", "via", "10.80.0.1", "dev", "dummy0", "onlink", "proto", "122", "metric", "4242")
	if ok, err := EnsureOffLinkRoute(path, old, like); err != nil || !ok || mainGw("10.80.0.50") != "" {
		t.Fatalf("main-table route of an earlier version kept: ok=%v err=%v", ok, err)
	}
	// The pod is back at the old address: nothing to steer.
	if ok, err := EnsureOffLinkRoute(path, old, old); ok || err != nil || gw("10.80.0.50") != "" {
		t.Fatalf("route kept for an address the pod has again: ok=%v err=%v", ok, err)
	}
	if _, err := EnsureOffLinkRoute(path, old, like); err != nil {
		t.Fatal(err)
	}
	if ok, err := EnsureOffLinkRoute(path, netip.MustParseAddr("10.90.0.7"), like); ok || err != nil {
		t.Fatalf("address behind a gateway must stay untouched: ok=%v err=%v", ok, err)
	}
	if err := RemoveOffLinkRoute(path, old); err != nil || gw("10.80.0.50") != "" || ours(t, path, old) {
		t.Fatalf("route not removed: err=%v gw=%q", err, gw("10.80.0.50"))
	}
	if err := RemoveOffLinkRoute(path, old); err != nil {
		t.Fatalf("second removal: %v", err)
	}
	// The new address on the same link: the old one is routed via it.
	if ok, err := EnsureOffLinkRoute(path, old, netip.MustParseAddr("10.80.0.60")); err != nil || !ok || gw("10.80.0.50") != "10.80.0.60" {
		t.Fatalf("on-link new address must become the next hop: ok=%v err=%v gw=%q", ok, err, gw("10.80.0.50"))
	}
	// The pod moves on (chained migration): our own route follows it.
	if ok, err := EnsureOffLinkRoute(path, old, like); err != nil || !ok || gw("10.80.0.50") != "10.80.0.1" {
		t.Fatalf("own route must be replaced, not kept: ok=%v err=%v gw=%q", ok, err, gw("10.80.0.50"))
	}
	if err := RemoveOffLinkRoute(path, old); err != nil {
		t.Fatal(err)
	}

	// The old node's pod subnet route is gone (node deleted): only the
	// default route covers the old address. In a node's host namespace
	// that leads out of the cluster; in a pod it is the CNI's route.
	e.in(ns, "ip", "route", "add", "default", "via", "10.80.0.1", "dev", "dummy0")
	gone := netip.MustParseAddr("10.70.0.9")
	if ok, err := ensureOffLinkRoute(path, false, gone, like); ok || err != nil {
		t.Fatalf("pod view: the default route is the CNI's: ok=%v err=%v", ok, err)
	}
	if ok, err := ensureOffLinkRoute(path, true, gone, like); err != nil || !ok || !ours(t, path, gone) {
		t.Fatalf("host view: an address behind the default route must get a route: ok=%v err=%v", ok, err)
	}
	if err := RemoveOffLinkRoute(path, gone); err != nil {
		t.Fatal(err)
	}

	// Cilium routes pod subnets through its router IP on cilium_host, an
	// address of the host itself. The kernel reports such routes without
	// a gateway; the old address goes to the same device via the new one.
	e.in(ns, "ip", "link", "add", "chost", "type", "dummy")
	e.in(ns, "ip", "link", "set", "chost", "up")
	e.in(ns, "ip", "addr", "add", "10.60.0.1/32", "dev", "chost")
	e.in(ns, "ip", "route", "add", "10.60.0.1", "dev", "chost", "scope", "link")
	e.in(ns, "ip", "route", "add", "10.61.0.0/24", "via", "10.60.0.1", "dev", "chost")
	sticky := netip.MustParseAddr("10.62.0.9")
	if ok, err := ensureOffLinkRoute(path, true, sticky, netip.MustParseAddr("10.61.0.5")); err != nil || !ok || gw("10.62.0.9") != "10.61.0.5" {
		t.Fatalf("route like a subnet behind a local next hop: ok=%v err=%v gw=%q", ok, err, gw("10.62.0.9"))
	}
	if err := RemoveOffLinkRoute(path, sticky); err != nil {
		t.Fatal(err)
	}

	// Routed into the cluster: by a pod subnet route, not by the default
	// route and not by Paguro's own route.
	routed := func(a string) bool {
		var ok bool
		if err := inNetns(path, func() (err error) { ok, err = RoutedIntoCluster(netip.MustParseAddr(a)); return }); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !routed("10.61.0.5") || !routed("10.80.0.50") {
		t.Fatal("addresses behind subnet routes must count as routed into the cluster")
	}
	if routed("10.70.0.9") {
		t.Fatal("the default route does not count")
	}
	if _, err := ensureOffLinkRoute(path, true, gone, like); err != nil || routed("10.70.0.9") {
		t.Fatalf("Paguro's own route does not count: err=%v", err)
	}
	// NEW reachable only through the default route (its CNI route not
	// there yet): nothing is copied – that would route OLD out.
	if err := RemoveOffLinkRoute(path, gone); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureOffLinkRoute(path, true, gone, netip.MustParseAddr("10.71.0.5")); err == nil || ours(t, path, gone) {
		t.Fatalf("a route like the default route must be refused: err=%v", err)
	}
	// The CNI route comes back (it was gone for a moment): Paguro's more
	// specific route must go again, or it would shadow the CNI's.
	e.in(ns, "ip", "route", "add", "10.70.0.0/24", "via", "10.80.0.9", "dev", "dummy0")
	if ok, err := ensureOffLinkRoute(path, true, gone, like); ok || err != nil || ours(t, path, gone) || mainGw("10.70.0.9") != "10.80.0.9" {
		t.Fatalf("own route must yield to a returning CNI route: ok=%v err=%v gw=%q", ok, err, mainGw("10.70.0.9"))
	}
}

// ours reports whether Paguro's route for a exists in netnsPath.
func ours(t *testing.T, netnsPath string, a netip.Addr) bool {
	t.Helper()
	found := false
	_ = inNetns(netnsPath, func() error {
		rs, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: prefixOf(a), Protocol: RouteProtocol, Table: unix.RT_TABLE_UNSPEC},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_TABLE)
		found = err == nil && len(rs) == 1
		return err
	})
	return found
}

// TestNextHopOnLink: the peer runs on the target node. It routed OLD (on
// another node) through its gateway; NEW is on its own segment. Open vSwitch
// CNIs (Antrea) hand frames addressed to the gateway to the host and route
// the replies of such a connection back there – modelled here by a gateway
// that does not forward at all. With FlagNeigh the frame goes to NEW
// directly; without it, nothing arrives.
func TestNextHopOnLink(t *testing.T) {
	needRoot(t)
	e := newNsEnv(t)
	node, peer, pod := e.ns("nd"), e.ns("pe"), e.ns("po")
	e.in(node, "ip", "link", "add", "br0", "type", "bridge")
	e.in(node, "ip", "link", "set", "br0", "up")
	e.in(node, "ip", "addr", "add", "10.77.0.1/24", "dev", "br0")
	e.in(node, "sysctl", "-qw", "net.ipv4.ip_forward=0")
	for _, p := range []struct{ ns, br, ip string }{{peer, "vpe", "10.77.0.10/24"}, {pod, "vpo", "10.77.0.20/24"}} {
		e.veth(p.ns, "eth0", node, p.br)
		e.in(node, "ip", "link", "set", p.br, "master", "br0")
		e.in(p.ns, "ip", "addr", "add", p.ip, "dev", "eth0")
		e.in(p.ns, "ip", "route", "add", "default", "via", "10.77.0.1")
	}
	old, new := netip.MustParseAddr("10.88.0.5"), netip.MustParseAddr("10.77.0.20")
	e.in(pod, "ip", "addr", "add", "10.88.0.5/32", "dev", "lo")
	e.in(pod, "sysctl", "-qw", "net.ipv4.conf.all.arp_announce=2")

	tr, _ := newTestTranslator(t)
	for _, ns := range []string{peer, pod} {
		if err := tr.Attach(Attachment{Netns: e.path(ns), Ifname: "eth0", Kind: KindPod}); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := listenIn(t, e.path(pod), "tcp4", netip.AddrPortFrom(old, 7000).String())
	defer l.Close()
	go func() {
		for {
			s, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(s, s) }()
		}
	}()

	dial := func(port uint16, neigh bool) error {
		f := Flow{Proto: TCP, Local: netip.AddrPortFrom(old, 7000), Remote: netip.AddrPortFrom(netip.MustParseAddr("10.77.0.10"), port)}
		mig := Migration{ID: uint32(port), OldIP: old, NewIP: new}
		tgt, err := Plan(mig, []Flow{f}, NodeContext{IsTarget: true, Migrated: PodEndpoint{Netns: e.path(pod), Ifname: "eth0"}})
		if err != nil {
			t.Fatal(err)
		}
		pr, err := Plan(mig, []Flow{f}, NodeContext{OnLink: OnLinkIn,
			LocalPods: map[netip.Addr]PodEndpoint{f.Remote.Addr(): {Netns: e.path(peer), Ifname: "eth0"}}})
		if err != nil {
			t.Fatal(err)
		}
		rules := append(tgt.Rules, pr.Rules...)
		for i := range rules {
			if !neigh {
				rules[i].Flags &^= FlagNeigh
			}
		}
		if err := tr.Upsert(rules...); err != nil {
			t.Fatal(err)
		}
		c, err := dialIn(e.path(peer), "tcp4", f.Remote.String(), f.Local.String(), time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		_, err = ioReadFull(c, buf)
		return err
	}
	if err := dial(42001, false); err == nil {
		t.Fatal("without FlagNeigh the connection must die at the gateway: test topology is wrong")
	}
	if err := dial(42002, true); err != nil {
		t.Fatalf("with FlagNeigh: %v", err)
	}
	if OnLinkIn(e.path(peer), old) || !OnLinkIn(e.path(peer), new) {
		t.Error("OnLinkIn: OLD is behind the gateway, NEW on the segment")
	}

	// The pod came back to an address its connections still use: identity
	// rules with FlagNeigh must pass, not loop (redirect only rewritten
	// destinations).
	l2, _ := listenIn(t, e.path(pod), "tcp4", netip.AddrPortFrom(new, 7001).String())
	defer l2.Close()
	go func() {
		if s, err := l2.Accept(); err == nil {
			_, _ = io.Copy(s, s)
		}
	}()
	f := Flow{Proto: TCP, Local: netip.AddrPortFrom(new, 7001), Remote: netip.AddrPortFrom(netip.MustParseAddr("10.77.0.10"), 42003)}
	same := Migration{ID: 99, OldIP: new, NewIP: new}
	for _, ctx := range []NodeContext{
		{IsTarget: true, Migrated: PodEndpoint{Netns: e.path(pod), Ifname: "eth0"}},
		{OnLink: OnLinkIn, LocalPods: map[netip.Addr]PodEndpoint{f.Remote.Addr(): {Netns: e.path(peer), Ifname: "eth0"}}},
	} {
		p, err := Plan(same, []Flow{f}, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Upsert(p.Rules...); err != nil {
			t.Fatal(err)
		}
	}
	c, err := dialIn(e.path(peer), "tcp4", f.Remote.String(), f.Local.String(), time.Second)
	if err != nil {
		t.Fatalf("identity rules: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if _, err := ioReadFull(c, make([]byte, 4)); err != nil {
		t.Fatalf("identity rules: %v", err)
	}
}

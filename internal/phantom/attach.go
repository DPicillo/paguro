// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Kind says what an interface is and therefore which programs go where.
type Kind string

const (
	// KindPod is a pod's own interface (eth0) inside the pod network
	// namespace. Egress = leaving the pod, ingress = entering the pod.
	// Preferred placement: no CNI program runs there, and the ingress hook
	// also sees packets the CNI delivers with bpf_redirect_peer.
	KindPod Kind = "pod"
	// KindPodHostSide is the host-side end of a pod's veth (lxc*, cali*,
	// eni*). Ingress = leaving the pod, egress = entering the pod. Only
	// for CNIs that deliver to pods through the host-side veth egress.
	KindPodHostSide Kind = "podhost"
	// KindHostDevice is a node device that carries pod traffic in the host
	// network namespace (uplink, cilium_host, cilium_vxlan, vxlan.calico,
	// tunl0, ...). Programs serve host-scope rules.
	KindHostDevice Kind = "hostdev"
	// KindHostLocal is the host-side veth of the MIGRATED pod on the target
	// node; it serves host-scope rules flagged FlagLocal (host clients on
	// the target node itself).
	KindHostLocal Kind = "hostlocal"
)

type hookDir string

const (
	dirIngress hookDir = "ingress"
	dirEgress  hookDir = "egress"
)

type hook struct {
	dir  hookDir
	prog string // program name in the ELF
}

func hooksFor(k Kind) ([]hook, error) {
	switch k {
	case KindPod:
		return []hook{{dirEgress, "xl_pod_out"}, {dirIngress, "xl_pod_in"}}, nil
	case KindPodHostSide:
		return []hook{{dirIngress, "xl_podhost_out"}, {dirEgress, "xl_pod_in"}}, nil
	case KindHostDevice:
		return []hook{{dirEgress, "xl_host_out"}, {dirIngress, "xl_host_in"}}, nil
	case KindHostLocal:
		return []hook{{dirIngress, "xl_host_local"}}, nil
	}
	return nil, fmt.Errorf("phantom: unknown attachment kind %q", k)
}

func (t *Translator) program(l3off uint32, name string) *ebpf.Program {
	p := t.progs[l3off]
	if p == nil {
		return nil
	}
	switch name {
	case "xl_pod_out":
		return p.XlPodOut
	case "xl_podhost_out":
		return p.XlPodhostOut
	case "xl_pod_in":
		return p.XlPodIn
	case "xl_host_out":
		return p.XlHostOut
	case "xl_host_in":
		return p.XlHostIn
	case "xl_host_local":
		return p.XlHostLocal
	}
	return nil
}

// Attachment identifies one interface to attach to.
type Attachment struct {
	// Netns is the path of the network namespace the interface lives in
	// (e.g. /proc/<pid>/ns/net or /var/run/netns/cni-...). Empty means the
	// agent's own (host) network namespace.
	Netns  string
	Ifname string
	Kind   Kind
}

func (a Attachment) String() string {
	ns := a.Netns
	if ns == "" {
		ns = "host"
	}
	return fmt.Sprintf("%s/%s(%s)", ns, a.Ifname, a.Kind)
}

// netnsID returns a stable identifier of the namespace for pin names.
func netnsID(path string) (string, error) {
	if path == "" {
		return "host", nil
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", fmt.Errorf("phantom: stat netns %s: %w", path, err)
	}
	return fmt.Sprintf("ns%d", st.Ino), nil
}

// pinName: <ns>:<ifname>:<kind>:<dir>:<l3off>. ':' is not allowed in
// interface names, so the name parses unambiguously.
func pinName(ns, ifname string, k Kind, d hookDir, l3off uint32) string {
	return fmt.Sprintf("%s:%s:%s:%s:%d", ns, pinEscape(ifname), k, d, l3off)
}

// pinEscaper keeps name components valid in bpffs and parseable: bpffs
// rejects any file name containing '.' with EPERM (dots are reserved for
// its own files) – found with flannel.1; vxlan.calico and VLAN devices
// (eth0.100) have dots too. ':' is our separator, '/' a path separator.
var pinEscaper = strings.NewReplacer("%", "%25", ".", "%2E", ":", "%3A", "/", "%2F")

func pinEscape(s string) string { return pinEscaper.Replace(s) }

type pinInfo struct {
	ns, ifname string
	kind       Kind
	dir        hookDir
	l3off      uint32
	legacy     bool
	// legacy markers only: filter priority and netns path ("" = the
	// agent's own netns).
	prio      uint16
	netnsPath string
}

// legacyMarker is the pin name recording a legacy cls_bpf attachment:
// <pinName>:legacy:<prio>:<url-escaped netns path>.
func legacyMarker(pin string, prio uint16, netnsPath string) string {
	return fmt.Sprintf("%s:legacy:%d:%s", pin, prio, pinEscape(netnsPath))
}

func parsePin(name string) (pinInfo, bool) {
	var info pinInfo
	if i := strings.Index(name, ":legacy:"); i >= 0 {
		rest := strings.SplitN(name[i+len(":legacy:"):], ":", 2)
		if len(rest) != 2 {
			return pinInfo{}, false
		}
		if _, err := fmt.Sscanf(rest[0], "%d", &info.prio); err != nil {
			return pinInfo{}, false
		}
		p, err := url.PathUnescape(rest[1])
		if err != nil {
			return pinInfo{}, false
		}
		info.netnsPath, info.legacy = p, true
		name = name[:i]
	}
	f := strings.Split(name, ":")
	if len(f) != 5 {
		return pinInfo{}, false
	}
	if _, err := fmt.Sscanf(f[4], "%d", &info.l3off); err != nil {
		return pinInfo{}, false
	}
	ifname, err := url.PathUnescape(f[1])
	if err != nil {
		return pinInfo{}, false
	}
	info.ns, info.ifname, info.kind, info.dir = f[0], ifname, Kind(f[2]), hookDir(f[3])
	return info, true
}

// inNetns runs fn on an OS thread switched into the given network namespace.
func inNetns(path string, fn func() error) error {
	if path == "" {
		return fn()
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer orig.Close()
		target, err := netns.GetFromPath(path)
		if err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("phantom: open netns %s: %w", path, err)
			return
		}
		defer target.Close()
		if err := netns.Set(target); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("phantom: enter netns %s: %w", path, err)
			return
		}
		ferr := fn()
		if err := netns.Set(orig); err != nil {
			// Leave the thread locked: the runtime terminates it when this
			// goroutine exits, so no goroutine ever runs in the wrong netns.
			errc <- errors.Join(ferr, fmt.Errorf("phantom: restore netns: %w", err))
			return
		}
		runtime.UnlockOSThread()
		errc <- ferr
	}()
	return <-errc
}

func l3offFor(l netlink.Link) uint32 {
	if l.Attrs().EncapType == "ether" || len(l.Attrs().HardwareAddr) == 6 {
		return 14
	}
	return 0
}

const legacyHandle = 0x7061 // "pa"

// Attach attaches the programs for a.Kind to the interface. It is
// idempotent: an existing pinned link is re-used (and switched to the
// currently loaded program); a stale one (interface gone) is replaced.
//
// TCX (kernel >= 6.6) is used when available, anchored at the head of the
// chain so the translation runs before any CNI program on the same hook.
// Otherwise the programs are installed as legacy cls_bpf filters on a
// clsact qdisc with Options.LegacyPriority.
func (t *Translator) Attach(a Attachment) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	hooks, err := hooksFor(a.Kind)
	if err != nil {
		return err
	}
	ns, err := netnsID(a.Netns)
	if err != nil {
		return err
	}
	return inNetns(a.Netns, func() error {
		l, err := netlink.LinkByName(a.Ifname)
		if err != nil {
			return fmt.Errorf("phantom: interface %s: %w", a, err)
		}
		off := l3offFor(l)
		for _, h := range hooks {
			prog := t.program(off, h.prog)
			if prog == nil {
				return fmt.Errorf("phantom: program %s not loaded", h.prog)
			}
			pin := filepath.Join(t.linksDir(), pinName(ns, a.Ifname, a.Kind, h.dir, off))
			if !t.opts.ForceLegacyTC {
				err := t.attachTCX(l.Attrs().Index, a, h, prog, pin, ns, off)
				if err == nil {
					continue
				}
				if !errors.Is(err, ebpf.ErrNotSupported) {
					return err
				}
			}
			if err := t.attachLegacy(l, h, prog, pin, a.Netns); err != nil {
				return err
			}
		}
		return nil
	})
}

func attachType(d hookDir) ebpf.AttachType {
	if d == dirIngress {
		return ebpf.AttachTCXIngress
	}
	return ebpf.AttachTCXEgress
}

func (t *Translator) attachTCX(ifindex int, a Attachment, h hook, prog *ebpf.Program, pin, ns string, off uint32) error {
	if old, err := link.LoadPinnedLink(pin, nil); err == nil {
		info, ierr := old.Info()
		if ierr == nil && info.TCX() != nil && int(info.TCX().Ifindex) == ifindex {
			uerr := old.Update(prog)
			old.Close()
			return uerr
		}
		// Stale: interface was deleted (and maybe re-created with the
		// same name). Drop the old pin and attach fresh.
		_ = old.Unpin()
		old.Close()
	}
	anchor := link.Head()
	if a.Kind == KindHostLocal {
		// The host-local bypass must see packets AFTER xl_podhost_out (if
		// that is attached host-side on the same veth), i.e. translated
		// to the wire tuple.
		peer := filepath.Join(t.linksDir(), pinName(ns, a.Ifname, KindPodHostSide, dirIngress, off))
		if pl, err := link.LoadPinnedLink(peer, nil); err == nil {
			anchor = link.AfterLink(pl)
			defer pl.Close()
		}
	}
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attachType(h.dir),
		Anchor:    anchor,
	})
	if err != nil {
		return err
	}
	defer l.Close()
	if err := l.Pin(pin); err != nil {
		_ = l.Detach()
		return fmt.Errorf("phantom: pin link %s: %w", pin, err)
	}
	return nil
}

func legacyFilter(l netlink.Link, d hookDir, prio uint16) *netlink.BpfFilter {
	parent := uint32(netlink.HANDLE_MIN_INGRESS)
	if d == dirEgress {
		parent = netlink.HANDLE_MIN_EGRESS
	}
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: l.Attrs().Index,
			Parent:    parent,
			Handle:    legacyHandle,
			Priority:  prio,
			Protocol:  unix.ETH_P_ALL,
		},
		Name:         "paguro-phantom",
		DirectAction: true,
	}
}

func (t *Translator) attachLegacy(l netlink.Link, h hook, prog *ebpf.Program, pin, netnsPath string) error {
	q := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: l.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(q); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("phantom: add clsact on %s: %w", l.Attrs().Name, err)
	}
	f := legacyFilter(l, h.dir, t.opts.LegacyPriority)
	f.Fd = prog.FD()
	if err := netlink.FilterReplace(f); err != nil {
		return fmt.Errorf("phantom: add cls_bpf filter on %s %s: %w", l.Attrs().Name, h.dir, err)
	}
	// Record the attachment so Cleanup/Attachments know about it. bpffs
	// only holds BPF objects, so we pin the program under the link name.
	// A fresh object (not prog itself) is pinned: Program.Pin renames an
	// existing pin, which would move the marker of another interface.
	removeLegacyMarkers(pin)
	lp := legacyMarker(pin, t.opts.LegacyPriority, netnsPath)
	pi, err := prog.Info()
	if err != nil {
		return err
	}
	id, _ := pi.ID()
	marker, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return err
	}
	defer marker.Close()
	if err := marker.Pin(lp); err != nil {
		return fmt.Errorf("phantom: pin legacy marker: %w", err)
	}
	return nil
}

// Detach removes the programs of a.Kind from the interface. Idempotent.
func (t *Translator) Detach(a Attachment) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	hooks, err := hooksFor(a.Kind)
	if err != nil {
		return err
	}
	ns, err := netnsID(a.Netns)
	if err != nil {
		return err
	}
	var errs []error
	for _, h := range hooks {
		for _, off := range []uint32{14, 0} {
			pin := filepath.Join(t.linksDir(), pinName(ns, a.Ifname, a.Kind, h.dir, off))
			if err := detachPin(pin); err != nil {
				errs = append(errs, err)
			}
			for _, m := range legacyMarkers(pin) {
				info, _ := parsePin(filepath.Base(m))
				err := inNetns(a.Netns, func() error {
					return detachLegacy(a.Ifname, h.dir, info.prio)
				})
				if err != nil {
					errs = append(errs, err)
				}
				_ = os.Remove(m)
			}
		}
	}
	return errors.Join(errs...)
}

func detachPin(pin string) error {
	l, err := link.LoadPinnedLink(pin, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		// Not a link (or unreadable): remove the pin anyway.
		return os.Remove(pin)
	}
	defer l.Close()
	derr := l.Detach()
	if derr != nil && !errors.Is(derr, ebpf.ErrNotSupported) {
		// A defunct link (interface gone) may refuse detach; unpinning
		// drops the last reference either way.
		_ = derr
	}
	return l.Unpin()
}

func detachLegacy(ifname string, d hookDir, prio uint16) error {
	l, err := netlink.LinkByName(ifname)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	if err := netlink.FilterDel(legacyFilter(l, d, prio)); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("phantom: delete filter on %s: %w", ifname, err)
	}
	return nil
}

func legacyMarkers(pin string) []string {
	m, _ := filepath.Glob(pin + ":legacy:*")
	return m
}

func removeLegacyMarkers(pin string) {
	for _, m := range legacyMarkers(pin) {
		_ = os.Remove(m)
	}
}

// detachAllPinned detaches every pinned link (TCX) and every legacy filter
// in the host netns that is recorded under dir.
func detachAllPinned(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		info, ok := parsePin(e.Name())
		if ok && info.legacy {
			err := inNetns(info.netnsPath, func() error {
				return detachLegacy(info.ifname, info.dir, info.prio)
			})
			// A vanished pod netns took its filters with it.
			if err != nil && !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "open netns") {
				errs = append(errs, err)
			}
			_ = os.Remove(p)
			continue
		}
		if err := detachPin(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// AttachmentState describes one pinned attachment.
type AttachmentState struct {
	Netns   string // "host" or "ns<inode>"
	Ifname  string
	Kind    Kind
	Dir     string
	Legacy  bool
	Ifindex uint32 // 0 for a defunct TCX link (interface deleted)
	LinkID  uint32
}

// Attachments lists the pinned attachments.
func (t *Translator) Attachments() ([]AttachmentState, error) {
	ents, err := os.ReadDir(t.linksDir())
	if err != nil {
		return nil, err
	}
	var out []AttachmentState
	for _, e := range ents {
		info, ok := parsePin(e.Name())
		if !ok {
			continue
		}
		s := AttachmentState{Netns: info.ns, Ifname: info.ifname, Kind: info.kind, Dir: string(info.dir), Legacy: info.legacy}
		if !info.legacy {
			l, err := link.LoadPinnedLink(filepath.Join(t.linksDir(), e.Name()), nil)
			if err == nil {
				if li, err := l.Info(); err == nil {
					s.LinkID = uint32(li.ID)
					if li.TCX() != nil {
						s.Ifindex = li.TCX().Ifindex
					}
				}
				l.Close()
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Netns+out[i].Ifname+out[i].Dir < out[j].Netns+out[j].Ifname+out[j].Dir
	})
	return out, nil
}

// PruneDefunct removes pins of TCX links whose interface no longer exists
// (e.g. the pod was deleted). Returns the number of pruned links.
func (t *Translator) PruneDefunct() (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ents, err := os.ReadDir(t.linksDir())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		info, ok := parsePin(e.Name())
		if !ok || info.legacy {
			continue
		}
		p := filepath.Join(t.linksDir(), e.Name())
		l, err := link.LoadPinnedLink(p, nil)
		if err != nil {
			continue
		}
		li, err := l.Info()
		if err == nil && li.TCX() != nil && li.TCX().Ifindex == 0 {
			_ = l.Unpin()
			n++
		}
		l.Close()
	}
	return n, nil
}

// refreshPinnedLinks switches all live pinned links to the programs loaded
// by this Translator (agent upgrade) and prunes defunct ones.
func (t *Translator) refreshPinnedLinks() error {
	ents, err := os.ReadDir(t.linksDir())
	if err != nil {
		return err
	}
	for _, e := range ents {
		info, ok := parsePin(e.Name())
		if !ok || info.legacy {
			continue
		}
		hooks, err := hooksFor(info.kind)
		if err != nil {
			continue
		}
		var progName string
		for _, h := range hooks {
			if h.dir == info.dir {
				progName = h.prog
			}
		}
		prog := t.program(info.l3off, progName)
		p := filepath.Join(t.linksDir(), e.Name())
		l, err := link.LoadPinnedLink(p, nil)
		if err != nil {
			continue
		}
		li, err := l.Info()
		switch {
		case err == nil && li.TCX() != nil && li.TCX().Ifindex == 0:
			_ = l.Unpin()
		case prog != nil:
			if err := l.Update(prog); err != nil {
				l.Close()
				return fmt.Errorf("phantom: update pinned link %s: %w", e.Name(), err)
			}
		}
		l.Close()
	}
	return nil
}

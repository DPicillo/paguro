// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criuimg

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	fdTypeInetSk = 4 // FileEntry.type INETSK
	afInet       = 2
	afInet6      = 10
	ipprotoUDP   = 17
)

// Sockets summarizes the inet sockets of a dump.
type Sockets struct {
	// Addrs are the local addresses the sockets are bound to – exactly
	// what the restore binds them to again – except wildcard, loopback and
	// link-local addresses. Unlike sock_diag on a live namespace this
	// includes sockets that are bound but closed (TCP_CLOSE after the peer
	// reset the connection), which older kernels do not report.
	Addrs []netip.Addr
	// UDPServerPorts are the ports of unconnected UDP sockets that are not
	// bound to loopback: servers that answer whoever writes to them (game
	// servers, QUIC, DNS).
	UDPServerPorts []uint16
}

// ListSockets reads the inet sockets of a dump from its files.img. A dump
// without files.img has none.
func ListSockets(dir string) (Sockets, error) {
	var out Sockets
	img, err := readImage(filepath.Join(dir, "files.img"), filesMagic)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	for _, e := range img.entries {
		f, err := fields(e)
		if err != nil {
			return out, err
		}
		if typ, _ := u64(f, 1); typ != fdTypeInetSk {
			continue
		}
		isk, ok := f[4] // FileEntry.isk
		if !ok || len(isk) == 0 {
			continue
		}
		b, ok := isk[0].([]byte)
		if !ok {
			continue
		}
		sk, err := fields(b)
		if err != nil {
			return out, err
		}
		a, ok := sockAddr(sk)
		if !ok {
			continue
		}
		if !a.IsUnspecified() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !slices.Contains(out.Addrs, a) {
			out.Addrs = append(out.Addrs, a)
		}
		proto, _ := u64(sk, 5)
		srcPort, _ := u64(sk, 7)
		dstPort, _ := u64(sk, 8)
		if proto == ipprotoUDP && dstPort == 0 && srcPort != 0 && !a.IsLoopback() && !slices.Contains(out.UDPServerPorts, uint16(srcPort)) {
			out.UDPServerPorts = append(out.UDPServerPorts, uint16(srcPort))
		}
	}
	slices.SortFunc(out.Addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	slices.Sort(out.UDPServerPorts)
	return out, nil
}

// sockAddr decodes InetSkEntry.src_addr: the words of the kernel's
// in_addr/in6_addr as CRIU copied them from memory (network byte order
// bytes, read as native uint32s).
func sockAddr(sk map[protowire.Number][]any) (netip.Addr, bool) {
	family, _ := u64(sk, 3)
	var words []uint32
	for _, v := range sk[11] {
		switch x := v.(type) {
		case uint64:
			words = append(words, uint32(x))
		case []byte: // packed encoding
			for len(x) > 0 {
				w, n := protowire.ConsumeVarint(x)
				if n < 0 {
					return netip.Addr{}, false
				}
				words = append(words, uint32(w))
				x = x[n:]
			}
		}
	}
	raw := make([]byte, 4*len(words))
	for i, w := range words {
		binary.NativeEndian.PutUint32(raw[4*i:], w)
	}
	switch {
	case family == afInet && len(raw) >= 4:
		return netip.AddrFrom4([4]byte(raw[:4])), true
	case family == afInet6 && len(raw) == 16:
		return netip.AddrFrom16([16]byte(raw)).Unmap(), true
	}
	return netip.Addr{}, false
}

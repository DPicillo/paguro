// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criuimg

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
)

// The addresses a restore binds: a closed TCP socket still bound to an IP
// from two migrations ago is listed; wildcard, loopback and duplicates are
// not; a v4-mapped IPv6 socket address is unmapped. The UDP server ports:
// unconnected UDP sockets except those on loopback.
func TestListSockets(t *testing.T) {
	dir := t.TempDir()
	if got, err := ListSockets(dir); err != nil || got.Addrs != nil || got.UDPServerPorts != nil {
		t.Fatalf("no files image: %+v %v", got, err)
	}
	words := func(a string) []uint64 {
		b := netip.MustParseAddr(a).AsSlice()
		var out []uint64
		for i := 0; i < len(b); i += 4 {
			out = append(out, uint64(binary.NativeEndian.Uint32(b[i:])))
		}
		return out
	}
	const tcp, udp = 6, ipprotoUDP
	sk := func(id, family, proto, srcPort, dstPort uint64, addr string) []byte {
		f := []any{1, id, 2, id, 3, family, 5, proto, 6, uint64(7), 7, srcPort, 8, dstPort}
		for _, w := range words(addr) {
			f = append(f, 11, w)
		}
		return msg(1, uint64(fdTypeInetSk), 2, id, 4, msg(f...))
	}
	writeImg(t, filepath.Join(dir, "files.img"), filesMagic,
		sk(1, afInet, tcp, 46422, 443, "10.246.3.3"),          // closed, bound to an old IP
		sk(2, afInet, udp, 19132, 0, "0.0.0.0"),               // UDP server, wildcard
		sk(3, afInet, udp, 5353, 0, "127.0.0.1"),              // UDP on loopback
		sk(4, afInet6, tcp, 8080, 51000, "::ffff:10.246.2.5"), // dual-stack socket, IPv4 client
		sk(5, afInet6, udp, 19133, 0, "::"),                   // UDP server, IPv6 wildcard
		sk(6, afInet6, tcp, 9000, 0, "fd00::5"),               // IPv6 listener on an address
		sk(7, afInet, udp, 40000, 53, "10.246.3.3"),           // connected UDP: a client
		sk(8, afInet, udp, 19132, 0, "0.0.0.0"),               // duplicate port
		msg(1, uint64(1), 2, uint64(9), 3, msg(1, uint64(9)))) // a regular file
	got, err := ListSockets(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantAddrs := []netip.Addr{netip.MustParseAddr("10.246.2.5"), netip.MustParseAddr("10.246.3.3"), netip.MustParseAddr("fd00::5")}
	if !slices.Equal(got.Addrs, wantAddrs) {
		t.Errorf("addresses: got %v, want %v", got.Addrs, wantAddrs)
	}
	if want := []uint16{19132, 19133}; !slices.Equal(got.UDPServerPorts, want) {
		t.Errorf("UDP server ports: got %v, want %v", got.UDPServerPorts, want)
	}
}

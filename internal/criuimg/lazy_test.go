// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criuimg

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func msg(fields ...any) []byte {
	var b []byte
	for i := 0; i < len(fields); i += 2 {
		num := protowire.Number(fields[i].(int))
		switch v := fields[i+1].(type) {
		case uint64:
			b = protowire.AppendTag(b, num, protowire.VarintType)
			b = protowire.AppendVarint(b, v)
		case []byte:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendBytes(b, v)
		}
	}
	return b
}

func writeImg(t *testing.T, path string, magic uint32, entries ...[]byte) {
	t.Helper()
	var out []byte
	out = binary.LittleEndian.AppendUint32(out, imgCommonMagic)
	out = binary.LittleEndian.AppendUint32(out, magic)
	for _, e := range entries {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(e)))
		out = append(out, e...)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	heap = 0x100000 // anonymous private, 64 pages
	file = 0x200000 // file-backed (not lazy), 4 pages
)

var stack = heap + 10*pageSize

func setup(t *testing.T) string {
	dir := t.TempDir()
	// mm-1.img: heap VMA (anon|private) and a file mapping (private only)
	heapVMA := msg(1, uint64(heap), 2, uint64(heap+64*pageSize), 6, uint64(mapAnonymous|mapPrivate), 7, uint64(1))
	fileVMA := msg(1, uint64(file), 2, uint64(file+4*pageSize), 6, uint64(mapPrivate), 7, uint64(1))
	writeImg(t, filepath.Join(dir, "mm-1.img"), mmMagic, msg(1, uint64(1), 14, heapVMA, 14, fileVMA))
	// core-1.img: sp in page 10 of the heap (thread stack inside the heap, as with Go)
	regs := msg(20, uint64(stack+128))
	writeImg(t, filepath.Join(dir, "core-1.img"), coreMagic, msg(1, uint64(1), 2, msg(2, regs)))
	// pagemap-1.img: head, one parent entry over the whole heap, one present
	// lazy entry CRIU wrote itself, one parent entry over the file mapping.
	head := msg(1, uint64(1))
	parentHeap := pagemapEntry{vaddr: heap, nrPages: 64, flags: PEParent}.encode()
	present := pagemapEntry{vaddr: heap + 64*pageSize, nrPages: 1, flags: PEPresent | PELazy}.encode()
	parentFile := pagemapEntry{vaddr: file, nrPages: 4, flags: PEParent}.encode()
	writeImg(t, filepath.Join(dir, "pagemap-1.img"), pagemapMagic, head, parentHeap, present, parentFile)
	return dir
}

func TestMakeParentPagesLazy(t *testing.T) {
	dir := setup(t)
	st, err := MakeParentPagesLazy(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 64 heap pages minus the stack page and the page below it.
	if st.LazyPages != 62 || st.EagerPages != 2+4 || st.AlreadyLazy != 1 {
		t.Fatalf("stats %+v", st)
	}
	img, err := readImage(filepath.Join(dir, "pagemap-1.img"), pagemapMagic)
	if err != nil {
		t.Fatal(err)
	}
	var got []pagemapEntry
	for _, raw := range img.entries[1:] {
		e, _ := decodePagemapEntry(raw)
		got = append(got, e)
	}
	// heap[0..9) lazy, heap[9..11) eager (red zone + sp page), heap[11..64) lazy,
	// CRIU's present entry untouched, file mapping eager.
	want := []pagemapEntry{
		{vaddr: heap, nrPages: 9, flags: PEParent | PELazy},
		{vaddr: heap + 9*pageSize, nrPages: 2, flags: PEParent},
		{vaddr: heap + 11*pageSize, nrPages: 53, flags: PEParent | PELazy},
		{vaddr: heap + 64*pageSize, nrPages: 1, flags: PEPresent | PELazy},
		{vaddr: file, nrPages: 4, flags: PEParent},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	for i := range want {
		if got[i].vaddr != want[i].vaddr || got[i].nrPages != want[i].nrPages || got[i].flags != want[i].flags {
			t.Fatalf("entry %d: got %+v want %+v", i, got[i], want[i])
		}
	}
	// Page count is preserved exactly.
	var total uint64
	for _, e := range got {
		total += e.nrPages
	}
	if total != 64+1+4 {
		t.Fatalf("pages %d", total)
	}
	// Idempotent: a second run changes nothing.
	st2, err := MakeParentPagesLazy(dir)
	if err != nil || st2.LazyPages != 0 || st2.AlreadyLazy != 62+1 {
		t.Fatalf("second run: %+v %v", st2, err)
	}
}

// The direct decoder reads what the generic one read.
func TestDecodePagemapEntryMatchesGeneric(t *testing.T) {
	parent := uint64(1)
	for _, e := range []pagemapEntry{
		{vaddr: 0x7f0000000000, nrPages: 3, flags: PEPresent},
		{vaddr: 0x1000, nrPages: 1 << 33, flags: PEParent | PELazy},
		{vaddr: 0x2000, nrPages: 7, flags: PEParent, inParent: &parent},
	} {
		b := e.encode()
		got, err := decodePagemapEntry(b)
		if err != nil {
			t.Fatal(err)
		}
		f, err := fields(b)
		if err != nil {
			t.Fatal(err)
		}
		want := pagemapEntry{}
		want.vaddr, _ = u64(f, 1)
		if n, ok := u64(f, 5); ok {
			want.nrPages = n
		} else {
			want.nrPages, _ = u64(f, 2)
		}
		want.flags, _ = u64(f, 4)
		if got.vaddr != want.vaddr || got.nrPages != want.nrPages || got.flags != want.flags ||
			(got.inParent == nil) != (e.inParent == nil) {
			t.Fatalf("decoded %+v, want %+v", got, want)
		}
	}
	// Without field 5 the 32-bit count counts.
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 0x3000)
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, 9)
	if got, err := decodePagemapEntry(b); err != nil || got.nrPages != 9 || got.vaddr != 0x3000 {
		t.Fatalf("old entry: %+v %v", got, err)
	}
}

func BenchmarkDecodePagemapEntry(b *testing.B) {
	raw := pagemapEntry{vaddr: 0x7f0000000000, nrPages: 3, flags: PEParent}.encode()
	for b.Loop() {
		if _, err := decodePagemapEntry(raw); err != nil {
			b.Fatal(err)
		}
	}
}

// A zombie in the process tree (no registers in its core image) does not
// turn the lazy restore into an eager one.
func TestStackPagesSkipsZombies(t *testing.T) {
	dir := setup(t)
	zombie := msg(1, uint64(1), 3, msg(1, uint64(taskDead), 2, uint64(0)))
	writeImg(t, filepath.Join(dir, "core-2.img"), coreMagic, zombie)
	pages, err := stackPages(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Fatalf("stack pages %v: want the live thread's two", pages)
	}
	// A live task without registers is still an error (unknown architecture).
	writeImg(t, filepath.Join(dir, "core-3.img"), coreMagic, msg(1, uint64(1), 3, msg(1, uint64(1), 2, uint64(0))))
	if _, err := stackPages(dir); err == nil {
		t.Fatal("a live task without thread_info was ignored")
	}
}

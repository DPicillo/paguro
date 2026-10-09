// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package criuimg reads and rewrites the few CRIU image files Paguro needs to
// touch, without depending on CRIU's generated protobuf code.
//
// The one rewrite it performs makes pre-copy and post-copy work together.
//
// Pre-copy leaves the bulk of a container's memory in parent images: the
// final dump only writes the pages dirtied since the last round and records
// every other page as "in parent" (PE_PARENT). CRIU marks pages as lazily
// restorable (PE_LAZY) only when it writes them itself, so with a pre-copy
// chain almost every page is restored eagerly – the whole RSS is copied into
// the new process before it may run (measured: 1 GiB → 1.87 s inside the
// freeze, 448 of ~262,000 pages lazy).
//
// CRIU's design assumes remote post-copy, where parent pages are already
// local and only the last dirty pages must come lazily from the source. In
// Paguro every page is already on the target, so all of them can be lazy.
// MakeParentPagesLazy sets PE_LAZY on the in-parent entries of the final
// pagemap using exactly the rule CRIU applies at dump time
// (vma_entry_can_be_lazy and !is_stack in criu/mem.c):
//
//   - the VMA is MAP_ANONYMOUS|MAP_PRIVATE, not MAP_LOCKED, not MAP_HUGETLB,
//     and not the vDSO, vvar or vsyscall area;
//   - the page is not a thread's current stack page (CRIU needs it before
//     userfaultfd is set up); as an extra margin the page below the stack
//     pointer (x86 red zone) is kept eager too.
//
// Only in-parent entries are touched: they carry no data in the pages file,
// so splitting them at excluded pages or VMA boundaries cannot shift the data
// of any other entry. Entries CRIU wrote itself keep their flags.
package criuimg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// Image magics (criu/include/magic.h).
const (
	imgCommonMagic = 0x54564319
	pagemapMagic   = 0x56084025
	mmMagic        = 0x57492820
	coreMagic      = 0x55053847
)

// Pagemap flags (criu/include/pagemap.h).
const (
	PEParent  = 1 << 0
	PELazy    = 1 << 1
	PEPresent = 1 << 2
)

// VMA status bits (criu/include/image.h) and mmap flags.
const (
	vmaAreaVsyscall = 1 << 2
	vmaAreaVDSO     = 1 << 3
	vmaAreaVVAR     = 1 << 12

	mapPrivate   = 0x02
	mapAnonymous = 0x20
	mapLocked    = 0x2000
	mapHugeTLB   = 0x040000
)

// pageSize is the page size of this machine. CRIU images use the page size
// of the kernel that dumped them, and a restore needs the same: 4 KiB on
// x86-64, 4 or 64 KiB on arm64 depending on the distribution.
var pageSize = uint64(os.Getpagesize())

// image is a CRIU image: the magic header and length-prefixed entries.
type image struct {
	magics  []uint32
	entries [][]byte
}

func readImage(path string, typeMagic uint32) (*image, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	img := &image{}
	off := 0
	readU32 := func() (uint32, error) {
		if off+4 > len(b) {
			return 0, io.ErrUnexpectedEOF
		}
		v := binary.LittleEndian.Uint32(b[off:])
		off += 4
		return v, nil
	}
	m, err := readU32()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	img.magics = append(img.magics, m)
	if m == imgCommonMagic {
		if m, err = readU32(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		img.magics = append(img.magics, m)
	}
	if m != typeMagic {
		return nil, fmt.Errorf("%s: unexpected magic %#x", path, m)
	}
	for off < len(b) {
		n, err := readU32()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if off+int(n) > len(b) {
			return nil, fmt.Errorf("%s: truncated entry", path)
		}
		img.entries = append(img.entries, b[off:off+int(n)])
		off += int(n)
	}
	return img, nil
}

func (img *image) write(path string) error {
	var out []byte
	for _, m := range img.magics {
		out = binary.LittleEndian.AppendUint32(out, m)
	}
	for _, e := range img.entries {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(e)))
		out = append(out, e...)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp := path + ".paguro-tmp"
	if err := os.WriteFile(tmp, out, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// fields decodes a flat protobuf message into field number → raw values.
// Varints are returned as uint64, length-delimited fields as []byte.
func fields(msg []byte) (map[protowire.Number][]any, error) {
	out := map[protowire.Number][]any{}
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		msg = msg[n:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(msg)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			out[num] = append(out[num], v)
			msg = msg[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(msg)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			out[num] = append(out[num], v)
			msg = msg[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, msg)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			msg = msg[n:]
		}
	}
	return out, nil
}

func u64(f map[protowire.Number][]any, n protowire.Number) (uint64, bool) {
	if v, ok := f[n]; ok && len(v) > 0 {
		if x, ok := v[0].(uint64); ok {
			return x, true
		}
	}
	return 0, false
}

// vma is the part of a VmaEntry the lazy rule needs.
type vma struct {
	start, end    uint64
	flags, status uint64
}

func (v vma) canBeLazy() bool {
	return v.flags&mapAnonymous != 0 && v.flags&mapPrivate != 0 &&
		v.flags&mapLocked == 0 && v.flags&mapHugeTLB == 0 &&
		v.status&(vmaAreaVDSO|vmaAreaVVAR|vmaAreaVsyscall) == 0
}

func readVMAs(path string) ([]vma, error) {
	img, err := readImage(path, mmMagic)
	if err != nil {
		return nil, err
	}
	if len(img.entries) != 1 {
		return nil, fmt.Errorf("%s: expected 1 mm entry, got %d", path, len(img.entries))
	}
	mm, err := fields(img.entries[0])
	if err != nil {
		return nil, err
	}
	var vmas []vma
	for _, raw := range mm[14] { // repeated vma_entry vmas = 14
		b, ok := raw.([]byte)
		if !ok {
			continue
		}
		f, err := fields(b)
		if err != nil {
			return nil, err
		}
		v := vma{}
		v.start, _ = u64(f, 1)
		v.end, _ = u64(f, 2)
		v.flags, _ = u64(f, 6)
		v.status, _ = u64(f, 7)
		vmas = append(vmas, v)
	}
	sort.Slice(vmas, func(i, j int) bool { return vmas[i].start < vmas[j].start })
	return vmas, nil
}

// stackPages collects the pages that must stay eager: each thread's current
// stack page and the page below it (core-*.img, the thread's stack pointer).
func stackPages(dir string) ([]uint64, error) {
	paths, _ := filepath.Glob(filepath.Join(dir, "core-*.img"))
	if len(paths) == 0 {
		return nil, errors.New("no core images")
	}
	set := map[uint64]bool{}
	for _, p := range paths {
		img, err := readImage(p, coreMagic)
		if err != nil {
			return nil, err
		}
		if len(img.entries) == 0 {
			continue
		}
		core, err := fields(img.entries[0])
		if err != nil {
			return nil, err
		}
		// A zombie has no registers and no stack. Measured: the Minecraft
		// image's server runner had an exited child not yet reaped, and the
		// missing thread_info turned the lazy restore into an eager one
		// (4.9 s instead of ~0.3 s inside the freeze).
		if taskState(core) == taskDead {
			continue
		}
		sp, err := stackPointer(core)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		page := sp &^ (pageSize - 1)
		set[page] = true
		set[page-pageSize] = true
	}
	out := make([]uint64, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// pagemapEntry mirrors PagemapEntry.
type pagemapEntry struct {
	vaddr, nrPages uint64
	flags          uint64
	inParent       *uint64
}

// decodePagemapEntry decodes a PagemapEntry directly: a pagemap of an
// 8 GiB process has ~730,000 entries, and the generic fields() (a map per
// entry, values boxed) took 190 ms to read them against 56 ms this way –
// inside the freeze, where the wrapper marks parent pages lazy. As with
// fields()/u64, the first occurrence of a field counts; nr_pages (5)
// overrides the older 32-bit field 2.
func decodePagemapEntry(b []byte) (pagemapEntry, error) {
	var e pagemapEntry
	var seen uint8 // bit n: field n set
	var nr32 uint64
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return pagemapEntry{}, protowire.ParseError(n)
		}
		b = b[n:]
		if typ != protowire.VarintType || num < 1 || num > 5 {
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return pagemapEntry{}, protowire.ParseError(n)
			}
			b = b[n:]
			continue
		}
		v, n := protowire.ConsumeVarint(b)
		if n < 0 {
			return pagemapEntry{}, protowire.ParseError(n)
		}
		b = b[n:]
		if seen&(1<<num) != 0 {
			continue
		}
		seen |= 1 << num
		switch num {
		case 1:
			e.vaddr = v
		case 2:
			nr32 = v
		case 3:
			parent := v // only this field escapes to the heap
			e.inParent = &parent
		case 4:
			e.flags = v
		case 5:
			e.nrPages = v
		}
	}
	if seen&(1<<5) == 0 {
		e.nrPages = nr32
	}
	return e, nil
}

func (e pagemapEntry) encode() []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, e.vaddr)
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, e.nrPages&0xffffffff)
	if e.inParent != nil {
		b = protowire.AppendTag(b, 3, protowire.VarintType)
		b = protowire.AppendVarint(b, *e.inParent)
	}
	b = protowire.AppendTag(b, 4, protowire.VarintType)
	b = protowire.AppendVarint(b, e.flags)
	b = protowire.AppendTag(b, 5, protowire.VarintType)
	b = protowire.AppendVarint(b, e.nrPages)
	return b
}

// Stats reports what MakeParentPagesLazy changed.
type Stats struct {
	Processes      int
	LazyPages      uint64 // in-parent pages newly marked lazy
	EagerPages     uint64 // in-parent pages that stay eager (not eligible)
	AlreadyLazy    uint64 // pages CRIU itself marked lazy
	StackPagesKept int
}

// MakeParentPagesLazy rewrites every pagemap-<pid>.img in dir (the final
// image directory of a pre-copy chain) as described in the package comment.
// It is idempotent.
func MakeParentPagesLazy(dir string) (Stats, error) {
	var st Stats
	stacks, err := stackPages(dir)
	if err != nil {
		return st, err
	}
	st.StackPagesKept = len(stacks)
	paths, _ := filepath.Glob(filepath.Join(dir, "pagemap-*.img"))
	for _, p := range paths {
		base := filepath.Base(p)
		if strings.HasPrefix(base, "pagemap-shmem") {
			continue // shared memory is never lazy
		}
		pid := strings.TrimSuffix(strings.TrimPrefix(base, "pagemap-"), ".img")
		vmas, err := readVMAs(filepath.Join(dir, "mm-"+pid+".img"))
		if err != nil {
			return st, err
		}
		img, err := readImage(p, pagemapMagic)
		if err != nil {
			return st, err
		}
		if len(img.entries) == 0 {
			continue
		}
		out := [][]byte{img.entries[0]} // pagemap_head
		for _, raw := range img.entries[1:] {
			e, err := decodePagemapEntry(raw)
			if err != nil {
				return st, fmt.Errorf("%s: %w", p, err)
			}
			if e.flags&PELazy != 0 {
				st.AlreadyLazy += e.nrPages
			}
			if e.flags&PEParent == 0 || e.flags&PELazy != 0 || e.flags&PEPresent != 0 {
				out = append(out, raw) // CRIU's own decision – untouched
				continue
			}
			for _, part := range splitLazy(e, vmas, stacks) {
				if part.flags&PELazy != 0 {
					st.LazyPages += part.nrPages
				} else {
					st.EagerPages += part.nrPages
				}
				out = append(out, part.encode())
			}
		}
		img.entries = out
		if err := img.write(p); err != nil {
			return st, err
		}
		st.Processes++
	}
	return st, nil
}

// splitLazy splits an in-parent entry into runs of equal laziness. It jumps
// from boundary to boundary (VMA edges and kept stack pages) instead of
// visiting every page: the rewrite runs inside the freeze, and an 8 GiB
// container has two million pages.
func splitLazy(e pagemapEntry, vmas []vma, stacks []uint64) []pagemapEntry {
	end := e.vaddr + e.nrPages*pageSize
	var out []pagemapEntry
	emit := func(from, to uint64, lazy bool) {
		if to <= from {
			return
		}
		if n := len(out); n > 0 {
			last := &out[n-1]
			if (last.flags&PELazy != 0) == lazy && last.vaddr+last.nrPages*pageSize == from {
				last.nrPages += (to - from) / pageSize
				return
			}
		}
		part := e
		part.vaddr, part.nrPages = from, (to-from)/pageSize
		if lazy {
			part.flags |= PELazy
		}
		out = append(out, part)
	}
	for addr := e.vaddr; addr < end; {
		i := sort.Search(len(vmas), func(i int) bool { return vmas[i].end > addr })
		if i == len(vmas) || vmas[i].start > addr {
			// Not inside a known VMA: keep eager up to the next VMA.
			next := end
			if i < len(vmas) && vmas[i].start < end {
				next = vmas[i].start
			}
			emit(addr, next, false)
			addr = next
			continue
		}
		runEnd := min(vmas[i].end, end)
		if !vmas[i].canBeLazy() {
			emit(addr, runEnd, false)
			addr = runEnd
			continue
		}
		// Lazy run, interrupted by kept stack pages.
		j := sort.Search(len(stacks), func(j int) bool { return stacks[j] >= addr })
		if j < len(stacks) && stacks[j] < runEnd {
			if stacks[j] == addr {
				emit(addr, addr+pageSize, false)
				addr += pageSize
				continue
			}
			runEnd = stacks[j]
		}
		emit(addr, runEnd, true)
		addr = runEnd
	}
	return out
}

// Where core_entry keeps a thread's registers (criu/images/core*.proto):
// thread_info (x86-64) = 2 with gpregs = 2 and sp = 20; ti_aarch64 = 8 with
// gpregs = 3 and sp = 2.
var stackPointerPaths = []struct {
	arch                   string
	threadInfo, gpregs, sp protowire.Number
}{
	{"x86-64", 2, 2, 20},
	{"aarch64", 8, 3, 2},
}

// taskDead is TaskCoreEntry.task_state of a zombie (CRIU's TASK_DEAD).
const taskDead = 2

// taskState is the core entry's tc.task_state (0 if absent: a thread's
// core image carries no tc).
func taskState(core map[protowire.Number][]any) uint64 {
	task, ok := core[3]
	if !ok || len(task) == 0 {
		return 0
	}
	b, ok := task[0].([]byte)
	if !ok {
		return 0
	}
	f, err := fields(b)
	if err != nil {
		return 0
	}
	state, _ := u64(f, 1)
	return state
}

// stackPointer returns a thread's stack pointer from its decoded core entry.
func stackPointer(core map[protowire.Number][]any) (uint64, error) {
	for _, a := range stackPointerPaths {
		ti, ok := core[a.threadInfo]
		if !ok || len(ti) == 0 {
			continue
		}
		tiBytes, ok := ti[0].([]byte)
		if !ok {
			return 0, fmt.Errorf("%s thread_info is not a message", a.arch)
		}
		tif, err := fields(tiBytes)
		if err != nil {
			return 0, err
		}
		gp, ok := tif[a.gpregs]
		if !ok || len(gp) == 0 {
			return 0, fmt.Errorf("no %s gpregs", a.arch)
		}
		gpBytes, ok := gp[0].([]byte)
		if !ok {
			return 0, fmt.Errorf("%s gpregs is not a message", a.arch)
		}
		regs, err := fields(gpBytes)
		if err != nil {
			return 0, err
		}
		sp, ok := u64(regs, a.sp)
		if !ok {
			return 0, fmt.Errorf("no %s stack pointer", a.arch)
		}
		return sp, nil
	}
	return 0, errors.New("no thread_info for x86-64 or aarch64 (unsupported architecture)")
}

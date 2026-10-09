// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criuimg

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// writeRound writes a pagemap-1.img + pages-<id>.img. present maps page
// index (relative to vaddr 0x100000) to a fill byte; parent lists page
// indexes that are in the parent.
// writeRound writes a pre-dump round; round n > 1 gets CRIU's parent link
// to round n-1.
func writeRound(t *testing.T, dir string, pagesID uint64, entries []pagemapEntry, data [][]byte) {
	t.Helper()
	os.MkdirAll(dir, 0o700)
	if n, err := strconv.Atoi(filepath.Base(dir)); err == nil && n > 1 {
		_ = os.Symlink(fmt.Sprintf("../%d", n-1), filepath.Join(dir, "parent"))
	}
	head := msg(1, pagesID)
	var raw [][]byte
	raw = append(raw, head)
	for _, e := range entries {
		raw = append(raw, e.encode())
	}
	writeImg(t, filepath.Join(dir, "pagemap-1.img"), pagemapMagic, raw...)
	var pages []byte
	for _, d := range data {
		pages = append(pages, d...)
	}
	if err := os.WriteFile(filepath.Join(dir, "pages-1.img"), pages, 0o600); err != nil {
		t.Fatal(err)
	}
}

func page(b byte) []byte { return bytes.Repeat([]byte{b}, int(pageSize)) }

// pageAt resolves a page the way CRIU does for a final image linked to the
// compacted images: delta first (if it lists the page as present), then base.
func pageAt(t *testing.T, imagesDir string, vaddr uint64) []byte {
	t.Helper()
	for _, sub := range []string{"delta", "base"} {
		dir := filepath.Join(imagesDir, sub)
		pm, err := loadPagemap(filepath.Join(dir, "pagemap-1.img"))
		if err != nil {
			continue
		}
		if r, ok := locate(presentRuns(pm, dir), vaddr); ok {
			data, _ := os.ReadFile(r.file)
			o := r.off + int64(vaddr-r.vaddr)
			return data[o : o+int64(pageSize)]
		}
	}
	t.Fatalf("page %x not found in delta or base", vaddr)
	return nil
}

const v0 = 0x100000

func TestApplyRoundInPlaceAndDelta(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")

	// Round 1: 4 present pages A B C D → becomes the base.
	r1 := filepath.Join(root, "1")
	writeRound(t, r1, 1, []pagemapEntry{{vaddr: v0, nrPages: 4, flags: PEPresent}},
		[][]byte{page('A'), page('B'), page('C'), page('D')})
	st, err := ApplyRound(base, r1)
	if err != nil || st.Mode != "initial" {
		t.Fatalf("round 1: %+v %v", st, err)
	}

	// Round 2: pages 1 and 2 dirty (b, c), rest in parent → in place.
	r2 := filepath.Join(root, "2")
	writeRound(t, r2, 1, []pagemapEntry{
		{vaddr: v0, nrPages: 1, flags: PEParent},
		{vaddr: v0 + pageSize, nrPages: 2, flags: PEPresent},
		{vaddr: v0 + 3*pageSize, nrPages: 1, flags: PEParent},
	}, [][]byte{page('b'), page('c')})
	st, err = ApplyRound(base, r2)
	if err != nil || st.Mode != "in-place" || st.PagesInPlace != 2 {
		t.Fatalf("round 2: %+v %v", st, err)
	}

	// Round 3: a new page before and after the known range plus dirty page 3
	// → page 3 in place, the two new pages go to the delta; the base pages
	// file is never rewritten.
	baseInfo, _ := os.Stat(filepath.Join(base, "pages-1.img"))
	r3 := filepath.Join(root, "3")
	writeRound(t, r3, 1, []pagemapEntry{
		{vaddr: v0 - pageSize, nrPages: 1, flags: PEPresent},
		{vaddr: v0, nrPages: 3, flags: PEParent},
		{vaddr: v0 + 3*pageSize, nrPages: 2, flags: PEPresent},
	}, [][]byte{page('z'), page('d'), page('E')})
	st, err = ApplyRound(base, r3)
	if err != nil || st.Mode != "in-place+delta" || st.PagesInPlace != 1 || st.PagesNew != 2 {
		t.Fatalf("round 3: %+v %v", st, err)
	}
	if after, _ := os.Stat(filepath.Join(base, "pages-1.img")); !os.SameFile(baseInfo, after) || after.Size() != int64(4*pageSize) {
		t.Fatal("base pages file must be patched in place, not rewritten")
	}
	for i, want := range "zAbcdE" {
		if got := pageAt(t, root, v0-pageSize+uint64(i)*pageSize); got[0] != byte(want) {
			t.Fatalf("after round 3, page %d = %c want %c", i, got[0], want)
		}
	}

	// Round 4: dirty a delta page (E → e) → in place in the delta.
	r4 := filepath.Join(root, "4")
	writeRound(t, r4, 1, []pagemapEntry{
		{vaddr: v0 - pageSize, nrPages: 5, flags: PEParent},
		{vaddr: v0 + 4*pageSize, nrPages: 1, flags: PEPresent},
	}, [][]byte{page('e')})
	if st, err = ApplyRound(base, r4); err != nil || st.Mode != "in-place" {
		t.Fatalf("round 4: %+v %v", st, err)
	}
	if got := pageAt(t, root, v0+4*pageSize); got[0] != 'e' {
		t.Fatalf("delta page = %c", got[0])
	}
	// The delta pagemap covers every page (own present, base in parent).
	dpm, _ := loadPagemap(filepath.Join(root, "delta", "pagemap-1.img"))
	var total uint64
	for _, e := range dpm.entries {
		total += e.nrPages
	}
	if total != 6 {
		t.Fatalf("delta pagemap covers %d pages, want 6: %+v", total, dpm.entries)
	}

	// The final dump expects round 4 as parent → linked to the delta.
	final := filepath.Join(root, "final")
	os.MkdirAll(final, 0o700)
	os.Symlink("../4", filepath.Join(final, "parent"))
	ok, err := LinkFinalToBase(final, base)
	if err != nil || !ok {
		t.Fatalf("link: %v %v", ok, err)
	}
	if l, _ := os.Readlink(filepath.Join(final, "parent")); l != "../delta" {
		t.Fatalf("parent -> %s", l)
	}
	if l, _ := os.Readlink(filepath.Join(root, "delta", "parent")); l != "../base" {
		t.Fatalf("delta parent -> %s", l)
	}
}

func TestLinkFinalRefusesIncompleteBase(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	os.MkdirAll(base, 0o700)
	os.WriteFile(filepath.Join(base, "ROUND"), []byte("2"), 0o600)
	final := filepath.Join(root, "final")
	os.MkdirAll(final, 0o700)
	os.Symlink("../3", filepath.Join(final, "parent"))
	if ok, err := LinkFinalToBase(final, base); ok || err == nil {
		t.Fatalf("expected refusal, got %v %v", ok, err)
	}
	// No base at all (stop-and-copy / compaction never ran): chain stays.
	if ok, err := LinkFinalToBase(final, filepath.Join(root, "nobase")); ok || err != nil {
		t.Fatalf("expected no-op, got %v %v", ok, err)
	}
}

// Two processes, only one of them with new pages: the delta has a pagemap
// for that one alone, yet the final dump of both is linked to it. The idle
// process gets a pass-through pagemap (its base pages in-parent) – without
// it CRIU found no parent for it and the restore failed.
func TestLinkFinalCompletesDeltaForIdleProcesses(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	r1 := filepath.Join(root, "1")
	writeRound(t, r1, 1, []pagemapEntry{{vaddr: v0, nrPages: 2, flags: PEPresent}}, [][]byte{page('A'), page('B')})
	// Process 7 next to process 1 (pages-7.img, pagemap-7.img).
	writeImg(t, filepath.Join(r1, "pagemap-7.img"), pagemapMagic, msg(1, uint64(7)),
		pagemapEntry{vaddr: v0, nrPages: 1, flags: PEPresent}.encode())
	if err := os.WriteFile(filepath.Join(r1, "pages-7.img"), page('X'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRound(base, r1); err != nil {
		t.Fatal(err)
	}
	// Round 2: process 1 gets a new page (→ delta), process 7 is idle.
	r2 := filepath.Join(root, "2")
	writeRound(t, r2, 1, []pagemapEntry{
		{vaddr: v0, nrPages: 2, flags: PEParent},
		{vaddr: v0 + 2*pageSize, nrPages: 1, flags: PEPresent},
	}, [][]byte{page('C')})
	writeImg(t, filepath.Join(r2, "pagemap-7.img"), pagemapMagic, msg(1, uint64(7)),
		pagemapEntry{vaddr: v0, nrPages: 1, flags: PEParent}.encode())
	if _, err := ApplyRound(base, r2); err != nil {
		t.Fatal(err)
	}
	// The pass-through pagemap is made while the round is applied (during
	// pre-copy), not inside the freeze.
	if _, err := os.Stat(filepath.Join(root, "delta", "pagemap-7.img")); err != nil {
		t.Fatal("the idle process got no delta pagemap with the round")
	}

	final := filepath.Join(root, "final")
	os.MkdirAll(final, 0o700)
	os.Symlink("../2", filepath.Join(final, "parent"))
	if ok, err := LinkFinalToBase(final, base); err != nil || !ok {
		t.Fatalf("link: %v %v", ok, err)
	}
	if l, _ := os.Readlink(filepath.Join(final, "parent")); l != "../delta" {
		t.Fatalf("parent -> %s", l)
	}
	pm, err := loadPagemap(filepath.Join(root, "delta", "pagemap-7.img"))
	if err != nil {
		t.Fatalf("idle process has no delta pagemap: %v", err)
	}
	if len(pm.entries) != 1 || pm.entries[0].flags != PEParent || pm.entries[0].vaddr != v0 || pm.entries[0].nrPages != 1 {
		t.Fatalf("pass-through pagemap: %+v", pm.entries)
	}
	if info, err := os.Stat(pm.pagesFile(filepath.Join(root, "delta"))); err != nil || info.Size() != 0 {
		t.Fatalf("pass-through pages file: %v", err)
	}
}

// Rounds are applied in order only: a round whose parent is not the round
// the base is complete up to is refused (its predecessor was lost or failed
// halfway – applying it would leave stale pages), and a retried round is a
// no-op.
func TestApplyRoundChecksTheChain(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "base")
	round := func(n int, flags uint64) string {
		dir := filepath.Join(root, strconv.Itoa(n))
		writeRound(t, dir, 1, []pagemapEntry{{vaddr: v0, nrPages: 1, flags: flags}}, [][]byte{page(byte('a' + n))})
		return dir
	}
	if _, err := ApplyRound(base, round(1, PEPresent)); err != nil {
		t.Fatal(err)
	}
	r2 := round(2, PEPresent)
	if _, err := ApplyRound(base, r2); err != nil {
		t.Fatal(err)
	}
	// The transfer of round 2 is retried: it arrives again.
	writeRound(t, r2, 1, []pagemapEntry{{vaddr: v0, nrPages: 1, flags: PEPresent}}, [][]byte{page('x')})
	if st, err := ApplyRound(base, r2); err != nil || st.Mode != "already applied" {
		t.Fatalf("retried round: %+v %v", st, err)
	}
	if got := pageAt(t, root, v0); got[0] != 'c' {
		t.Fatalf("page %q: a retried round must not be applied twice", got[0])
	}
	// Round 3 is lost; round 4 must not be applied on top of round 2.
	round(3, PEPresent)
	if _, err := ApplyRound(base, round(4, PEPresent)); err == nil {
		t.Fatal("round 4 applied after round 2")
	}
	if b, _ := os.ReadFile(filepath.Join(base, "ROUND")); string(b) != "2" {
		t.Fatalf("ROUND = %q, want 2 (unchanged)", b)
	}
}

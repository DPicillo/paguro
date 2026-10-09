// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criuimg

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Compaction keeps the pre-copy rounds on the target as two flat images
// instead of a deep, fragmented chain.
//
// Each pre-dump round only contains the pages dirtied since the previous
// round (PE_PRESENT) and refers to its parent for everything else
// (PE_PARENT). With an application that dirties memory at random every round
// consists of tens of thousands of tiny entries, and CRIU's page reader – it
// seeks forward only and walks the chain level by level – becomes the
// bottleneck: the lazy-pages daemon transferred ~2 MB/s for an 8 GiB
// container (over an hour to bring the memory back).
//
// Layout in the container's images directory:
//
//	base/   all pages of the first round, later only patched in place
//	delta/  pages the base does not know (new mappings), parent -> ../base
//	final/  the freeze dump, parent re-linked to delta/ (or base/)
//
// ApplyRound costs O(dirty pages) for the base – it is never rewritten, which
// mattered: an earlier version rebuilt the 8 GiB base when a round contained
// a few new pages, took 62 s and stalled pre-copy long enough to dirty
// 600 MB more. Only the small delta is rewritten when new pages appear.

// pagemapImage is a decoded pagemap-<pid>.img; pages are stored in the pages
// file in pagemap order (present entries only).
type pagemapImage struct {
	img     *image
	head    []byte
	entries []pagemapEntry
	pagesID uint64
}

func loadPagemap(path string) (*pagemapImage, error) {
	img, err := readImage(path, pagemapMagic)
	if err != nil {
		return nil, err
	}
	if len(img.entries) == 0 {
		return nil, fmt.Errorf("%s: no pagemap head", path)
	}
	head, err := fields(img.entries[0])
	if err != nil {
		return nil, err
	}
	pm := &pagemapImage{img: img, head: img.entries[0]}
	pm.pagesID, _ = u64(head, 1)
	for _, raw := range img.entries[1:] {
		e, err := decodePagemapEntry(raw)
		if err != nil {
			return nil, err
		}
		pm.entries = append(pm.entries, e)
	}
	return pm, nil
}

func (pm *pagemapImage) pagesFile(dir string) string {
	return filepath.Join(dir, fmt.Sprintf("pages-%d.img", pm.pagesID))
}

func (pm *pagemapImage) save(path string) error {
	out := [][]byte{pm.head}
	for _, e := range pm.entries {
		out = append(out, e.encode())
	}
	pm.img.entries = out
	return pm.img.write(path)
}

// run is a stretch of pages and where their data lives.
type run struct {
	vaddr, n uint64
	file     string
	off      int64
}

func (r run) end() uint64 { return r.vaddr + r.n*pageSize }

// presentRuns lists the present entries of an image with their data offset.
func presentRuns(pm *pagemapImage, dir string) []run {
	var out []run
	var off int64
	for _, e := range pm.entries {
		if e.flags&PEPresent == 0 {
			continue
		}
		out = append(out, run{e.vaddr, e.nrPages, pm.pagesFile(dir), off})
		off += int64(e.nrPages) * int64(pageSize)
	}
	return out
}

// locate finds the run containing vaddr (runs sorted, non-overlapping).
func locate(runs []run, vaddr uint64) (run, bool) {
	i := sort.Search(len(runs), func(i int) bool { return runs[i].end() > vaddr })
	if i == len(runs) || runs[i].vaddr > vaddr {
		return run{}, false
	}
	return runs[i], true
}

// CompactStats reports what ApplyRound did.
type CompactStats struct {
	Mode         string // "initial", "in-place" or "in-place+delta"
	PagesInPlace uint64
	PagesNew     uint64
	Processes    int
}

// ApplyRound folds the pre-dump round in roundDir into the base (baseDir)
// and its sibling delta directory, then removes the round's page data (its
// small pagemaps stay for inspection). On success it records the round's
// name in baseDir/ROUND: base+delta are complete up to that round.
//
// Rounds must be applied in order: a round is accepted only if its parent
// is the round the base is complete up to. Otherwise – a round lost or
// failed halfway, its page data partly gone – the next one would be applied
// on top and the restore would silently read stale pages. Applying the
// round the base already holds again (a retried transfer) is a no-op.
// Nothing is fsynced: a node that crashes loses the migration anyway.
func ApplyRound(baseDir, roundDir string) (st CompactStats, err error) {
	name := filepath.Base(roundDir)
	applied, _ := os.ReadFile(filepath.Join(baseDir, "ROUND"))
	if string(applied) == name {
		st.Mode = "already applied"
		return st, removeRoundPages(roundDir)
	}
	if parent, perr := os.Readlink(filepath.Join(roundDir, "parent")); perr == nil {
		if want := filepath.Base(parent); string(applied) != want {
			return st, fmt.Errorf("round %s follows round %s, but the base is complete up to %q", name, want, applied)
		}
	} else if _, serr := os.Stat(baseDir); serr == nil {
		return st, fmt.Errorf("round %s has no parent, but a base exists already", name)
	}
	defer func() {
		if err == nil {
			err = os.WriteFile(filepath.Join(baseDir, "ROUND"), []byte(name), 0o600)
		} else {
			// Partially applied: nobody may link a final image to this base,
			// and no later round may be applied on top of it.
			_ = os.Remove(filepath.Join(baseDir, "ROUND"))
		}
	}()
	maps, _ := filepath.Glob(filepath.Join(roundDir, "pagemap-*.img"))
	if len(maps) == 0 {
		return st, errors.New("round has no pagemaps")
	}
	deltaDir := filepath.Join(filepath.Dir(baseDir), "delta")
	for _, dir := range []string{baseDir, deltaDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return st, err
		}
	}
	st.Mode = "in-place"
	for _, rp := range maps {
		name := filepath.Base(rp)
		if strings.HasPrefix(name, "pagemap-shmem") {
			continue
		}
		round, err := loadPagemap(rp)
		if err != nil {
			return st, err
		}
		if _, err := os.Stat(filepath.Join(baseDir, name)); errors.Is(err, os.ErrNotExist) {
			// First round for this process: no parent, every page present,
			// already flat – it becomes the base.
			if err := adoptAsBase(round, rp, roundDir, baseDir); err != nil {
				return st, err
			}
			st.Mode = "initial"
			st.Processes++
			continue
		}
		inPlace, fresh, err := applyToProcess(round, roundDir, baseDir, deltaDir, name)
		if err != nil {
			return st, err
		}
		st.PagesInPlace += inPlace
		st.PagesNew += fresh
		if fresh > 0 {
			st.Mode = "in-place+delta"
		}
		st.Processes++
		_ = os.Remove(round.pagesFile(roundDir))
	}
	// Every process of the base needs a pagemap in the delta once the delta
	// exists; done here, during pre-copy, instead of inside the freeze.
	if m, _ := filepath.Glob(filepath.Join(deltaDir, "pagemap-*.img")); len(m) > 0 {
		if err := completeDelta(baseDir, deltaDir); err != nil {
			return st, err
		}
	}
	return st, nil
}

// removeRoundPages deletes a round's page files (pagemaps stay).
func removeRoundPages(roundDir string) error {
	pages, _ := filepath.Glob(filepath.Join(roundDir, "pages-*.img"))
	for _, p := range pages {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func adoptAsBase(round *pagemapImage, rp, roundDir, baseDir string) error {
	for _, e := range round.entries {
		if e.flags&PEParent != 0 {
			return fmt.Errorf("%s: first round refers to a parent", rp)
		}
	}
	if err := moveFile(round.pagesFile(roundDir), round.pagesFile(baseDir)); err != nil {
		return err
	}
	return copyFile(rp, filepath.Join(baseDir, filepath.Base(rp)))
}

// pageCopy copies n pages from offset from (in the round) to dst.
type pageCopy struct {
	dst  run
	from int64
}

// applyToProcess writes a round's present pages into base or delta in place
// and rebuilds the delta if the round contains pages neither of them knows.
func applyToProcess(round *pagemapImage, roundDir, baseDir, deltaDir, name string) (inPlace, fresh uint64, err error) {
	base, err := loadPagemap(filepath.Join(baseDir, name))
	if err != nil {
		return 0, 0, err
	}
	baseRuns := presentRuns(base, baseDir)
	var deltaRuns []run
	if d, err := loadPagemap(filepath.Join(deltaDir, name)); err == nil {
		deltaRuns = presentRuns(d, deltaDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	known := func(vaddr uint64) (run, bool) {
		if r, ok := locate(baseRuns, vaddr); ok {
			return r, true
		}
		return locate(deltaRuns, vaddr)
	}

	var copies []pageCopy
	var newRuns []run
	for _, r := range presentRuns(round, roundDir) {
		for p := uint64(0); p < r.n; {
			vaddr := r.vaddr + p*pageSize
			from := r.off + int64(p*pageSize)
			dst, ok := known(vaddr)
			if !ok {
				// New page: extend up to the next page that exists somewhere.
				n := uint64(1)
				for p+n < r.n {
					if _, ok := known(r.vaddr + (p+n)*pageSize); ok {
						break
					}
					n++
				}
				newRuns = append(newRuns, run{vaddr, n, r.file, from})
				fresh += n
				p += n
				continue
			}
			n := min(r.n-p, (dst.end()-vaddr)/pageSize)
			dst.off += int64(vaddr - dst.vaddr)
			dst.vaddr, dst.n = vaddr, n
			copies = append(copies, pageCopy{dst, from})
			inPlace += n
			p += n
		}
	}

	if err := copyPages(copies, round.pagesFile(roundDir)); err != nil {
		return 0, 0, err
	}
	if len(newRuns) > 0 {
		if err := rebuildDelta(base, baseRuns, deltaRuns, newRuns, baseDir, deltaDir, name); err != nil {
			return 0, 0, err
		}
	}
	return inPlace, fresh, nil
}

// copyPages copies pages from src into their destination files in place.
func copyPages(copies []pageCopy, src string) error {
	if len(copies) == 0 {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	outs := map[string]*os.File{}
	defer func() {
		for _, f := range outs {
			f.Close()
		}
	}()
	buf := make([]byte, 1<<20)
	for _, c := range copies {
		out, ok := outs[c.dst.file]
		if !ok {
			if out, err = os.OpenFile(c.dst.file, os.O_WRONLY, 0); err != nil {
				return err
			}
			outs[c.dst.file] = out
		}
		total := int64(c.dst.n) * int64(pageSize)
		for done := int64(0); done < total; {
			n := min(int64(len(buf)), total-done)
			if _, err := in.ReadAt(buf[:n], c.from+done); err != nil {
				return err
			}
			if _, err := out.WriteAt(buf[:n], c.dst.off+done); err != nil {
				return err
			}
			done += n
		}
	}
	for _, f := range outs {
		if err := f.Close(); err != nil {
			return err
		}
	}
	clear(outs)
	return nil
}

// rebuildDelta rewrites the delta of one process: its own pages plus the new
// ones (both small), and a pagemap that lists the base's pages as in-parent,
// so CRIU resolves every page through delta -> base.
func rebuildDelta(base *pagemapImage, baseRuns, deltaRuns, newRuns []run, baseDir, deltaDir, name string) error {
	own := append(append([]run{}, deltaRuns...), newRuns...)
	sort.Slice(own, func(i, j int) bool { return own[i].vaddr < own[j].vaddr })

	pm := &pagemapImage{img: &image{magics: base.img.magics}, head: base.head, pagesID: base.pagesID}
	if err := writePages(own, pm.pagesFile(deltaDir)); err != nil {
		return err
	}

	// Own pages present, base pages in parent – merged by address.
	type span struct {
		vaddr, n uint64
		flags    uint64
	}
	var spans []span
	for _, r := range baseRuns {
		spans = append(spans, span{r.vaddr, r.n, PEParent})
	}
	for _, r := range own {
		spans = append(spans, span{r.vaddr, r.n, PEPresent})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].vaddr < spans[j].vaddr })
	for _, s := range spans {
		if n := len(pm.entries); n > 0 {
			last := &pm.entries[n-1]
			if last.flags == s.flags && last.vaddr+last.nrPages*pageSize == s.vaddr {
				last.nrPages += s.n
				continue
			}
		}
		pm.entries = append(pm.entries, pagemapEntry{vaddr: s.vaddr, nrPages: s.n, flags: s.flags})
	}
	pmPath := filepath.Join(deltaDir, name)
	if _, err := os.Stat(pmPath); errors.Is(err, os.ErrNotExist) {
		// image.write keeps the mode of an existing file.
		if err := os.WriteFile(pmPath, nil, 0o600); err != nil {
			return err
		}
	}
	if err := pm.save(pmPath); err != nil {
		return err
	}
	return ensureParentLink(deltaDir, baseDir)
}

// writePages writes the data of runs, in order, to a new pages file (atomic).
func writePages(runs []run, path string) error {
	tmp := path + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	srcs := map[string]*os.File{}
	defer func() {
		for _, f := range srcs {
			f.Close()
		}
	}()
	for _, r := range runs {
		f, ok := srcs[r.file]
		if !ok {
			if f, err = os.Open(r.file); err != nil {
				out.Close()
				return err
			}
			srcs[r.file] = f
		}
		if _, err := io.Copy(out, io.NewSectionReader(f, r.off, int64(r.n*pageSize))); err != nil {
			out.Close()
			return err
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ensureParentLink(dir, parentDir string) error {
	rel, err := filepath.Rel(dir, parentDir)
	if err != nil {
		return err
	}
	link := filepath.Join(dir, "parent")
	if cur, err := os.Readlink(link); err == nil && cur == rel {
		return nil
	}
	tmp := link + ".paguro"
	_ = os.Remove(tmp)
	if err := os.Symlink(rel, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

// LinkFinalToBase points the final image's parent link at the compacted
// images – delta/ if it holds pages, otherwise base/ – but only if they are
// complete up to exactly the round the final dump was taken against. Returns
// false (and changes nothing) if compaction never ran, e.g. stop-and-copy.
func LinkFinalToBase(finalDir, baseDir string) (bool, error) {
	target, err := os.Readlink(filepath.Join(finalDir, "parent"))
	if err != nil {
		return false, nil // no parent: nothing to redirect
	}
	round, err := os.ReadFile(filepath.Join(baseDir, "ROUND"))
	if errors.Is(err, os.ErrNotExist) {
		if _, serr := os.Stat(baseDir); errors.Is(serr, os.ErrNotExist) {
			return false, nil // compaction never ran: the original chain is intact
		}
		return false, fmt.Errorf("base image incomplete (no ROUND marker)")
	} else if err != nil {
		return false, err
	}
	if string(round) != filepath.Base(target) {
		return false, fmt.Errorf("base is complete up to round %s, final dump expects %s", round, filepath.Base(target))
	}
	parent := baseDir
	deltaDir := filepath.Join(filepath.Dir(baseDir), "delta")
	if m, _ := filepath.Glob(filepath.Join(deltaDir, "pagemap-*.img")); len(m) > 0 {
		parent = deltaDir
		if err := completeDelta(baseDir, deltaDir); err != nil {
			return false, err
		}
	}
	if err := ensureParentLink(finalDir, parent); err != nil {
		return false, err
	}
	return true, nil
}

// completeDelta gives every process of the base a pagemap in the delta.
// CRIU looks a process's parent pages up in pagemap-<pid>.img of the parent
// directory, and the delta held only the processes that had new mappings:
// a container with a second, idle process (the Minecraft image's wrapper
// next to Java) failed its restore with "No parent for snapshot pagemap"
// and cold-started. The added pagemaps list the base's pages as in-parent.
func completeDelta(baseDir, deltaDir string) error {
	maps, _ := filepath.Glob(filepath.Join(baseDir, "pagemap-*.img"))
	for _, bp := range maps {
		name := filepath.Base(bp)
		if strings.HasPrefix(name, "pagemap-shmem") {
			continue
		}
		if _, err := os.Stat(filepath.Join(deltaDir, name)); err == nil {
			continue
		}
		base, err := loadPagemap(bp)
		if err != nil {
			return err
		}
		if err := rebuildDelta(base, presentRuns(base, baseDir), nil, nil, baseDir, deltaDir, name); err != nil {
			return fmt.Errorf("pass-through delta for %s: %w", name, err)
		}
	}
	return nil
}

func moveFile(from, to string) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	if err := copyFile(from, to); err != nil {
		return err
	}
	return os.Remove(from)
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to+".tmp", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(to+".tmp", to)
}

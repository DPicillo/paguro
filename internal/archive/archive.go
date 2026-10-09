// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package archive packs and unpacks directory trees as a tar stream.
//
// Two differences from a plain tar:
//
//   - Overlay upperdirs contain deletions as whiteouts (char device 0:0)
//     and opaque directories (xattr trusted.overlay.opaque=y).
//     Pack(…, Overlay: true) translates both into the OCI format
//     (".wh.<name>", ".wh..wh..opq"), Unpack applies it to a mounted rootfs –
//     i.e. "this delta onto that root".
//   - Unpacking happens strictly inside the root (securejoin): a symlink in
//     the container rootfs that points to the host's /etc must not cause us
//     to overwrite host files.
package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// PackOptions controls Pack.
type PackOptions struct {
	// Overlay means the source is an overlay upperdir; translate whiteouts.
	Overlay bool
	// Exclude lists relative paths (with a leading "/") that are skipped.
	Exclude []string
	// Record, if set, receives the state of every entry, taken before its
	// content is read: the base of a later delta (Since). A file that
	// shrinks while it is read is padded – its state no longer matches, so
	// the delta carries it again.
	Record Manifest
	// Since makes Pack write a delta: only entries that are new or whose
	// state differs from Since, plus a whiteout for every entry of Since
	// that is gone (unpack it with UnpackOptions.Overlay).
	Since Manifest
	// Always, in a delta, names entries written whatever their state – a
	// file mapped writable by a process may change without its mtime.
	Always func(name string) bool
}

// FileState is what tells an unchanged entry from a changed one.
type FileState struct {
	Mode     fs.FileMode
	Size     int64
	MTime    int64 // nanoseconds
	Ino      uint64
	Uid, Gid uint32
}

// Manifest maps entry names (slash-separated, relative to the root) to
// their state.
type Manifest map[string]FileState

// racyWindow: entries modified this recently when a base is recorded are
// sent again with the delta (mtimes advance in coarse ticks).
const racyWindow = time.Second

// Stats counts what was packed or unpacked.
type Stats struct {
	Files     int64
	Dirs      int64
	Whiteouts int64
	Bytes     int64 // payload of regular files
	// Skipped: files named like a whiteout, left out by Pack.
	Skipped int64
}

// Pack writes the tree under root as tar to w.
func Pack(w io.Writer, root string, opt PackOptions) (Stats, error) {
	pk := &packer{tw: tar.NewWriter(w), root: root, opt: opt,
		hardlinks: map[uint64]string{}, seen: map[string]bool{}}
	if err := filepath.WalkDir(root, pk.visit); err != nil {
		return pk.st, err
	}
	if opt.Since != nil {
		if err := writeWhiteouts(pk.tw, opt.Since, pk.seen, &pk.st); err != nil {
			return pk.st, err
		}
	}
	return pk.st, pk.tw.Close()
}

// packer is one run of Pack.
type packer struct {
	tw        *tar.Writer
	root      string
	opt       PackOptions
	st        Stats
	hardlinks map[uint64]string // inode → first path
	seen      map[string]bool   // delta: entries that still exist
}

// visit packs one entry of the walk.
func (pk *packer) visit(p string, d fs.DirEntry, err error) error {
	if err != nil {
		// During pre-copy the app may delete files we have just listed.
		// That is not an error: the next pass (or the final dump during
		// the freeze) is what counts.
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	rel, _ := filepath.Rel(pk.root, p)
	if rel == "." {
		return nil
	}
	name := filepath.ToSlash(rel)
	if pk.excluded(name) {
		if d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	sys := fi.Sys().(*syscall.Stat_t)
	if pk.unchanged(name, fi, sys) {
		return nil // the target has it (a directory's entries are still walked)
	}
	// Overlay whiteout: char device with major/minor 0.
	if pk.opt.Overlay && fi.Mode()&fs.ModeCharDevice != 0 && sys.Rdev == 0 {
		pk.st.Whiteouts++
		return pk.tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     filepath.ToSlash(filepath.Join(filepath.Dir(rel), whiteoutPrefix+filepath.Base(rel))),
			Mode:     0o600,
			ModTime:  fi.ModTime(),
		})
	}
	hdr, err := pk.header(p, name, fi, sys)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return pk.writeDir(p, name, hdr, fi)
	}
	// A file the container itself named ".wh.*" would come back as a
	// whiteout (the OCI layer format cannot tell them apart): left out.
	if pk.opt.Overlay && strings.HasPrefix(fi.Name(), whiteoutPrefix) && fi.Mode().Type() != fs.ModeCharDevice {
		pk.st.Skipped++
		return nil
	}
	return pk.writeFile(p, name, hdr)
}

func (pk *packer) excluded(name string) bool {
	for _, ex := range pk.opt.Exclude {
		if "/"+name == ex || strings.HasPrefix("/"+name, ex+"/") {
			return true
		}
	}
	return false
}

// unchanged records the entry's state (Record) and, for a delta (Since),
// reports whether it is the same as in the base.
func (pk *packer) unchanged(name string, fi fs.FileInfo, sys *syscall.Stat_t) bool {
	state := FileState{Mode: fi.Mode(), Size: fi.Size(), MTime: fi.ModTime().UnixNano(), Ino: sys.Ino, Uid: sys.Uid, Gid: sys.Gid}
	if fi.IsDir() {
		state.Size, state.MTime = 0, 0 // a directory changes with its entries
	}
	if pk.opt.Record != nil {
		pk.opt.Record[name] = state
		// Changed within the timestamp's resolution of now: a second write
		// in the same tick would leave size and mtime alone. Such an entry
		// counts as changed (as git's "racy" entries).
		if !fi.IsDir() && time.Since(fi.ModTime()) < racyWindow {
			pk.opt.Record[name] = FileState{}
		}
	}
	if pk.opt.Since == nil {
		return false
	}
	pk.seen[name] = true
	old, ok := pk.opt.Since[name]
	return ok && old == state && (pk.opt.Always == nil || !pk.opt.Always(name))
}

// header builds the entry's tar header: owner by number, no times but
// the mtime, xattrs as PAX records, the second name of a hard link as a
// link to the first.
func (pk *packer) header(p, name string, fi fs.FileInfo, sys *syscall.Stat_t) (*tar.Header, error) {
	link := ""
	if fi.Mode()&fs.ModeSymlink != 0 {
		var err error
		if link, err = os.Readlink(p); err != nil {
			return nil, err
		}
	}
	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return nil, err
	}
	hdr.Name = name
	hdr.Uid, hdr.Gid = int(sys.Uid), int(sys.Gid)
	hdr.Uname, hdr.Gname = "", ""
	hdr.Format = tar.FormatPAX
	hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
	if x := readXattrs(p); len(x) > 0 {
		hdr.PAXRecords = x
	}
	if fi.Mode().IsRegular() && sys.Nlink > 1 {
		if first, ok := pk.hardlinks[sys.Ino]; ok {
			hdr.Typeflag = tar.TypeLink
			hdr.Linkname = first
			hdr.Size = 0
		} else {
			pk.hardlinks[sys.Ino] = name
		}
	}
	return hdr, nil
}

func (pk *packer) writeDir(p, name string, hdr *tar.Header, fi fs.FileInfo) error {
	hdr.Name += "/"
	pk.st.Dirs++
	if err := pk.tw.WriteHeader(hdr); err != nil {
		return err
	}
	// Opaque directory: the content of the lower layer is hidden. The
	// marker goes directly after the directory so that Unpack first
	// empties it and then fills it.
	if pk.opt.Overlay && isOpaque(p) {
		pk.st.Whiteouts++
		return pk.tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name + "/" + whiteoutOpaque,
			Mode:     0o600,
			ModTime:  fi.ModTime(),
		})
	}
	return nil
}

func (pk *packer) writeFile(p, name string, hdr *tar.Header) error {
	if err := pk.tw.WriteHeader(hdr); err != nil {
		return err
	}
	if hdr.Typeflag != tar.TypeReg {
		return nil
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	n, err := io.CopyN(pk.tw, f, hdr.Size)
	f.Close()
	if errors.Is(err, io.EOF) && pk.opt.Record != nil {
		// Shrunk while being read (the application runs): pad; the
		// recorded state is outdated, the delta sends it again.
		if _, err = io.CopyN(pk.tw, zeros{}, hdr.Size-n); err == nil {
			pk.opt.Record[name] = FileState{}
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	pk.st.Bytes += n
	pk.st.Files++
	return nil
}

// writeWhiteouts marks every entry of since that no longer exists as
// deleted – once, at the topmost deleted directory.
func writeWhiteouts(tw *tar.Writer, since Manifest, seen map[string]bool, st *Stats) error {
	gone := make([]string, 0)
	for name := range since {
		if !seen[name] {
			gone = append(gone, name)
		}
	}
	sort.Strings(gone)
	for _, name := range gone {
		if parent := path.Dir(name); parent != "." && !seen[parent] {
			continue // inside a deleted directory: its whiteout covers it
		}
		st.Whiteouts++
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     path.Join(path.Dir(name), whiteoutPrefix+path.Base(name)),
			Mode:     0o600,
		}); err != nil {
			return err
		}
	}
	return nil
}

// zeros reads as an endless stream of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// UnpackOptions controls Unpack.
type UnpackOptions struct {
	// Overlay applies OCI whiteouts instead of creating them as files.
	Overlay bool
}

// Unpack applies the tar stream r under root.
func Unpack(r io.Reader, root string, opt UnpackOptions) (Stats, error) {
	u := &unpacker{tr: tar.NewReader(r), root: root, opt: opt}
	for {
		hdr, err := u.tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return u.st, err
		}
		if err := u.entry(hdr); err != nil {
			return u.st, err
		}
	}
	// Directory times last, otherwise creating the children overwrites them
	// again.
	for i := len(u.dirs) - 1; i >= 0; i-- {
		_ = os.Chtimes(u.dirs[i].path, u.dirs[i].t, u.dirs[i].t)
	}
	return u.st, nil
}

// unpacker is one run of Unpack.
type unpacker struct {
	tr   *tar.Reader
	root string
	opt  UnpackOptions
	st   Stats
	dirs []dirTime
}

type dirTime struct {
	path string
	t    time.Time
}

// entry applies one tar entry: a whiteout, or an object created (or
// replaced) inside root with its owner, xattrs, mode and mtime.
func (u *unpacker) entry(hdr *tar.Header) error {
	clean := filepath.Clean("/" + hdr.Name)
	if clean == "/" {
		return nil
	}
	base := filepath.Base(clean)
	parent, err := securejoin.SecureJoin(u.root, filepath.Dir(clean))
	if err != nil {
		return err
	}
	if u.opt.Overlay {
		if done, err := u.whiteout(hdr, parent, base); done || err != nil {
			return err
		}
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	target := filepath.Join(parent, base)
	// Replace an existing object of a different type (file → symlink …);
	// directories stay in place, they are only updated.
	if fi, err := os.Lstat(target); err == nil {
		if !(fi.IsDir() && hdr.Typeflag == tar.TypeDir) {
			if err := os.RemoveAll(target); err != nil {
				return err
			}
		}
	}
	// hdr.Mode holds the Unix bits (04000 setuid, 02000 setgid, 01000
	// sticky); FileInfo translates them into Go's mode bits, which os.Chmod
	// and friends take. Masking hdr.Mode with Go's bits lost them: /tmp
	// came back 0777 instead of 1777.
	mode := hdr.FileInfo().Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if created, err := u.create(hdr, target, mode); !created || err != nil {
		return err
	}
	return u.attributes(hdr, target, mode)
}

// whiteout applies an OCI whiteout entry; done reports whether hdr was one.
func (u *unpacker) whiteout(hdr *tar.Header, parent, base string) (done bool, err error) {
	if base == whiteoutOpaque {
		u.st.Whiteouts++
		return true, clearDir(parent)
	}
	if !strings.HasPrefix(base, whiteoutPrefix) {
		return false, nil
	}
	// The victim is one entry of parent, never parent itself or above it:
	// ".wh.." would otherwise delete the parent – at the top, the bundle
	// directory on the host (a container can create such a file in its
	// writable layer).
	name := strings.TrimPrefix(base, whiteoutPrefix)
	if name == "" || name == "." || name == ".." {
		return true, fmt.Errorf("invalid whiteout %q", hdr.Name)
	}
	u.st.Whiteouts++
	return true, os.RemoveAll(filepath.Join(parent, name))
}

// create makes the object; created is false for entry types Unpack skips.
func (u *unpacker) create(hdr *tar.Header, target string, mode os.FileMode) (created bool, err error) {
	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := os.Mkdir(target, mode); err != nil && !os.IsExist(err) {
			return false, err
		}
		u.st.Dirs++
		u.dirs = append(u.dirs, dirTime{target, hdr.ModTime})
	case tar.TypeReg:
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|unix.O_NOFOLLOW, mode)
		if err != nil {
			return false, err
		}
		n, err := io.Copy(f, u.tr)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return false, err
		}
		u.st.Files++
		u.st.Bytes += n
	case tar.TypeSymlink:
		if err := os.Symlink(hdr.Linkname, target); err != nil {
			return false, err
		}
	case tar.TypeLink:
		src, err := securejoin.SecureJoin(u.root, hdr.Linkname)
		if err != nil {
			return false, err
		}
		if err := os.Link(src, target); err != nil {
			return false, err
		}
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		m := unixMode(mode)
		switch hdr.Typeflag {
		case tar.TypeChar:
			m |= unix.S_IFCHR
		case tar.TypeBlock:
			m |= unix.S_IFBLK
		default:
			m |= unix.S_IFIFO
		}
		if err := unix.Mknod(target, m, int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor)))); err != nil {
			return false, err
		}
	default:
		return false, nil
	}
	return true, nil
}

// attributes sets owner, xattrs, mode and mtime of a created object.
func (u *unpacker) attributes(hdr *tar.Header, target string, mode os.FileMode) error {
	if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil && !errors.Is(err, syscall.EPERM) {
		return err
	}
	for k, v := range hdr.PAXRecords {
		if name, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
			_ = unix.Lsetxattr(target, name, []byte(v), 0)
		}
	}
	if hdr.Typeflag != tar.TypeSymlink {
		// chown clears setuid/setgid – set the mode again afterwards.
		if hdr.Typeflag != tar.TypeLink {
			_ = os.Chmod(target, mode)
		}
		_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
	}
	return nil
}

// unixMode converts Go's permission and special bits into Unix mode bits.
func unixMode(m os.FileMode) uint32 {
	u := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		u |= unix.S_ISUID
	}
	if m&os.ModeSetgid != 0 {
		u |= unix.S_ISGID
	}
	if m&os.ModeSticky != 0 {
		u |= unix.S_ISVTX
	}
	return u
}

func clearDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func isOpaque(p string) bool {
	buf := make([]byte, 8)
	for _, attr := range []string{"trusted.overlay.opaque", "user.overlay.opaque"} {
		n, err := unix.Lgetxattr(p, attr, buf)
		if err == nil && n == 1 && buf[0] == 'y' {
			return true
		}
	}
	return false
}

// readXattrs reads extended attributes (capabilities, SELinux …) in PAX
// format. Overlay-internal attributes are skipped.
func readXattrs(p string) map[string]string {
	sz, err := unix.Llistxattr(p, nil)
	if err != nil || sz <= 0 {
		return nil
	}
	buf := make([]byte, sz)
	sz, err = unix.Llistxattr(p, buf)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, name := range strings.Split(strings.TrimRight(string(buf[:sz]), "\x00"), "\x00") {
		if name == "" || strings.HasPrefix(name, "trusted.overlay.") || strings.HasPrefix(name, "user.overlay.") {
			continue
		}
		vsz, err := unix.Lgetxattr(p, name, nil)
		if err != nil || vsz < 0 {
			continue
		}
		v := make([]byte, vsz)
		if vsz, err = unix.Lgetxattr(p, name, v); err == nil {
			out["SCHILY.xattr."+name] = string(v[:vsz])
		}
	}
	return out
}

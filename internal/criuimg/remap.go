// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package criuimg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	filesMagic      = 0x56303138 // files.img (FileEntry)
	regFilesMagic   = 0x50363636 // reg-files.img of older CRIU versions (RegFileEntry)
	remapFpathMagic = 0x59133954 // remap-fpath.img (RemapFilePathEntry)

	remapLinked = 0 // RemapFilePathEntry.remap_type LINKED (the default)
)

// LinkedRemap is a file the dumped process had open under a name that
// disappears with the process – an NFS "silly rename" (.nfsXXXX) of a file
// deleted while open. CRIU dumps it as a hard link under a stable name
// (Remap, "link_remap.<id>" next to it) that the restore opens and then
// removes. Both are paths in the container's mount namespace.
type LinkedRemap struct {
	Orig, Remap string
}

// LinkedRemaps lists the linked remaps of a dump (none if the dump has no
// remap-fpath.img).
func LinkedRemaps(dir string) ([]LinkedRemap, error) {
	remaps, err := readImage(filepath.Join(dir, "remap-fpath.img"), remapFpathMagic)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names, err := regFileNames(dir)
	if err != nil {
		return nil, err
	}
	var out []LinkedRemap
	for _, e := range remaps.entries {
		f, err := fields(e)
		if err != nil {
			return nil, err
		}
		typ, _ := u64(f, 3)
		if typ != remapLinked {
			continue // ghost files carry their content in the images
		}
		orig, _ := u64(f, 1)
		remap, _ := u64(f, 2)
		o, r := names[uint32(orig)], names[uint32(remap)]
		if o == "" || r == "" {
			return nil, fmt.Errorf("%s: linked remap %d -> %d without file names", dir, orig, remap)
		}
		out = append(out, LinkedRemap{Orig: o, Remap: r})
	}
	return out, nil
}

// regFileNames maps the ids of regular files to their names (files.img, or
// reg-files.img of older CRIU versions).
func regFileNames(dir string) (map[uint32]string, error) {
	names := map[uint32]string{}
	add := func(rfe []byte) error {
		f, err := fields(rfe)
		if err != nil {
			return err
		}
		id, _ := u64(f, 1)
		if v, ok := f[6]; ok && len(v) > 0 {
			if b, ok := v[0].([]byte); ok {
				names[uint32(id)] = string(b)
			}
		}
		return nil
	}
	img, err := readImage(filepath.Join(dir, "files.img"), filesMagic)
	if errors.Is(err, os.ErrNotExist) {
		if img, err = readImage(filepath.Join(dir, "reg-files.img"), regFilesMagic); err != nil {
			return nil, err
		}
		for _, e := range img.entries {
			if err := add(e); err != nil {
				return nil, err
			}
		}
		return names, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range img.entries {
		f, err := fields(e)
		if err != nil {
			return nil, err
		}
		reg, ok := f[protowire.Number(3)] // FileEntry.reg
		if !ok || len(reg) == 0 {
			continue
		}
		if b, ok := reg[0].([]byte); ok {
			if err := add(b); err != nil {
				return nil, err
			}
		}
	}
	return names, nil
}

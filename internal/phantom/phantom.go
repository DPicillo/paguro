// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package phantom implements the datapath of Paguro's Phantom network mode.
//
// In Phantom mode the replacement pod gets a normal, NEW IP from its node. The
// established connections that were restored by CRIU keep their OLD address
// inside the pod; small eBPF programs translate exactly those 5-tuples
// between the OLD address (what the sockets see) and the NEW address (what
// the network and the CNI see). Translation is per flow, never per IP, so a
// recycled OLD IP and all new connections are never touched.
//
// The package has three layers:
//
//   - Translator: owns the pinned eBPF maps and programs and attaches them
//     (TCX with legacy tc fallback). Rules are exact 5-tuple rewrites.
//   - Plan: turns a migration (OLD/NEW IP, flows harvested at freeze time)
//     into the rules and attachments one node needs.
//   - Harvest helpers: read the flows of a pod (sock_diag in its netns) and
//     NAT state (kernel conntrack).
//
// See docs/PHANTOM-MODE.md for the design and the packet flows.
package phantom

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
)

// DefaultPinPath is the bpffs directory under which maps and links are pinned.
const DefaultPinPath = "/sys/fs/bpf/paguro/phantom"

// Options tune a Translator.
type Options struct {
	// ForceLegacyTC disables TCX and always uses clsact + cls_bpf.
	ForceLegacyTC bool
	// LegacyPriority is the cls_bpf filter priority (lower runs first).
	// Default 1. See docs/PHANTOM-MODE.md, "Ordering".
	LegacyPriority uint16
	// StartDisabled leaves the global kill switch off.
	StartDisabled bool
}

// Translator owns the pinned state of the Phantom datapath on one node.
type Translator struct {
	pinPath string
	opts    Options

	mu    sync.Mutex
	maps  phantomMaps
	progs map[uint32]*phantomPrograms // keyed by L3 offset (14 or 0)
}

// New loads (or re-opens) the pinned maps under pinPath and loads the
// programs. Maps survive agent restarts; existing pinned TCX links are
// switched to the freshly loaded programs, so an agent upgrade replaces the
// datapath code atomically without detaching.
func New(pinPath string, opts ...Options) (*Translator, error) {
	if pinPath == "" {
		pinPath = DefaultPinPath
	}
	t := &Translator{pinPath: pinPath, progs: map[uint32]*phantomPrograms{}}
	if len(opts) > 0 {
		t.opts = opts[0]
	}
	if t.opts.LegacyPriority == 0 {
		t.opts.LegacyPriority = 1
	}
	if err := os.MkdirAll(t.mapsDir(), 0o700); err != nil {
		return nil, fmt.Errorf("phantom: create pin dir (is bpffs mounted at /sys/fs/bpf?): %w", err)
	}
	if err := os.MkdirAll(t.linksDir(), 0o700); err != nil {
		return nil, fmt.Errorf("phantom: create link pin dir: %w", err)
	}
	for _, off := range []uint32{14, 0} {
		if err := t.loadVariant(off); err != nil {
			t.Close()
			return nil, err
		}
	}
	if err := t.SetEnabled(!t.opts.StartDisabled); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.refreshPinnedLinks(); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func (t *Translator) mapsDir() string  { return filepath.Join(t.pinPath, "maps") }
func (t *Translator) linksDir() string { return filepath.Join(t.pinPath, "links") }

func (t *Translator) loadVariant(l3off uint32) error {
	spec, err := loadPhantom()
	if err != nil {
		return fmt.Errorf("phantom: load spec: %w", err)
	}
	if err := spec.Variables["cfg_l3_off"].Set(l3off); err != nil {
		return fmt.Errorf("phantom: set cfg_l3_off: %w", err)
	}
	objs := struct {
		phantomPrograms
		phantomMaps
	}{}
	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: t.mapsDir()},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("phantom: verifier: %+v", ve)
		}
		return fmt.Errorf("phantom: load objects (incompatible pinned maps from an older version? see Cleanup): %w", err)
	}
	t.progs[l3off] = &objs.phantomPrograms
	if t.maps.PaguroXlOut == nil {
		t.maps = objs.phantomMaps
	} else {
		objs.phantomMaps.Close()
	}
	return nil
}

// Close releases the Translator's file descriptors. Pinned maps and links
// (and therefore the datapath) stay in place.
func (t *Translator) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.progs {
		p.Close()
	}
	t.progs = map[uint32]*phantomPrograms{}
	if t.maps.PaguroXlOut != nil {
		t.maps.Close()
		t.maps = phantomMaps{}
	}
	return nil
}

// SetEnabled flips the global kill switch. When disabled, every program
// passes every packet unmodified (rules and attachments stay in place).
func (t *Translator) SetEnabled(on bool) error {
	v := phantomCtl{}
	if on {
		v.Enabled = 1
	}
	return t.maps.PaguroXlCtl.Update(uint32(0), &v, ebpf.UpdateAny)
}

// Stats are datapath counters summed over all CPUs.
type Stats struct {
	Seen, Translated, PendingDrops, Rerouted, LocalDelivered, Errors, TunnelRewrites uint64
}

// Stats returns the datapath counters.
func (t *Translator) Stats() (Stats, error) {
	var out [7]uint64
	for i := range out {
		var per []uint64
		if err := t.maps.PaguroXlStats.Lookup(uint32(i), &per); err != nil {
			return Stats{}, err
		}
		for _, v := range per {
			out[i] += v
		}
	}
	return Stats{out[0], out[1], out[2], out[3], out[4], out[5], out[6]}, nil
}

// Cleanup removes everything Paguro's Phantom mode installed on this node: all
// pinned links (which detaches the programs), legacy tc filters recorded in
// the link directory, and the pinned maps. Safe to call repeatedly; used on
// uninstall and by tests.
func Cleanup(pinPath string) error {
	if pinPath == "" {
		pinPath = DefaultPinPath
	}
	var errs []error
	if err := detachAllPinned(filepath.Join(pinPath, "links")); err != nil {
		errs = append(errs, err)
	}
	if err := os.RemoveAll(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

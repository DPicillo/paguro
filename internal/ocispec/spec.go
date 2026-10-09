// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package ocispec reads the parts of an OCI bundle config.json that Paguro
// needs. Deliberately minimal instead of the full runtime-spec types: the
// wrapper should not change anything in the spec, only look things up.
package ocispec

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
)

// containerd CRI annotations in the OCI spec.
const (
	AnnContainerType = "io.kubernetes.cri.container-type" // "sandbox" | "container"
	AnnContainerName = "io.kubernetes.cri.container-name"
	AnnSandboxUID    = "io.kubernetes.cri.sandbox-uid"
	AnnSandboxID     = "io.kubernetes.cri.sandbox-id"
	TypeSandbox      = "sandbox"
	TypeContainer    = "container"
)

type Mount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Source      string   `json:"source,omitempty"`
	Options     []string `json:"options,omitempty"`
}

type Namespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type Spec struct {
	Root *struct {
		Path     string `json:"path"`
		Readonly bool   `json:"readonly,omitempty"`
	} `json:"root,omitempty"`
	Process *struct {
		Terminal bool     `json:"terminal,omitempty"`
		Args     []string `json:"args,omitempty"`
	} `json:"process,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Linux       *struct {
		Namespaces  []Namespace `json:"namespaces,omitempty"`
		CgroupsPath string      `json:"cgroupsPath,omitempty"`
	} `json:"linux,omitempty"`

	bundle string
}

// Load reads <bundle>/config.json.
func Load(bundle string) (*Spec, error) {
	b, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, err
	}
	s := &Spec{bundle: bundle}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	return s, nil
}

// RootfsPath returns the absolute path of the root filesystem.
func (s *Spec) RootfsPath() string {
	if s.Root == nil || s.Root.Path == "" {
		return filepath.Join(s.bundle, "rootfs")
	}
	if filepath.IsAbs(s.Root.Path) {
		return s.Root.Path
	}
	return filepath.Join(s.bundle, s.Root.Path)
}

// NetNSPath returns the path of the network namespace ("" = its own, new
// one).
func (s *Spec) NetNSPath() string {
	if s.Linux == nil {
		return ""
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == "network" {
			return ns.Path
		}
	}
	return ""
}

func (s *Spec) Ann(k string) string { return s.Annotations[k] }

// EnsureTimeNamespace adds a dedicated time namespace to config.json if none
// is set, and returns true if the file was changed.
//
// Why: CLOCK_MONOTONIC and CLOCK_BOOTTIME count from the node's boot. After a
// migration the process would suddenly see the target node's clock – if it
// is behind (node up for a shorter time), timers and sleeps stall until it
// has caught up; if it is ahead, all timeouts fire at once. If the container
// lives in its own time namespace from the start, CRIU saves its clock state
// and on restore sets the offsets so that both clocks continue seamlessly.
//
// The file is read and written as a generic map so that no field is lost
// that this minimal spec struct does not know about.
func EnsureTimeNamespace(bundle string) (bool, error) {
	changed := false
	err := editConfig(bundle, func(doc map[string]any) {
		linux, _ := doc["linux"].(map[string]any)
		if linux == nil {
			return
		}
		nss, _ := linux["namespaces"].([]any)
		for _, ns := range nss {
			if m, ok := ns.(map[string]any); ok && m["type"] == "time" {
				return
			}
		}
		linux["namespaces"] = append(nss, map[string]any{"type": "time"})
		changed = true
	})
	return changed && err == nil, err
}

// EditEnv lets edit change the process environment (KEY=VALUE entries) and
// rewrites config.json if it returned changed variables, which it passes on.
func EditEnv(bundle string, edit func(env []string) ([]string, []string)) ([]string, error) {
	var set []string
	err := editConfig(bundle, func(doc map[string]any) {
		proc, _ := doc["process"].(map[string]any)
		if proc == nil {
			return
		}
		raw, _ := proc["env"].([]any)
		env := make([]string, 0, len(raw))
		for _, e := range raw {
			if s, ok := e.(string); ok {
				env = append(env, s)
			}
		}
		out, changed := edit(env)
		if len(changed) == 0 {
			return
		}
		list := make([]any, len(out))
		for i, e := range out {
			list[i] = e
		}
		proc["env"] = list
		set = changed
	})
	return set, err
}

// editConfig rewrites config.json atomically after mutate changed the
// generic document (unknown fields are kept as they are).
func editConfig(bundle string, mutate func(doc map[string]any)) error {
	path := filepath.Join(bundle, "config.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Numbers stay json.Number: through float64, values above 2^53 (an
	// unlimited rlimit, for instance) would change.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return err
	}
	before, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	mutate(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if bytes.Equal(before, out) {
		return nil // nothing changed: no rewrite
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp := path + ".paguro"
	if err := os.WriteFile(tmp, out, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

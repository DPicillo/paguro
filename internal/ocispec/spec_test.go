// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package ocispec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureTimeNamespace(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"ociVersion":"1.2.0","unknownField":{"keep":true},"linux":{"namespaces":[{"type":"pid"},{"type":"network","path":"/var/run/netns/x"}]}}`
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600)
	changed, err := EnsureTimeNamespace(dir)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if !strings.Contains(string(b), `"type":"time"`) || !strings.Contains(string(b), `"unknownField":{"keep":true}`) || !strings.Contains(string(b), "/var/run/netns/x") {
		t.Fatalf("config: %s", b)
	}
	if changed, _ := EnsureTimeNamespace(dir); changed {
		t.Fatal("second call must not change anything")
	}
}

func TestEditEnv(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"ociVersion":"1.2.0","process":{"env":["PATH=/bin","GODEBUG=x=1"],"args":["/app"]},"x-unknown":{"keep":true}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := EditEnv(dir, func(env []string) ([]string, []string) {
		return append(env[:1:1], "GODEBUG=x=1,cpu.adx=off"), []string{"GODEBUG"}
	})
	if err != nil || len(set) != 1 {
		t.Fatalf("set=%v err=%v", set, err)
	}
	var doc map[string]any
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	env := doc["process"].(map[string]any)["env"].([]any)
	if len(env) != 2 || env[1] != "GODEBUG=x=1,cpu.adx=off" {
		t.Fatalf("env = %v", env)
	}
	if doc["x-unknown"] == nil || doc["process"].(map[string]any)["args"] == nil {
		t.Fatalf("unknown fields lost: %s", b)
	}
	// No change: the environment stays as it is.
	set, _ = EditEnv(dir, func(env []string) ([]string, []string) { return nil, nil })
	b2, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if len(set) != 0 || !strings.Contains(string(b2), "cpu.adx=off") {
		t.Fatalf("unchanged edit altered the env: %s", b2)
	}
}

// Large integers survive an edit, and an edit that changes nothing leaves
// the file alone.
func TestEditConfigKeepsNumbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	orig := `{"process":{"rlimits":[{"type":"RLIMIT_NOFILE","hard":18446744073709551615,"soft":1048576}]}}`
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := editConfig(dir, func(map[string]any) {}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Fatalf("unchanged config rewritten: %s", b)
	}
	if err := editConfig(dir, func(doc map[string]any) { doc["x"] = true }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "18446744073709551615") {
		t.Fatalf("large number changed: %s", b)
	}
}

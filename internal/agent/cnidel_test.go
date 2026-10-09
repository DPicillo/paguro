// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The source's network is released with containerd's cached CNI
// attachment: the same network list, namespace and container id.
func TestReleaseNetworkFromCache(t *testing.T) {
	tmp := t.TempDir()
	bin, cache := filepath.Join(tmp, "bin"), filepath.Join(tmp, "cache")
	record := filepath.Join(tmp, "calls")
	for _, d := range []string{bin, filepath.Join(cache, "results")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	plugin := "#!/bin/sh\ncat > /dev/null\necho \"$CNI_COMMAND $CNI_CONTAINERID $CNI_NETNS $CNI_IFNAME\" >> " + record + "\n"
	if err := os.WriteFile(filepath.Join(bin, "fakecni"), []byte(plugin), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := `{"cniVersion":"1.0.0","name":"k8s-pod-network","plugins":[{"type":"fakecni"}]}`
	entry, _ := json.Marshal(map[string]any{
		"kind": "cniCacheV1", "containerId": "sb1", "config": []byte(conf), "ifName": "eth0",
		"networkName": "k8s-pod-network", "netns": "/var/run/netns/cni-x",
		"result": map[string]any{"cniVersion": "1.0.0"},
	})
	if err := os.WriteFile(filepath.Join(cache, "results", "k8s-pod-network-sb1-eth0"), entry, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(b []string, c string) { cniBinDirs, cniCacheDir = b, c }(cniBinDirs, cniCacheDir)
	cniBinDirs, cniCacheDir = []string{bin}, cache
	a := &Agent{Host: &Host{Root: "/"}}
	ok, err := a.releaseNetwork(context.Background(), "sb1")
	if err != nil || !ok {
		t.Fatalf("released=%v err=%v", ok, err)
	}
	b, _ := os.ReadFile(record)
	if got := strings.TrimSpace(string(b)); got != "DEL sb1 /var/run/netns/cni-x eth0" {
		t.Fatalf("plugin call %q", got)
	}
	if ok, err := a.releaseNetwork(context.Background(), "unknown"); ok || err == nil {
		t.Fatal("a sandbox without a cached attachment must report failure")
	}
}

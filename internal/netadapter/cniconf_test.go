// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package netadapter

import (
	"os"
	"path/filepath"
	"testing"
)

// Configurations as the CNIs write them (trimmed to the relevant fields).
var cniConfigs = map[string]struct {
	conf    string
	name    string
	movable bool
}{
	"calico": {`{"name":"k8s-pod-network","cniVersion":"1.0.0","plugins":[{"type":"calico","datastore_type":"kubernetes","ipam":{"type":"calico-ipam"}},{"type":"portmap","snat":true}]}`, CNICalico, true},
	"canal":  {`{"name":"k8s-pod-network","cniVersion":"0.3.1","plugins":[{"type":"calico","ipam":{"type":"host-local","subnet":"usePodCidr"}},{"type":"portmap"},{"type":"bandwidth"}]}`, CNICanal, false},
	"cilium": {`{"cniVersion":"1.0.0","name":"cilium","plugins":[{"type":"cilium-cni","enable-debug":false}]}`, CNICilium, true},
	"flannel": {`{"name":"cbr0","cniVersion":"0.3.1","plugins":[{"type":"flannel","delegate":{"hairpinMode":true,"isDefaultGateway":true}},{"type":"portmap","capabilities":{"portMappings":true}}]}`,
		CNIFlannel, false},
	"aws": {`{"cniVersion":"0.4.0","name":"aws-cni","disableCheck":true,"plugins":[{"name":"aws-cni","type":"aws-cni","vethPrefix":"eni","mtu":"9001"},{"name":"egress-cni","type":"egress-cni"},{"type":"portmap","snat":true}]}`,
		CNIAWSVPC, false},
	"azure": {`{"cniVersion":"0.3.0","name":"azure","plugins":[{"type":"azure-vnet","mode":"transparent","ipam":{"type":"azure-cns"}},{"type":"portmap","snat":true}]}`,
		CNIAzure, false},
	"ovn-k":    {`{"cniVersion":"0.4.0","name":"ovn-kubernetes","type":"ovn-k8s-cni-overlay","ipam":{},"dns":{}}`, CNIOVNKubernetes, false},
	"antrea":   {`{"cniVersion":"0.3.0","name":"antrea","plugins":[{"type":"antrea","ipam":{"type":"host-local"}},{"type":"portmap"},{"type":"bandwidth"}]}`, CNIAntrea, false},
	"kube-ovn": {`{"name":"kube-ovn","cniVersion":"0.3.1","plugins":[{"type":"kube-ovn","ipam":{"type":"kube-ovn"}},{"type":"portmap"}]}`, CNIKubeOVN, false},
	"multus": {`{"cniVersion":"0.3.1","name":"multus-cni-network","type":"multus","delegates":[{"cniVersion":"0.3.1","name":"cbr0","plugins":[{"type":"flannel","delegate":{}}]}]}`,
		CNIFlannel + "+multus", false},
	"kindnet": {`{"cniVersion":"0.3.1","name":"kindnet","plugins":[{"type":"ptp","ipam":{"type":"host-local"}},{"type":"portmap"}]}`, CNIKindnet, false},
}

func TestParseCNIConfig(t *testing.T) {
	for id, c := range cniConfigs {
		info, err := ParseCNIConfig([]byte(c.conf))
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if info.Name != c.name || info.MovableIP() != c.movable {
			t.Errorf("%s: got %+v (movable %v), want %s (movable %v)", id, info, info.MovableIP(), c.name, c.movable)
		}
		if back := ParseCNIAnnotation(info.String()); back.Name != info.Name || back.Plugin != info.Plugin || back.IPAM != info.IPAM {
			t.Errorf("%s: annotation round trip %q -> %+v", id, info.String(), back)
		}
	}
}

func TestDetectNodeCNIPicksFirstFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("10-calico.conflist", cniConfigs["calico"].conf)
	write("05-cilium.conflist", cniConfigs["cilium"].conf) // wins: sorts first
	write("calico-kubeconfig", "not a CNI config")
	info, err := DetectNodeCNI(dir)
	if err != nil || info.Name != CNICilium || info.File != "05-cilium.conflist" {
		t.Fatalf("got %+v, %v", info, err)
	}
	if _, err := DetectNodeCNI(t.TempDir()); err == nil {
		t.Error("empty directory accepted")
	}
}

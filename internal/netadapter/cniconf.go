// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package netadapter

// Node-level CNI detection. The container runtime uses the first network
// configuration in /etc/cni/net.d (by file name); the agent reads the same
// file and publishes what it found as the node annotation paguro.dev/cni.
// This is more precise than looking for CRDs: Calico's CRDs also exist with
// Canal, where IPs come from host-local IPAM and cannot move between nodes.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CNI names as published in the node annotation (CNIInfo.Name).
const (
	CNICalico        = "calico"         // Calico with calico-ipam: IPs can move (ipAddrs)
	CNICanal         = "canal"          // Calico policy + host-local IPAM (RKE2 default)
	CNICilium        = "cilium"         //
	CNIFlannel       = "flannel"        // k3s default; host-local IPAM per node subnet
	CNIAWSVPC        = "aws-vpc-cni"    // EKS default; IPs belong to the node's ENIs
	CNIAzure         = "azure-cni"      // AKS default (Azure CNI, overlay or VNet)
	CNIOVNKubernetes = "ovn-kubernetes" // OpenShift default
	CNIAntrea        = "antrea"
	CNIKubeOVN       = "kube-ovn"
	CNIWeave         = "weave"
	CNIKindnet       = "kindnet"
	CNIMultus        = "multus" // meta plugin; the primary network is a delegate
	CNIUnknown       = "unknown"
)

// CNIInfo is what a node's active CNI configuration says.
type CNIInfo struct {
	Name   string // one of the CNI* names
	Plugin string // "type" of the main plugin
	IPAM   string // its IPAM "type", if configured inline
	File   string // configuration file (base name)
}

// PodsInNodeSubnets reports whether the CNI gives pods addresses from the
// node's own subnets (VPC-native: AWS VPC CNI, Azure CNI), which no
// Kubernetes object names – the agents report them.
func (c CNIInfo) PodsInNodeSubnets() bool {
	return c.Name == CNIAWSVPC || c.Name == CNIAzure
}

// String is the annotation value: "<name>;<plugin>/<ipam>".
func (c CNIInfo) String() string { return c.Name + ";" + c.Plugin + "/" + c.IPAM }

// ParseCNIAnnotation is the inverse of CNIInfo.String.
func ParseCNIAnnotation(v string) CNIInfo {
	name, rest, _ := strings.Cut(v, ";")
	plugin, ipam, _ := strings.Cut(rest, "/")
	return CNIInfo{Name: name, Plugin: plugin, IPAM: ipam}
}

// DetectNodeCNI reads the active configuration in dir (/etc/cni/net.d).
func DetectNodeCNI(dir string) (CNIInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return CNIInfo{Name: CNIUnknown}, err
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && (strings.HasSuffix(n, ".conflist") || strings.HasSuffix(n, ".conf") || strings.HasSuffix(n, ".json")) {
			files = append(files, n)
		}
	}
	if len(files) == 0 {
		return CNIInfo{Name: CNIUnknown}, fmt.Errorf("no CNI configuration in %s", dir)
	}
	sort.Strings(files) // libcni picks the first one by name
	b, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		return CNIInfo{Name: CNIUnknown}, err
	}
	info, err := ParseCNIConfig(b)
	info.File = files[0]
	return info, err
}

// ParseCNIConfig classifies one .conf or .conflist document.
func ParseCNIConfig(b []byte) (CNIInfo, error) {
	var doc struct {
		Type    string                `json:"type"`
		IPAM    struct{ Type string } `json:"ipam"`
		Plugins []map[string]any      `json:"plugins"`
		// multus: thick plugin delegates, thin plugin clusterNetwork.
		Delegates []map[string]any `json:"delegates"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return CNIInfo{Name: CNIUnknown}, fmt.Errorf("CNI configuration: %w", err)
	}
	plugin, ipam := doc.Type, doc.IPAM.Type
	if plugin == "" && len(doc.Plugins) > 0 {
		plugin, _ = doc.Plugins[0]["type"].(string)
		if m, ok := doc.Plugins[0]["ipam"].(map[string]any); ok {
			ipam, _ = m["type"].(string)
		}
	}
	info := CNIInfo{Plugin: plugin, IPAM: ipam, Name: CNIUnknown}
	switch plugin {
	case "calico":
		info.Name = CNICalico
		if ipam != "" && ipam != "calico-ipam" {
			info.Name = CNICanal
		}
	case "cilium-cni":
		info.Name = CNICilium
	case "flannel":
		info.Name = CNIFlannel
	case "aws-cni":
		info.Name = CNIAWSVPC
	case "azure-vnet":
		info.Name = CNIAzure
	case "ovn-k8s-cni-overlay":
		info.Name = CNIOVNKubernetes
	case "antrea":
		info.Name = CNIAntrea
	case "kube-ovn":
		info.Name = CNIKubeOVN
	case "weave-net":
		info.Name = CNIWeave
	case "ptp":
		info.Name = CNIKindnet // kindnet writes a plain ptp configuration
	case "multus", "multus-shim":
		info.Name = CNIMultus
		if len(doc.Delegates) > 0 {
			if d, err := json.Marshal(doc.Delegates[0]); err == nil {
				if inner, err := ParseCNIConfig(d); err == nil && inner.Name != CNIUnknown {
					inner.Name += "+multus"
					return inner, nil
				}
			}
		}
	}
	return info, nil
}

// VerifiesSource reports whether this CNI drops packets that leave a pod
// with a source address other than the pod's own (Open vSwitch CNIs'
// spoof guards, Cilium's endpoint source check, Calico's strict rpfilter
// on workload traffic – Felix also runs it under Canal). Measured on
// Calico: a ClusterIP reply from the migrated pod to a client on the same
// node, translated back to the old address on the pod's veth, was dropped
// for as long as the pod stayed there.
func (c CNIInfo) VerifiesSource() bool {
	switch strings.TrimSuffix(c.Name, "+multus") {
	case CNIAntrea, CNIOVNKubernetes, CNIKubeOVN, CNICilium, CNICalico, CNICanal:
		return true
	}
	return false
}

// MovableIP reports whether this CNI can give a pod on another node the
// same IP (the basis of Paguro's IP-preserving adapters). Calico can with
// calico-ipam; Cilium with multi-pool IPAM (checked per pod: sticky pool).
// Everything else uses Phantom mode (new IP, connections translated).
func (c CNIInfo) MovableIP() bool {
	switch strings.TrimSuffix(c.Name, "+multus") {
	case CNICalico, CNICilium:
		return true
	}
	return false
}

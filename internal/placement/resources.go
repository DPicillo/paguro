// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package placement

import (
	"cmp"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"paguro.dev/paguro/internal/cpufeat"
)

// Usage is the allocated requests on a node.
type Usage struct {
	MilliCPU int64
	Memory   int64
	Pods     int64
	// HostPorts in use on the node (HostPort.String).
	HostPorts map[HostPort]bool
}

// HostPort is a port a container claims on its node.
type HostPort struct {
	Protocol corev1.Protocol
	IP       string // "" = every address
	Port     int32
}

func (h HostPort) String() string {
	return fmt.Sprintf("%s/%s:%d", h.Protocol, cmp.Or(h.IP, "*"), h.Port)
}

// HostPorts lists the host ports of a pod's containers (sidecars included).
func HostPorts(pod *corev1.Pod) []HostPort {
	var out []HostPort
	for _, list := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for _, c := range list {
			for _, p := range c.Ports {
				if p.HostPort == 0 {
					continue
				}
				ip := p.HostIP
				if ip == "0.0.0.0" || ip == "::" {
					ip = ""
				}
				out = append(out, HostPort{Protocol: cmp.Or(p.Protocol, corev1.ProtocolTCP), IP: ip, Port: p.HostPort})
			}
		}
	}
	return out
}

// conflicts: the same protocol and port, and either side on every address
// or both on the same – the scheduler's NodePorts rule.
func (u Usage) conflicts(h HostPort) bool {
	for used := range u.HostPorts {
		if used.Protocol == h.Protocol && used.Port == h.Port && (used.IP == "" || h.IP == "" || used.IP == h.IP) {
			return true
		}
	}
	return false
}

// PodRequests computes a pod's effective requests like the scheduler:
// sum of all app containers and sidecars (restartable init containers),
// but at least the maximum of each individual classic init container
// (plus sidecars started up to that point), plus overhead.
func PodRequests(pod *corev1.Pod) (milliCPU, memory int64) {
	var sumCPU, sumMem int64
	for i := range pod.Spec.Containers {
		r := pod.Spec.Containers[i].Resources.Requests
		sumCPU += r.Cpu().MilliValue()
		sumMem += r.Memory().Value()
	}
	var sidecarCPU, sidecarMem, initCPU, initMem int64
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		r := c.Resources.Requests
		if IsSidecar(c) {
			sidecarCPU += r.Cpu().MilliValue()
			sidecarMem += r.Memory().Value()
			continue
		}
		initCPU = max(initCPU, sidecarCPU+r.Cpu().MilliValue())
		initMem = max(initMem, sidecarMem+r.Memory().Value())
	}
	milliCPU = max(sumCPU+sidecarCPU, initCPU)
	memory = max(sumMem+sidecarMem, initMem)
	if pod.Spec.Overhead != nil {
		milliCPU += pod.Spec.Overhead.Cpu().MilliValue()
		memory += pod.Spec.Overhead.Memory().Value()
	}
	return milliCPU, memory
}

// IsSidecar reports restartable init containers (restartPolicy: Always).
func IsSidecar(c *corev1.Container) bool {
	return c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways
}

// NodeUsage sums the requests of all non-terminal pods per node.
// Pods with a UID in skip (e.g. the source pod) are ignored.
func NodeUsage(pods []corev1.Pod, skip ...string) map[string]Usage {
	out := make(map[string]Usage)
	for i := range pods {
		p := &pods[i]
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if contains(skip, string(p.UID)) {
			continue
		}
		out[p.Spec.NodeName] = AddPod(out[p.Spec.NodeName], p)
	}
	return out
}

// AddPod adds a pod's requests and host ports to a node's usage.
func AddPod(u Usage, p *corev1.Pod) Usage {
	cpu, mem := PodRequests(p)
	u.MilliCPU += cpu
	u.Memory += mem
	u.Pods++
	for _, h := range HostPorts(p) {
		if u.HostPorts == nil {
			u.HostPorts = map[HostPort]bool{}
		}
		u.HostPorts[h] = true
	}
	return u
}

// ParseCPUFlags parses the node annotation paguro.dev/cpu-flags.
func ParseCPUFlags(s string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out[f] = struct{}{}
		}
	}
	return out
}

// MissingCPUFlags returns the source flags missing on the target
// (sorted). Empty = target ⊇ source. Only flags that can matter to a
// process are compared (cpufeat.Relevant): kernel, hypervisor and platform
// flags never block (lab: smap alone would have blocked migrations between
// two hypervisor generations).
func MissingCPUFlags(source, target string) []string {
	src, dst := ParseCPUFlags(source), ParseCPUFlags(target)
	var missing []string
	for f := range src {
		if _, ok := dst[f]; !ok && cpufeat.Relevant(f) {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	return missing
}

// UncoveredCPUFlags returns the missing flags a pod may use – those inside
// its CPU baseline (annotation paguro.dev/cpu-baseline). Without a baseline
// every missing flag counts.
func UncoveredCPUFlags(missing []string, baseline string) []string {
	if baseline == "" {
		return missing
	}
	in := ParseCPUFlags(baseline)
	var out []string
	for _, f := range missing {
		if _, ok := in[f]; ok {
			out = append(out, f)
		}
	}
	return out
}

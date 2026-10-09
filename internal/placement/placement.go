// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package placement selects the target node of a Migration. Pure logic
// without API access, so it is fully unit-testable.
package placement

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"paguro.dev/paguro/api/v1alpha1"
)

// Request contains everything needed for the selection.
type Request struct {
	Pod        *corev1.Pod
	SourceNode *corev1.Node
	Nodes      []corev1.Node
	// Allocated requests per node (excluding the source pod), see NodeUsage.
	Usage map[string]Usage
	// Explicitly requested target node (spec.targetNode), otherwise empty.
	TargetNode string
	CPUPolicy  v1alpha1.CPUPolicy
	// Required topology of the RWO volumes (spec.nodeAffinity.required of the PVs).
	VolumeTopology []*corev1.NodeSelector
}

// Result is the selected node plus warnings (e.g. CPU difference with Ignore).
type Result struct {
	Node     string
	Warnings []string
}

// Rejection explains why a node is not eligible.
type Rejection struct {
	Node            string
	Reason          string
	MissingCPUFlags []string
}

// NoTargetError: no node satisfies all conditions.
type NoTargetError struct {
	Requested  string
	Rejections []Rejection
}

func (e *NoTargetError) Error() string {
	if e.Requested != "" && len(e.Rejections) == 1 {
		return fmt.Sprintf("target node %s not eligible: %s", e.Requested, e.Rejections[0].Reason)
	}
	if len(e.Rejections) == 0 {
		return "no candidate nodes besides the source node"
	}
	parts := make([]string, 0, len(e.Rejections))
	for _, r := range e.Rejections {
		parts = append(parts, r.Node+": "+r.Reason)
	}
	return "no eligible target node (" + strings.Join(parts, "; ") + ")"
}

type candidate struct {
	name       string
	freeMemory int64
	warnings   []string
}

// Select checks the candidates and returns the best node. If a target
// is given explicitly, only that one is validated.
func Select(req Request) (Result, error) {
	if req.Pod == nil || req.SourceNode == nil {
		return Result{}, fmt.Errorf("placement: pod and source node are required")
	}
	if req.TargetNode != "" {
		if req.TargetNode == req.SourceNode.Name {
			return Result{}, &NoTargetError{Requested: req.TargetNode, Rejections: []Rejection{{
				Node: req.TargetNode, Reason: "target equals source node"}}}
		}
		for i := range req.Nodes {
			if req.Nodes[i].Name != req.TargetNode {
				continue
			}
			c, rej := evaluate(&req, &req.Nodes[i])
			if rej != nil {
				return Result{}, &NoTargetError{Requested: req.TargetNode, Rejections: []Rejection{*rej}}
			}
			return Result{Node: c.name, Warnings: c.warnings}, nil
		}
		return Result{}, &NoTargetError{Requested: req.TargetNode, Rejections: []Rejection{{
			Node: req.TargetNode, Reason: "node does not exist"}}}
	}

	var cands []candidate
	var rejections []Rejection
	for i := range req.Nodes {
		n := &req.Nodes[i]
		if n.Name == req.SourceNode.Name {
			continue
		}
		c, rej := evaluate(&req, n)
		if rej != nil {
			rejections = append(rejections, *rej)
			continue
		}
		cands = append(cands, c)
	}
	if len(cands) == 0 {
		sort.Slice(rejections, func(i, j int) bool { return rejections[i].Node < rejections[j].Node })
		return Result{}, &NoTargetError{Rejections: rejections}
	}
	// Most free memory wins, ties broken by name (deterministic).
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].freeMemory != cands[j].freeMemory {
			return cands[i].freeMemory > cands[j].freeMemory
		}
		return cands[i].name < cands[j].name
	})
	return Result{Node: cands[0].name, Warnings: cands[0].warnings}, nil
}

func evaluate(req *Request, n *corev1.Node) (candidate, *Rejection) {
	reject := func(format string, args ...any) (candidate, *Rejection) {
		return candidate{}, &Rejection{Node: n.Name, Reason: fmt.Sprintf(format, args...)}
	}
	pod := req.Pod

	if !nodeReady(n) {
		return reject("node not Ready")
	}
	if n.Spec.Unschedulable {
		return reject("node is cordoned (unschedulable)")
	}
	if n.Annotations[v1alpha1.AnnotationNodeAgent] == "" {
		return reject("no paguro agent on node (annotation %s missing)", v1alpha1.AnnotationNodeAgent)
	}
	if n.Annotations[v1alpha1.AnnotationNodeAgentDraining] != "" {
		return reject("the paguro agent on the node is shutting down (upgrade or uninstall)")
	}
	// During an upgrade the agents restart node by node: data dumped by one
	// release is restored only by the same release.
	if want, got := AgentVersion(req.SourceNode), AgentVersion(n); want != got {
		return reject("the agent runs release %s, the source node's %s (upgrade in progress?)", got, want)
	}
	// Not even cpuPolicy=Ignore crosses instruction sets.
	if src, dst := nodeArch(req.SourceNode), nodeArch(n); src != dst {
		return reject("different CPU architecture (%s → %s): a process cannot continue on another instruction set", src, dst)
	}
	if t := UntoleratedTaint(n.Spec.Taints, pod.Spec.Tolerations); t != nil {
		return reject("untolerated taint %s=%s:%s", t.Key, t.Value, t.Effect)
	}
	if !MatchNodeSelectorMap(pod.Spec.NodeSelector, n) {
		return reject("pod nodeSelector does not match")
	}
	if a := pod.Spec.Affinity; a != nil && a.NodeAffinity != nil {
		ok, err := MatchNodeSelector(a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution, n)
		if err != nil {
			return reject("invalid pod node affinity: %v", err)
		}
		if !ok {
			return reject("required node affinity does not match")
		}
	}
	for _, topo := range req.VolumeTopology {
		ok, err := MatchNodeSelector(topo, n)
		if err != nil {
			return reject("invalid volume node affinity: %v", err)
		}
		if !ok {
			return reject("volume topology (PV node affinity) does not match")
		}
	}

	cpu, mem := PodRequests(pod)
	used := req.Usage[n.Name]
	alloc := n.Status.Allocatable
	if free := alloc.Cpu().MilliValue() - used.MilliCPU; cpu > free {
		return reject("insufficient cpu (requested %dm, free %dm)", cpu, free)
	}
	freeMem := alloc.Memory().Value() - used.Memory
	if mem > freeMem {
		return reject("insufficient memory (requested %d MiB, free %d MiB)", mem>>20, freeMem>>20)
	}
	if maxPods := alloc.Pods().Value(); maxPods > 0 && used.Pods+1 > maxPods {
		return reject("pod limit reached (%d)", maxPods)
	}
	// The replacement keeps its host ports (kubelet would refuse it).
	for _, h := range HostPorts(pod) {
		if used.conflicts(h) {
			return reject("host port %s in use", h)
		}
	}

	c := candidate{name: n.Name, freeMemory: freeMem - mem}
	missing := MissingCPUFlags(req.SourceNode.Annotations[v1alpha1.AnnotationNodeCPUFlags],
		n.Annotations[v1alpha1.AnnotationNodeCPUFlags])
	// Features outside the pod's CPU baseline were never available to its
	// runtimes (cpufeat): their absence on the target is safe.
	uncovered := UncoveredCPUFlags(missing, pod.Annotations[v1alpha1.AnnotationCPUBaseline])
	switch {
	case len(uncovered) > 0 && req.CPUPolicy != v1alpha1.CPUIgnore:
		reason := "CPU lacks source features: " + strings.Join(uncovered, ",")
		if pod.Annotations[v1alpha1.AnnotationCPUBaseline] != "" {
			reason = "CPU lacks features within the pod's CPU baseline: " + strings.Join(uncovered, ",")
		}
		return candidate{}, &Rejection{Node: n.Name, Reason: reason, MissingCPUFlags: uncovered}
	case len(uncovered) > 0:
		c.warnings = append(c.warnings, fmt.Sprintf(
			"cpuPolicy=Ignore: target %s lacks CPU features of source: %s (risk of SIGILL)",
			n.Name, strings.Join(uncovered, ",")))
	case len(missing) > 0:
		c.warnings = append(c.warnings, fmt.Sprintf(
			"target %s lacks %s – outside the pod's CPU baseline, its runtimes were started without them",
			n.Name, strings.Join(missing, ",")))
	}
	return c, nil
}

// nodeArch is the node's CPU architecture: kubernetes.io/arch, else the
// kubelet's report.
func nodeArch(n *corev1.Node) string {
	if a := n.Labels[corev1.LabelArchStable]; a != "" {
		return a
	}
	return n.Status.NodeInfo.Architecture
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// AgentVersion is the release of a node's agent ("unknown" before agents
// reported it).
func AgentVersion(n *corev1.Node) string {
	if n == nil || n.Annotations[v1alpha1.AnnotationNodeAgentVersion] == "" {
		return "unknown"
	}
	return n.Annotations[v1alpha1.AnnotationNodeAgentVersion]
}

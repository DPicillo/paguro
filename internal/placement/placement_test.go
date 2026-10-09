// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package placement

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"paguro.dev/paguro/api/v1alpha1"
)

type nodeOpt func(*corev1.Node)

func withLabels(kv ...string) nodeOpt {
	return func(n *corev1.Node) {
		for i := 0; i+1 < len(kv); i += 2 {
			n.Labels[kv[i]] = kv[i+1]
		}
	}
}

func withFlags(f string) nodeOpt {
	return func(n *corev1.Node) { n.Annotations[v1alpha1.AnnotationNodeCPUFlags] = f }
}

func withTaint(key, value string, effect corev1.TaintEffect) nodeOpt {
	return func(n *corev1.Node) {
		n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{Key: key, Value: value, Effect: effect})
	}
}

func withMemory(m string) nodeOpt {
	return func(n *corev1.Node) { n.Status.Allocatable[corev1.ResourceMemory] = resource.MustParse(m) }
}

func node(name string, opts ...nodeOpt) corev1.Node {
	n := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{"kubernetes.io/hostname": name},
			Annotations: map[string]string{v1alpha1.AnnotationNodeAgent: name + ":9555", v1alpha1.AnnotationNodeCPUFlags: "sse,sse2,avx"},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
				corev1.ResourcePods:   resource.MustParse("110"),
			},
		},
	}
	for _, o := range opts {
		o(&n)
	}
	return n
}

func pod(cpu, mem string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", UID: "src-uid"},
		Spec: corev1.PodSpec{
			NodeName: "src",
			Containers: []corev1.Container{{
				Name: "app",
				Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse(cpu), corev1.ResourceMemory: resource.MustParse(mem),
				}},
			}},
		},
	}
}

func baseRequest(p *corev1.Pod, nodes ...corev1.Node) Request {
	src := node("src")
	return Request{Pod: p, SourceNode: &src, Nodes: append([]corev1.Node{src}, nodes...), CPUPolicy: v1alpha1.CPUStrict}
}

func TestSelectPrefersMostFreeMemoryAndTieBreaksByName(t *testing.T) {
	req := baseRequest(pod("100m", "1Gi"), node("b"), node("a"), node("c", withMemory("4Gi")))
	res, err := Select(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Node != "a" {
		t.Fatalf("want a (tie with b, lower name), got %s", res.Node)
	}
	req.Usage = map[string]Usage{"a": {Memory: 2 << 30}}
	if res, _ = Select(req); res.Node != "b" {
		t.Fatalf("want b after a is loaded, got %s", res.Node)
	}
}

func TestSelectNeverPicksSource(t *testing.T) {
	_, err := Select(baseRequest(pod("1", "1Gi")))
	var nt *NoTargetError
	if !errors.As(err, &nt) {
		t.Fatalf("want NoTargetError, got %v", err)
	}
	req := baseRequest(pod("1", "1Gi"), node("a"))
	req.TargetNode = "src"
	if _, err := Select(req); err == nil {
		t.Fatal("explicit target == source must fail")
	}
}

func TestSelectBasicEligibility(t *testing.T) {
	notReady := node("notready")
	notReady.Status.Conditions[0].Status = corev1.ConditionFalse
	cordoned := node("cordoned")
	cordoned.Spec.Unschedulable = true
	noAgent := node("noagent")
	delete(noAgent.Annotations, v1alpha1.AnnotationNodeAgent)

	_, err := Select(baseRequest(pod("1", "1Gi"), notReady, cordoned, noAgent))
	var nt *NoTargetError
	if !errors.As(err, &nt) || len(nt.Rejections) != 3 {
		t.Fatalf("want 3 rejections, got %v", err)
	}
	for _, want := range []string{"not Ready", "cordoned", "no paguro agent"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestSelectTaints(t *testing.T) {
	p := pod("1", "1Gi")
	nodes := []corev1.Node{
		node("gpu", withTaint("gpu", "true", corev1.TaintEffectNoSchedule)),
		node("soft", withTaint("soft", "x", corev1.TaintEffectPreferNoSchedule)),
	}
	res, err := Select(baseRequest(p, nodes...))
	if err != nil || res.Node != "soft" {
		t.Fatalf("PreferNoSchedule must be ignored, NoSchedule must block: %v %v", res, err)
	}

	cases := []struct {
		name string
		tol  corev1.Toleration
		ok   bool
	}{
		{"equal match", corev1.Toleration{Key: "gpu", Operator: corev1.TolerationOpEqual, Value: "true"}, true},
		{"default operator is equal", corev1.Toleration{Key: "gpu", Value: "true"}, true},
		{"equal wrong value", corev1.Toleration{Key: "gpu", Value: "false"}, false},
		{"exists by key", corev1.Toleration{Key: "gpu", Operator: corev1.TolerationOpExists}, true},
		{"exists wildcard", corev1.Toleration{Operator: corev1.TolerationOpExists}, true},
		{"wrong effect", corev1.Toleration{Key: "gpu", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute}, false},
		{"right effect", corev1.Toleration{Key: "gpu", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := pod("1", "1Gi")
			p.Spec.Tolerations = []corev1.Toleration{tt.tol}
			req := baseRequest(p, nodes[0])
			_, err := Select(req)
			if (err == nil) != tt.ok {
				t.Fatalf("ok=%v, err=%v", tt.ok, err)
			}
		})
	}
}

func TestSelectNodeSelectorAndAffinity(t *testing.T) {
	nodes := []corev1.Node{
		node("a", withLabels("zone", "z1", "tier", "gold", "cores", "16")),
		node("b", withLabels("zone", "z2", "cores", "8")),
		node("c", withLabels("zone", "z3", "cores", "32", "spot", "true")),
	}
	expr := func(key string, op corev1.NodeSelectorOperator, vals ...string) corev1.NodeSelectorRequirement {
		return corev1.NodeSelectorRequirement{Key: key, Operator: op, Values: vals}
	}
	cases := []struct {
		name  string
		terms []corev1.NodeSelectorTerm
		want  string // "" = none
	}{
		{"In", []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{expr("zone", corev1.NodeSelectorOpIn, "z2")}}}, "b"},
		{"NotIn excludes", []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{expr("zone", corev1.NodeSelectorOpNotIn, "z1", "z2")}}}, "c"},
		{"Exists", []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{expr("tier", corev1.NodeSelectorOpExists)}}}, "a"},
		{"DoesNotExist", []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{
			expr("tier", corev1.NodeSelectorOpDoesNotExist), expr("spot", corev1.NodeSelectorOpDoesNotExist)}}}, "b"},
		{"Gt", []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{expr("cores", corev1.NodeSelectorOpGt, "20")}}}, "c"},
		{"Lt", []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{expr("cores", corev1.NodeSelectorOpLt, "10")}}}, "b"},
		{"terms are ORed", []corev1.NodeSelectorTerm{
			{MatchExpressions: []corev1.NodeSelectorRequirement{expr("zone", corev1.NodeSelectorOpIn, "nope")}},
			{MatchFields: []corev1.NodeSelectorRequirement{expr("metadata.name", corev1.NodeSelectorOpIn, "c")}},
		}, "c"},
		{"expressions are ANDed", []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{
			expr("zone", corev1.NodeSelectorOpIn, "z1"), expr("cores", corev1.NodeSelectorOpGt, "20")}}}, ""},
		{"empty term matches nothing", []corev1.NodeSelectorTerm{{}}, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := pod("1", "1Gi")
			p.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: tt.terms},
			}}
			res, err := Select(baseRequest(p, nodes...))
			if tt.want == "" {
				if err == nil {
					t.Fatalf("want no node, got %s", res.Node)
				}
				return
			}
			if err != nil || res.Node != tt.want {
				t.Fatalf("want %s, got %q (%v)", tt.want, res.Node, err)
			}
		})
	}

	p := pod("1", "1Gi")
	p.Spec.NodeSelector = map[string]string{"zone": "z3"}
	if res, err := Select(baseRequest(p, nodes...)); err != nil || res.Node != "c" {
		t.Fatalf("nodeSelector: want c, got %q (%v)", res.Node, err)
	}
}

func TestSelectResources(t *testing.T) {
	req := baseRequest(pod("3", "6Gi"), node("a"), node("b"))
	req.Usage = map[string]Usage{
		"a": {MilliCPU: 2000},  // 2 of 4 CPUs free → not enough
		"b": {Memory: 3 << 30}, // 5 GiB free → not enough
	}
	_, err := Select(req)
	if err == nil || !strings.Contains(err.Error(), "insufficient cpu") || !strings.Contains(err.Error(), "insufficient memory") {
		t.Fatalf("want cpu and memory rejections, got %v", err)
	}
	req.Usage["b"] = Usage{Memory: 1 << 30}
	if res, err := Select(req); err != nil || res.Node != "b" {
		t.Fatalf("want b, got %q (%v)", res.Node, err)
	}
}

func TestPodRequestsWithInitAndSidecars(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	req := func(cpu, mem string) corev1.ResourceRequirements {
		return corev1.ResourceRequirements{Requests: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse(cpu), corev1.ResourceMemory: resource.MustParse(mem)}}
	}
	p := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{
			{Name: "sidecar", RestartPolicy: &always, Resources: req("100m", "100Mi")},
			{Name: "big-init", Resources: req("2", "64Mi")},
		},
		Containers: []corev1.Container{{Name: "app", Resources: req("500m", "1Gi")}},
		Overhead:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m")},
	}}
	cpu, mem := PodRequests(p)
	if cpu != 2110 { // max(500+100, 100+2000) + 10
		t.Errorf("cpu = %d, want 2110", cpu)
	}
	if want := int64(1124 << 20); mem != want { // 1Gi + 100Mi
		t.Errorf("mem = %d, want %d", mem, want)
	}

	usage := NodeUsage([]corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{UID: "1"}, Spec: corev1.PodSpec{NodeName: "a", Containers: p.Spec.Containers}},
		{ObjectMeta: metav1.ObjectMeta{UID: "2"}, Spec: corev1.PodSpec{NodeName: "a", Containers: p.Spec.Containers}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
		{ObjectMeta: metav1.ObjectMeta{UID: "3"}, Spec: corev1.PodSpec{NodeName: "a", Containers: p.Spec.Containers}},
	}, "3")
	if u := usage["a"]; u.MilliCPU != 500 || u.Pods != 1 {
		t.Errorf("usage = %+v, want one pod with 500m", u)
	}
}

func TestSelectCPUCompatibility(t *testing.T) {
	old := node("old", withFlags("sse,sse2"))
	newer := node("newer", withFlags("sse,sse2,avx,avx2"), withMemory("1Gi"))

	// Strict: old lacks avx → only newer.
	req := baseRequest(pod("100m", "100Mi"), old, newer)
	res, err := Select(req)
	if err != nil || res.Node != "newer" {
		t.Fatalf("strict: want newer, got %q (%v)", res.Node, err)
	}

	// Strict + explicit incompatible target → error with missing flags.
	req.TargetNode = "old"
	_, err = Select(req)
	var nt *NoTargetError
	if !errors.As(err, &nt) || !reflect.DeepEqual(nt.Rejections[0].MissingCPUFlags, []string{"avx"}) {
		t.Fatalf("want missing [avx], got %v", err)
	}

	// Ignore → allowed, but with a warning.
	req.CPUPolicy = v1alpha1.CPUIgnore
	res, err = Select(req)
	if err != nil || res.Node != "old" || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "avx") {
		t.Fatalf("ignore: got %+v (%v)", res, err)
	}

	// Missing annotation on the target = no flags known.
	unknown := node("unknown")
	delete(unknown.Annotations, v1alpha1.AnnotationNodeCPUFlags)
	if _, err := Select(baseRequest(pod("1", "1Gi"), unknown)); err == nil {
		t.Fatal("unknown target CPU flags must be rejected under Strict")
	}
}

func TestMissingCPUFlagsIgnoresSystemFlags(t *testing.T) {
	// The lab's two hypervisor generations (k8s-w-3 vs k8s-w-1).
	src := "adx,avx2,rdseed,rtm,hle,3dnowprefetch,smap,sse4_2"
	dst := "avx2,sse4_2"
	got := MissingCPUFlags(src, dst)
	if want := []string{"3dnowprefetch", "adx", "hle", "rdseed", "rtm"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v (smap is kernel-only)", got, want)
	}
	if got := MissingCPUFlags("smap,smep,pti,hypervisor,vmx,avx2", "avx2"); len(got) != 0 {
		t.Fatalf("system-only flags must not block: %v", got)
	}
}

func TestMissingCPUFlags(t *testing.T) {
	if got := MissingCPUFlags("a, b,c", "c,b,a,d"); len(got) != 0 {
		t.Errorf("superset: got %v", got)
	}
	if got := MissingCPUFlags("z,a,b", "b"); !reflect.DeepEqual(got, []string{"a", "z"}) {
		t.Errorf("got %v", got)
	}
}

func TestSelectVolumeTopology(t *testing.T) {
	const zoneKey = "topology.cinder.csi.openstack.org/zone"
	req := baseRequest(pod("100m", "100Mi"),
		node("a", withLabels(zoneKey, "nova")),
		node("b", withLabels(zoneKey, "other"), withMemory("64Gi")))
	req.VolumeTopology = []*corev1.NodeSelector{{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
		MatchExpressions: []corev1.NodeSelectorRequirement{{Key: zoneKey, Operator: corev1.NodeSelectorOpIn, Values: []string{"nova"}}},
	}}}}
	res, err := Select(req)
	if err != nil || res.Node != "a" {
		t.Fatalf("want a (volume zone), got %q (%v)", res.Node, err)
	}
}

// The lab: a Broadwell source, a Haswell target without adx/rdseed/TSX.
func TestSelectCPUBaseline(t *testing.T) {
	src := node("broadwell", withFlags("sse2,avx2,bmi2,adx,rdseed,rtm,hle,3dnowprefetch,smap"))
	haswell := node("haswell", withFlags("sse2,avx2,bmi2"))
	req := func(baseline string) Request {
		p := pod("100m", "100Mi")
		if baseline != "" {
			p.Annotations = map[string]string{v1alpha1.AnnotationCPUBaseline: baseline}
		}
		return Request{Pod: p, SourceNode: &src, Nodes: []corev1.Node{src, haswell},
			TargetNode: "haswell", CPUPolicy: v1alpha1.CPUStrict}
	}

	// Created with the cluster's common baseline: adx & co. were never
	// available to its runtimes.
	res, err := Select(req("sse2,avx2,bmi2"))
	if err != nil || res.Node != "haswell" || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "outside the pod's CPU baseline") {
		t.Fatalf("baseline: got %+v (%v)", res, err)
	}
	// No baseline (created before Paguro stamped one): as strict as before,
	// but smap (kernel only) no longer counts.
	_, err = Select(req(""))
	var nt *NoTargetError
	if !errors.As(err, &nt) || !reflect.DeepEqual(nt.Rejections[0].MissingCPUFlags, []string{"3dnowprefetch", "adx", "hle", "rdseed", "rtm"}) {
		t.Fatalf("no baseline: %v", err)
	}
	// A baseline that includes adx (all nodes had it when the pod was
	// created): the pod may use it, the Haswell node is not eligible.
	_, err = Select(req("sse2,avx2,bmi2,adx"))
	if !errors.As(err, &nt) || !reflect.DeepEqual(nt.Rejections[0].MissingCPUFlags, []string{"adx"}) ||
		!strings.Contains(nt.Rejections[0].Reason, "within the pod's CPU baseline") {
		t.Fatalf("baseline with adx: %v", err)
	}
}

func TestSelectNeverCrossesArchitectures(t *testing.T) {
	src := node("x86")
	src.Labels[corev1.LabelArchStable] = "amd64"
	arm := node("graviton")
	arm.Labels[corev1.LabelArchStable] = "arm64"
	arm.Annotations[v1alpha1.AnnotationNodeCPUFlags] = "" // arm64 publishes "Features", not x86 flags
	for _, policy := range []v1alpha1.CPUPolicy{v1alpha1.CPUStrict, v1alpha1.CPUIgnore} {
		req := Request{Pod: pod("100m", "100Mi"), SourceNode: &src, Nodes: []corev1.Node{src, arm}, TargetNode: "graviton", CPUPolicy: policy}
		_, err := Select(req)
		var nt *NoTargetError
		if !errors.As(err, &nt) || !strings.Contains(nt.Rejections[0].Reason, "different CPU architecture (amd64 → arm64)") {
			t.Fatalf("%s: x86 → arm64 not refused: %v", policy, err)
		}
		// and the other way round, where the empty flag list once looked like "nothing missing"
		req.SourceNode, req.Nodes, req.TargetNode = &arm, []corev1.Node{arm, src}, "x86"
		if _, err := Select(req); !errors.As(err, &nt) {
			t.Fatalf("%s: arm64 → x86 not refused", policy)
		}
	}
}

// A pod with host ports goes only where they are free – the replacement
// keeps them (Agones game servers: players know the port).
func TestSelectHostPorts(t *testing.T) {
	p := pod("1", "1Gi")
	p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 7777, HostPort: 7938, Protocol: corev1.ProtocolUDP}}
	busy := corev1.Pod{Spec: corev1.PodSpec{NodeName: "a", Containers: []corev1.Container{{Name: "x",
		Ports: []corev1.ContainerPort{{ContainerPort: 1, HostPort: 7938, Protocol: corev1.ProtocolUDP}}}}}}
	tcp := corev1.Pod{Spec: corev1.PodSpec{NodeName: "b", Containers: []corev1.Container{{Name: "y",
		Ports: []corev1.ContainerPort{{ContainerPort: 1, HostPort: 7938}}}}}}
	req := baseRequest(p, node("a"), node("b"))
	req.Usage = NodeUsage([]corev1.Pod{busy, tcp})
	res, err := Select(req)
	if err != nil || res.Node != "b" {
		t.Fatalf("want b (only TCP 7938 in use there), got %v %v", res.Node, err)
	}
	req.TargetNode = "a"
	if _, err := Select(req); err == nil || !strings.Contains(err.Error(), "host port UDP/*:7938 in use") {
		t.Fatalf("want a host port rejection, got %v", err)
	}
	// Different addresses do not collide.
	busy.Spec.Containers[0].Ports[0].HostIP = "10.0.0.1"
	p.Spec.Containers[0].Ports[0].HostIP = "10.0.0.2"
	req.Usage = NodeUsage([]corev1.Pod{busy, tcp})
	if _, err := Select(req); err != nil {
		t.Fatalf("different host IPs: %v", err)
	}
}

func TestSelectSkipsDrainingAgentsAndOtherReleases(t *testing.T) {
	withAgent := func(version, draining string) nodeOpt {
		return func(n *corev1.Node) {
			if version != "" {
				n.Annotations[v1alpha1.AnnotationNodeAgentVersion] = version
			}
			if draining != "" {
				n.Annotations[v1alpha1.AnnotationNodeAgentDraining] = draining
			}
		}
	}
	req := baseRequest(pod("1", "1Gi"),
		node("draining", withAgent("v2", "2026-10-06T20:00:00Z")),
		node("old", withAgent("v1", "")),
		node("unknown"),
		node("same", withAgent("v2", "")))
	req.SourceNode.Annotations[v1alpha1.AnnotationNodeAgentVersion] = "v2"
	res, err := Select(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Node != "same" {
		t.Fatalf("want the node with the source's release, got %s", res.Node)
	}
	req.TargetNode = "draining"
	if _, err := Select(req); err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Fatalf("a draining agent must be refused, got %v", err)
	}
	req.TargetNode = "old"
	if _, err := Select(req); err == nil || !strings.Contains(err.Error(), "release v1, the source node's v2") {
		t.Fatalf("another release must be refused, got %v", err)
	}
	// Agents before the annotation existed: all "unknown", still eligible.
	delete(req.SourceNode.Annotations, v1alpha1.AnnotationNodeAgentVersion)
	req.TargetNode = "unknown"
	if res, err := Select(req); err != nil || res.Node != "unknown" {
		t.Fatalf("unversioned agents among themselves: %v %v", res, err)
	}
}

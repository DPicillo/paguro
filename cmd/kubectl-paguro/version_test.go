// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"paguro.dev/paguro/api/v1alpha1"
)

func TestImageTag(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/dpicillo/paguro/paguro-controller:v0.1.0":                         "v0.1.0",
		"localhost:5000/paguro/paguro-controller:dev":                              "dev",
		"localhost:5000/paguro/paguro-controller":                                  "",
		"ghcr.io/dpicillo/paguro/paguro-controller:v0.1.0@sha256:0123456789abcdef": "v0.1.0",
		"ghcr.io/dpicillo/paguro/paguro-controller@sha256:0123456789abcdef0123":    "@0123456789ab",
	} {
		if got := imageTag(in); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func versionScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	return s
}

func agentNode(name, release string) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{}},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	if release != "" {
		n.Annotations[v1alpha1.AnnotationNodeAgent] = "10.0.0.1:9555"
		n.Annotations[v1alpha1.AnnotationNodeAgentVersion] = release
	}
	return n
}

// An agent that withdrew (helm uninstall, a stopped agent) leaves its
// release on the node: such a node has no agent, as kubectl paguro nodes
// says too. A node that is not Ready is counted apart.
func TestLookupVersionsGoneAgents(t *testing.T) {
	gone := agentNode("gone", "v0.1.0")
	delete(gone.Annotations, v1alpha1.AnnotationNodeAgent)
	down := agentNode("down", "v0.1.0")
	down.Status.Conditions[0].Status = corev1.ConditionUnknown
	c := fake.NewClientBuilder().WithScheme(versionScheme()).WithObjects(agentNode("a", "v0.1.0"), gone, down).Build()
	cv := lookupVersions(context.Background(), c, "")
	if cv.agents["v0.1.0"] != 1 || cv.noAgent != 1 || cv.notReady != 1 {
		t.Fatalf("agents = %v, without = %d, not ready = %d", cv.agents, cv.noAgent, cv.notReady)
	}
	out := strings.Join(renderVersion(&cv), "\n")
	if !strings.Contains(out, "v0.1.0 on 1 node (1 node without an agent, 1 node not ready)") {
		t.Errorf("output:\n%s", out)
	}

	// After helm uninstall: no agent anywhere, whatever releases the nodes
	// still carry.
	c = fake.NewClientBuilder().WithScheme(versionScheme()).WithObjects(gone).Build()
	cv = lookupVersions(context.Background(), c, "")
	if out := strings.Join(renderVersion(&cv), "\n"); !strings.Contains(out, "none") || strings.Contains(out, "v0.1.0 on") {
		t.Errorf("uninstalled:\n%s", out)
	}
}

func controllerDeployment(ns, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: controllerName, Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/name": controllerName}},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](2),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{
				{Name: controllerContainer, Image: image},
			}}},
		},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 2},
	}
}

// The controller is found in any namespace by its label; agents are
// counted per release, nodes without an agent separately.
func TestLookupVersions(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(versionScheme()).WithObjects(
		controllerDeployment("paguro", "ghcr.io/dpicillo/paguro/paguro-controller:v0.1.0"),
		agentNode("a", "v0.1.0"), agentNode("b", "v0.1.0"), agentNode("c", "v0.1.1"), agentNode("cp", ""),
	).Build()
	cv := lookupVersions(context.Background(), c, "")
	if cv.err != nil || cv.controllerErr != nil || cv.nodesErr != nil {
		t.Fatalf("errors: %v %v %v", cv.err, cv.controllerErr, cv.nodesErr)
	}
	if cv.controller != "v0.1.0" || cv.controllerAt != "paguro/paguro-controller" || cv.controllerReady != "2/2 ready" {
		t.Errorf("controller = %q %q %q", cv.controller, cv.controllerAt, cv.controllerReady)
	}
	if cv.agents["v0.1.0"] != 2 || cv.agents["v0.1.1"] != 1 || cv.noAgent != 1 {
		t.Errorf("agents = %v, without = %d", cv.agents, cv.noAgent)
	}
	out := strings.Join(renderVersion(&cv), "\n")
	for _, want := range []string{"kubectl-paguro", "v0.1.0 (paguro/paguro-controller, 2/2 ready)",
		"v0.1.0 on 2 nodes, v0.1.1 on 1 node", "same release", "1 node without an agent"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// A namespace that holds no controller.
	cv = lookupVersions(context.Background(), c, "elsewhere")
	if out := strings.Join(renderVersion(&cv), "\n"); !strings.Contains(out, "not installed") {
		t.Errorf("no controller in the namespace:\n%s", out)
	}
}

// Without a cluster the plugin's version still prints, and one line says
// why nothing else does.
func TestVersionOffline(t *testing.T) {
	refused := errors.New("dial tcp 127.0.0.1:6443: connect: connection refused\nmore detail")
	c := fake.NewClientBuilder().WithScheme(versionScheme()).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error { return refused },
	}).Build()
	cv := lookupVersions(context.Background(), c, "")
	lines := renderVersion(&cv)
	if len(lines) != 2 || !strings.Contains(lines[0], version) ||
		!strings.Contains(lines[1], "not reachable") || !strings.Contains(lines[1], "connection refused") ||
		strings.Contains(lines[1], "more detail") {
		t.Errorf("offline output:\n%s", strings.Join(lines, "\n"))
	}
	if lines := renderVersion(nil); len(lines) != 1 {
		t.Errorf("--client output:\n%s", strings.Join(lines, "\n"))
	}

	// Nodes readable, Deployments not (RBAC): only the controller is unknown.
	forbidden := errors.New(`deployments.apps is forbidden: User "dev" cannot list resource "deployments"`)
	c = fake.NewClientBuilder().WithScheme(versionScheme()).WithObjects(agentNode("a", "v0.1.0")).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*appsv1.DeploymentList); ok {
					return forbidden
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	cv = lookupVersions(context.Background(), c, "")
	out := strings.Join(renderVersion(&cv), "\n")
	if cv.err != nil || !strings.Contains(out, "unknown") || !strings.Contains(out, "forbidden") || !strings.Contains(out, "v0.1.0 on 1 node") {
		t.Errorf("forbidden deployments:\n%s", out)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package main

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

// version is set at build time: -ldflags "-X main.version=<tag>"
// (make kubectl-plugin, make plugin-dist).
var version = "dev"

// The controller Deployment as the chart names and labels it.
const (
	controllerName      = "paguro-controller"
	controllerContainer = "controller"
)

// clusterTimeout bounds each request, so that an unreachable cluster is
// reported within seconds instead of after the client's default timeouts.
const clusterTimeout = 5 * time.Second

// clusterVersions is what the cluster runs. err is set when the cluster could
// not be asked at all; the other fields are then empty.
type clusterVersions struct {
	err error
	// controller: the image tag of the controller Deployment; "" if none
	// was found. controllerAt names it (namespace/name), controllerReady its
	// ready replicas out of the wanted ones.
	controller, controllerAt, controllerReady string
	// controllerErr: the Deployment could not be read (permissions).
	controllerErr error
	// agents: release → ready nodes whose agent publishes its endpoint;
	// noAgent: nodes without an agent endpoint (none ever ran, or it
	// withdrew – uninstalled, stopped); notReady: nodes with an agent
	// endpoint that are not Ready, so whether the agent runs is not known.
	agents   map[string]int
	noAgent  int
	notReady int
	// nodesErr: the nodes could not be listed.
	nodesErr error
}

func cmdVersion(ctx context.Context, args []string) error {
	var g globals
	var clientOnly bool
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	g.register(fs)
	fs.BoolVar(&clientOnly, "client", false, "only the plugin's version; do not contact the cluster")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if clientOnly {
		printLines(renderVersion(nil))
		return nil
	}
	cv := clusterVersions{}
	g.timeout = clusterTimeout
	c, _, err := g.connect()
	if err != nil {
		cv.err = err
	} else {
		ctx, cancel := context.WithTimeout(ctx, 3*clusterTimeout)
		defer cancel()
		cv = lookupVersions(ctx, c, g.namespace)
	}
	printLines(renderVersion(&cv))
	return nil
}

// lookupVersions finds the controller Deployment – in namespace if given,
// otherwise in any namespace – and the agents' releases on the nodes.
func lookupVersions(ctx context.Context, c client.Client, namespace string) clusterVersions {
	var cv clusterVersions
	var deps appsv1.DeploymentList
	opts := []client.ListOption{client.MatchingLabels{"app.kubernetes.io/name": controllerName}}
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := c.List(ctx, &deps, opts...); err != nil {
		cv.controllerErr = err
	} else {
		for i := range deps.Items {
			d := &deps.Items[i]
			for _, ctr := range d.Spec.Template.Spec.Containers {
				if ctr.Name != controllerContainer {
					continue
				}
				cv.controller = imageTag(ctr.Image)
				cv.controllerAt = d.Namespace + "/" + d.Name
				want := int32(1)
				if d.Spec.Replicas != nil {
					want = *d.Spec.Replicas
				}
				cv.controllerReady = fmt.Sprintf("%d/%d ready", d.Status.ReadyReplicas, want)
			}
			if cv.controller != "" {
				break
			}
		}
	}

	var nodes corev1.NodeList
	if err := c.List(ctx, &nodes); err != nil {
		cv.nodesErr = err
	} else {
		cv.agents = map[string]int{}
		for i := range nodes.Items {
			n := &nodes.Items[i]
			a := n.Annotations
			// The release stays on the node when an agent withdraws its
			// endpoint (helm uninstall, a stopped agent): only the
			// endpoint says that one runs – as kubectl paguro nodes shows.
			switch {
			case a[v1alpha1.AnnotationNodeAgent] == "" && a[v1alpha1.AnnotationNodeAgentDraining] == "":
				cv.noAgent++
			case !nodeReady(n):
				cv.notReady++
			default:
				cv.agents[orDash(a[v1alpha1.AnnotationNodeAgentVersion])]++
			}
		}
	}
	// Neither could be read: the cluster is not reachable (or the
	// credentials do not work), say so once.
	if cv.controllerErr != nil && cv.nodesErr != nil {
		return clusterVersions{err: cv.nodesErr}
	}
	return cv
}

// imageTag returns the tag of an image reference ("" without one; a digest
// is shown shortened when there is no tag).
func imageTag(image string) string {
	ref, digest, _ := strings.Cut(image, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[i+1:]
	}
	if digest != "" {
		if _, hex, ok := strings.Cut(digest, ":"); ok && len(hex) > 12 {
			return "@" + hex[:12]
		}
		return "@" + digest
	}
	return ""
}

// renderVersion prints the plugin's version and, unless cv is nil, what the
// cluster runs.
func renderVersion(cv *clusterVersions) []string {
	lines := []string{kvVersion("kubectl-paguro", fmt.Sprintf("%s (%s, %s/%s)", version, runtime.Version(), runtime.GOOS, runtime.GOARCH))}
	if cv == nil {
		return lines
	}
	if cv.err != nil {
		return append(lines, kvVersion("cluster", paint("not reachable", sYellow)+paint(" – "+oneLine(cv.err), sDim)))
	}

	switch {
	case cv.controllerErr != nil:
		lines = append(lines, kvVersion("controller", paint("unknown", sYellow)+paint(" – "+oneLine(cv.controllerErr), sDim)))
	case cv.controller == "":
		lines = append(lines, kvVersion("controller", paint("not installed", sYellow)+paint(" – no Deployment "+controllerName+" found", sDim)))
	default:
		v := cv.controller
		if version != "dev" && v != version {
			v = paint(v, sYellow)
		}
		lines = append(lines, kvVersion("controller", v+paint(fmt.Sprintf(" (%s, %s)", cv.controllerAt, cv.controllerReady), sDim)))
	}

	var others []string
	if cv.noAgent > 0 {
		others = append(others, plural(cv.noAgent, "node")+" without an agent")
	}
	if cv.notReady > 0 {
		others = append(others, plural(cv.notReady, "node")+" not ready")
	}
	switch {
	case cv.nodesErr != nil:
		lines = append(lines, kvVersion("agents", paint("unknown", sYellow)+paint(" – "+oneLine(cv.nodesErr), sDim)))
	case len(cv.agents) == 0:
		text := paint("none", sYellow) + paint(fmt.Sprintf(" – no ready node of %d runs a Paguro agent", cv.noAgent+cv.notReady), sDim)
		if cv.notReady > 0 {
			text += paint(" ("+plural(cv.notReady, "node")+" not ready)", sDim)
		}
		lines = append(lines, kvVersion("agents", text))
	default:
		releases := make([]string, 0, len(cv.agents))
		for r := range cv.agents {
			releases = append(releases, r)
		}
		sort.Strings(releases)
		parts := make([]string, 0, len(releases))
		for _, r := range releases {
			parts = append(parts, fmt.Sprintf("%s on %s", r, plural(cv.agents[r], "node")))
		}
		text := strings.Join(parts, ", ")
		if len(releases) > 1 {
			text = paint(text, sYellow) + paint(" – migrations run only between agents of the same release", sDim)
		}
		if len(others) > 0 {
			text += paint(" ("+strings.Join(others, ", ")+")", sDim)
		}
		lines = append(lines, kvVersion("agents", text))
	}
	return lines
}

// nodeReady: the node's Ready condition is True.
func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func kvVersion(k, v string) string { return paint(padRight(k, 16), sBold) + v }

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// oneLine shortens an error to its first line.
func oneLine(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	return s
}

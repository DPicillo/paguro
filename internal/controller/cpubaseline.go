// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/cpufeat"
)

// CPUBaseline returns the webhook's baseline function for a setting:
// "auto" – the relevant CPU features every node with a Paguro agent shares
// when the pod is created; "x86-64-v1" … "x86-64-v4" – a fixed level, for
// clusters whose node types change; "off" – no baseline (a pod can then
// only move to nodes that offer every feature of its current node).
func CPUBaseline(c client.Reader, setting string) (func(context.Context) (string, error), error) {
	setting = strings.ToLower(strings.TrimSpace(setting))
	switch setting {
	case "off":
		return nil, nil
	case "auto", "":
	default:
		if _, ok := cpufeat.Resolve(setting, nil); !ok {
			return nil, fmt.Errorf("unknown CPU baseline %q (auto, off, x86-64-v1 … x86-64-v4)", setting)
		}
	}
	return func(ctx context.Context) (string, error) {
		var nodes [][]string
		if setting == "auto" || setting == "" {
			var list corev1.NodeList
			if err := c.List(ctx, &list); err != nil {
				return "", err
			}
			for _, n := range list.Items {
				if n.Annotations[v1.AnnotationNodeAgent] == "" {
					continue
				}
				if f := n.Annotations[v1.AnnotationNodeCPUFlags]; f != "" {
					nodes = append(nodes, cpufeat.Parse(f))
				}
			}
		}
		b, ok := cpufeat.Resolve(setting, nodes)
		if !ok {
			return "", nil
		}
		return strings.Join(b, ","), nil
	}, nil
}

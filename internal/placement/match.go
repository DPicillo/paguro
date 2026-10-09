// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package placement

import (
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

// MatchNodeSelector checks a NodeSelector (requiredDuring... of a pod
// NodeAffinity or nodeAffinity of a PV) against a node.
// Semantics as in kube-scheduler: terms are ORed, expressions within a
// term are ANDed; an empty term matches no node.
func MatchNodeSelector(sel *corev1.NodeSelector, node *corev1.Node) (bool, error) {
	if sel == nil {
		return true, nil
	}
	for i := range sel.NodeSelectorTerms {
		ok, err := matchTerm(&sel.NodeSelectorTerms[i], node)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func matchTerm(t *corev1.NodeSelectorTerm, node *corev1.Node) (bool, error) {
	if len(t.MatchExpressions) == 0 && len(t.MatchFields) == 0 {
		return false, nil
	}
	for _, req := range t.MatchExpressions {
		val, has := node.Labels[req.Key]
		ok, err := matchRequirement(req, val, has)
		if err != nil || !ok {
			return false, err
		}
	}
	for _, req := range t.MatchFields {
		// The scheduler only supports metadata.name here.
		if req.Key != "metadata.name" {
			return false, fmt.Errorf("unsupported matchFields key %q", req.Key)
		}
		ok, err := matchRequirement(req, node.Name, true)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func matchRequirement(req corev1.NodeSelectorRequirement, val string, has bool) (bool, error) {
	switch req.Operator {
	case corev1.NodeSelectorOpIn:
		return has && contains(req.Values, val), nil
	case corev1.NodeSelectorOpNotIn:
		return !has || !contains(req.Values, val), nil
	case corev1.NodeSelectorOpExists:
		return has, nil
	case corev1.NodeSelectorOpDoesNotExist:
		return !has, nil
	case corev1.NodeSelectorOpGt, corev1.NodeSelectorOpLt:
		if len(req.Values) != 1 {
			return false, fmt.Errorf("operator %s on %q needs exactly one value", req.Operator, req.Key)
		}
		want, err := strconv.ParseInt(req.Values[0], 10, 64)
		if err != nil {
			return false, fmt.Errorf("operator %s on %q: %w", req.Operator, req.Key, err)
		}
		if !has {
			return false, nil
		}
		got, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			// A non-numeric label simply does not match (as in the scheduler).
			return false, nil
		}
		if req.Operator == corev1.NodeSelectorOpGt {
			return got > want, nil
		}
		return got < want, nil
	default:
		return false, fmt.Errorf("unknown node selector operator %q", req.Operator)
	}
}

// MatchNodeSelectorMap checks spec.nodeSelector (exact label equality).
func MatchNodeSelectorMap(sel map[string]string, node *corev1.Node) bool {
	for k, v := range sel {
		if node.Labels[k] != v {
			return false
		}
	}
	return true
}

// UntoleratedTaint returns the first taint with effect NoSchedule or
// NoExecute that the pod does not tolerate (nil = all tolerated).
func UntoleratedTaint(taints []corev1.Taint, tolerations []corev1.Toleration) *corev1.Taint {
	for i := range taints {
		t := &taints[i]
		if t.Effect != corev1.TaintEffectNoSchedule && t.Effect != corev1.TaintEffectNoExecute {
			continue
		}
		tolerated := false
		for j := range tolerations {
			if tolerates(&tolerations[j], t) {
				tolerated = true
				break
			}
		}
		if !tolerated {
			return t
		}
	}
	return nil
}

func tolerates(tol *corev1.Toleration, t *corev1.Taint) bool {
	if tol.Effect != "" && tol.Effect != t.Effect {
		return false
	}
	if tol.Key != "" && tol.Key != t.Key {
		return false
	}
	switch tol.Operator {
	case corev1.TolerationOpExists:
		return true
	case corev1.TolerationOpEqual, "":
		// An empty key with Equal is invalid per the API, so it tolerates nothing.
		return tol.Key != "" && tol.Value == t.Value
	default:
		return false
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

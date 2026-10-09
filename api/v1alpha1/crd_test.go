// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package v1alpha1

import (
	"os"
	"slices"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// The API server checks status values against the CRD's enums – a fake
// client does not. A value the code writes but the CRD lacks fails every
// status patch in a real cluster (found: cutover mode same-name, the
// migration stuck in Preflight).
func TestCRDEnumsMatchConstants(t *testing.T) {
	b, err := os.ReadFile("../../deploy/crds/paguro.dev_migrations.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(b, &crd); err != nil {
		t.Fatal(err)
	}
	root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	enum := func(path ...string) []string {
		s := root
		for _, p := range path {
			child, ok := s.Properties[p]
			if !ok {
				t.Fatalf("CRD has no %v", path)
			}
			s = &child
		}
		var out []string
		for _, e := range s.Enum {
			out = append(out, string(e.Raw[1:len(e.Raw)-1]))
		}
		return out
	}
	for _, c := range []struct {
		path []string
		want []string
	}{
		{[]string{"status", "cutover", "mode"}, []string{CutoverEarly, CutoverOnDelete, CutoverSameName}},
		{[]string{"spec", "network"}, []string{string(NetworkAuto), string(NetworkPreserve), string(NetworkPhantom),
			string(NetworkGeneric)}},
		{[]string{"status", "phase"}, []string{string(PhasePending), string(PhasePreflight), string(PhasePreCopy),
			string(PhaseFrozen), string(PhaseCuttingOver), string(PhaseRestoring), string(PhaseSucceeded),
			string(PhaseFailed), string(PhaseAborting), string(PhaseRolledBack)}},
	} {
		got := enum(c.path...)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("%v: the CRD lacks %q (has %v) – run make generate", c.path, w, got)
			}
		}
	}
}

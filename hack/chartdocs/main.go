// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// chartdocs writes the tables of the chart's values into the chart's
// README.md, between its markers: every value of values.yaml, in its order,
// with its type and description from values.schema.json and its default
// from values.yaml. Artifact Hub shows that README as the package page.
//
//	go run ./hack/chartdocs
//
// It fails on a value without a description and on a value that is in only
// one of the two files, so that the README, the schema and the defaults
// cannot drift apart (make generate-check runs it).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	chart  = "deploy/helm/paguro"
	readme = chart + "/README.md"
	begin  = "<!-- values:begin -->"
	end    = "<!-- values:end -->"
)

// groups are the README's tables, in this order. A value belongs to the
// group with the longest prefix that matches it.
var groups = []struct {
	title    string
	prefixes []string
}{
	{"Images", []string{"global", "controller.image", "agent.image", "nodeInstaller.image"}},
	{"Controller", []string{"controller"}},
	{"Agent", []string{"agent"}},
	{"Security", []string{"agent.transferTLS", "agent.restrictionPolicy", "agent.token", "agent.testFaults"}},
	{"Node installer", []string{"nodeInstaller"}},
	{"Webhooks and RuntimeClass", []string{"webhook", "runtimeClass"}},
	{"Network and Phantom mode", []string{"cni", "phantom", "commitGate"}},
	{"CPUs, Agones and the CRD", []string{"cpuBaseline", "agones", "crds"}},
	{"Monitoring", []string{"monitoring"}},
}

// published are defaults that the release workflow replaces in the packaged
// chart: the source tree points at a development registry.
var published = map[string]string{
	"global.imageRegistry": "ghcr.io/dpicillo/paguro",
}

// leafRefs are definitions documented as one value, not per property:
// requests and limits belong together.
var leafRefs = map[string]bool{"resources": true}

type row struct {
	key, typ, def, desc string
}

type schema = map[string]any

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "chartdocs:", err)
		os.Exit(1)
	}
}

func run() error {
	var root schema
	b, err := os.ReadFile(chart + "/values.schema.json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return fmt.Errorf("values.schema.json: %w", err)
	}
	var doc yaml.Node
	b, err = os.ReadFile(chart + "/values.yaml")
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("values.yaml: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("values.yaml: not a mapping")
	}
	defs, _ := root["definitions"].(schema)
	var rows []row
	var problems []string
	walk(doc.Content[0], root, defs, "", &rows, &problems)
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "\n  "))
	}
	return replaceBetween(readme, render(rows))
}

// walk collects a row per value. A mapping whose schema lists its
// properties is documented property by property; everything else (lists,
// free-form maps such as nodeSelector, resources) is one value.
func walk(n *yaml.Node, s, defs schema, path string, rows *[]row, problems *[]string) {
	props, _ := s["properties"].(schema)
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i].Value, n.Content[i+1]
		p := join(path, key)
		seen[key] = true
		sub, ok := props[key].(schema)
		if !ok {
			*problems = append(*problems, p+": in values.yaml, not in values.schema.json")
			continue
		}
		res, ref := resolve(sub, defs)
		if _, nested := res["properties"]; nested && val.Kind == yaml.MappingNode && !leafRefs[ref] {
			walk(val, res, defs, p, rows, problems)
			continue
		}
		desc := description(sub, res)
		if desc == "" {
			*problems = append(*problems, p+": no description in values.schema.json")
		}
		def := render1(val)
		if v, ok := published[p]; ok {
			def = "`" + v + "`"
		}
		*rows = append(*rows, row{key: p, typ: typeOf(sub, res), def: def, desc: desc})
	}
	// Properties the schema knows but values.yaml does not set would have no
	// documented default (global may hold other charts' keys).
	var missing []string
	for k := range props {
		if !seen[k] {
			missing = append(missing, join(path, k))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		*problems = append(*problems, m+": in values.schema.json, not in values.yaml")
	}
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// resolve follows a $ref into the definitions and returns the definition's
// name.
func resolve(s, defs schema) (schema, string) {
	ref, ok := s["$ref"].(string)
	if !ok {
		return s, ""
	}
	name := ref[strings.LastIndex(ref, "/")+1:]
	d, _ := defs[name].(schema)
	return d, name
}

// description prefers the one next to a $ref: it describes this use of the
// definition.
func description(s, res schema) string {
	if d, ok := s["description"].(string); ok && d != "" {
		return d
	}
	d, _ := res["description"].(string)
	return d
}

func typeOf(s, res schema) string {
	if alts, ok := res["oneOf"].([]any); ok {
		var parts []string
		for _, a := range alts {
			if as, ok := a.(schema); ok {
				parts = append(parts, typeOf(as, as))
			}
		}
		return strings.Join(parts, " or ")
	}
	if enum, ok := res["enum"].([]any); ok {
		var vals []string
		for _, v := range enum {
			vals = append(vals, fmt.Sprintf("`%v`", v))
		}
		return strings.Join(vals, ", ")
	}
	switch t := res["type"].(type) {
	case string:
		return map[string]string{
			"boolean": "bool", "integer": "int", "string": "string", "number": "number",
			"array": "list", "object": "map",
		}[t]
	case []any:
		var parts []string
		for _, x := range t {
			parts = append(parts, fmt.Sprint(x))
		}
		return strings.Join(parts, " or ")
	}
	return ""
}

// render1 renders a default as one line of YAML in flow style, without the
// comments values.yaml carries.
func render1(n *yaml.Node) string {
	c := flow(n)
	b, err := yaml.Marshal(c)
	if err != nil {
		return "?"
	}
	return "`" + strings.Join(strings.Fields(string(b)), " ") + "`"
}

func flow(n *yaml.Node) *yaml.Node {
	c := *n
	c.HeadComment, c.LineComment, c.FootComment = "", "", ""
	if c.Kind == yaml.MappingNode || c.Kind == yaml.SequenceNode {
		c.Style = yaml.FlowStyle
	}
	c.Content = nil
	for _, sub := range n.Content {
		c.Content = append(c.Content, flow(sub))
	}
	return &c
}

func render(rows []row) string {
	byGroup := make([][]row, len(groups))
	for _, r := range rows {
		best, bestLen := -1, -1
		for gi, g := range groups {
			for _, p := range g.prefixes {
				if (r.key == p || strings.HasPrefix(r.key, p+".")) && len(p) > bestLen {
					best, bestLen = gi, len(p)
				}
			}
		}
		if best < 0 {
			fmt.Fprintf(os.Stderr, "chartdocs: %s belongs to no group\n", r.key)
			os.Exit(1)
		}
		byGroup[best] = append(byGroup[best], r)
	}
	var sb strings.Builder
	sb.WriteString("<!-- Generated by hack/chartdocs from values.yaml and values.schema.json; edit those. -->\n")
	for gi, g := range groups {
		if len(byGroup[gi]) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "\n#### %s\n\n| Key | Type | Default | Description |\n|---|---|---|---|\n", g.title)
		for _, r := range byGroup[gi] {
			fmt.Fprintf(&sb, "| `%s` | %s | %s | %s |\n", r.key, cell(r.typ), cell(r.def), cell(r.desc))
		}
	}
	sb.WriteString("\n")
	return sb.String()
}

// cell escapes what Markdown would read as a column break or as HTML (a
// description's "<registry>").
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;").Replace(s)
}

func replaceBetween(path, body string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(b)
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		return fmt.Errorf("%s: markers %s / %s missing", path, begin, end)
	}
	return os.WriteFile(path, []byte(s[:i+len(begin)]+"\n"+body+s[j:]), 0o644)
}

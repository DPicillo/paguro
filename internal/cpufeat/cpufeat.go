// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package cpufeat decides which CPU features matter for a migrated process
// and keeps migratable pods to a CPU baseline, so that they can move between
// nodes with different CPUs.
//
// A process picks its code paths when it starts: glibc chooses memcpy and
// friends by CPUID (on CPUs with TSX it chooses variants that execute XTEST),
// the Go runtime uses ADX and BMI2 for crypto when the CPU has them, the JVM
// compiles for the AVX level it finds. Moved to a CPU without those
// instructions, the process dies with SIGILL at the next call – no
// checkpoint/restore tool can repair that afterwards. The way out is the
// one VM live migration takes with CPU models: a process that never saw a
// feature cannot depend on it. Paguro gives every migratable pod a baseline
// when it is created (the features all nodes share, or an x86-64 level) and
// starts its containers with the common runtimes limited to it (Env). A
// target that lacks only features outside the pod's baseline is then safe.
//
// What a baseline cannot cover: code that queries CPUID itself without a
// runtime switch (V8, Rust's feature detection, hand-written assembly,
// numpy's dispatch – numpy refuses to start when a feature it was built
// with is disabled), and binaries compiled for a higher level than the
// baseline. The latter cannot run on such a node in the first place, so a
// scheduler constraint already keeps them away – and Paguro respects it.
package cpufeat

import (
	"os"
	"slices"
	"sort"
	"strings"
)

// systemOnly: /proc/cpuinfo flags that user space cannot use – privileged
// instructions, paging and interrupt features, mitigations, virtualization,
// power and performance monitoring – and performance hints that add no
// instruction (erms, fsrm: `rep movsb` runs on every x86-64 CPU). A list of
// exclusions on purpose: a flag that is missing here is compared, which at
// worst refuses a target unnecessarily, never accepts an unsafe one.
var systemOnly = map[string]bool{
	// paging, interrupts, privileged state
	"vme": true, "de": true, "pse": true, "msr": true, "pae": true, "mce": true, "apic": true,
	"mtrr": true, "pge": true, "mca": true, "pat": true, "pse36": true, "pdpe1gb": true,
	"pcid": true, "invpcid": true, "x2apic": true, "smep": true, "smap": true, "umip": true,
	"xsaves": true, "monitor": true, "mwaitx": true, "nx": true, "ds_cpl": true, "dtes64": true,
	"xtpr": true, "pdcm": true, "dca": true, "tsc_deadline_timer": true, "tsc_adjust": true,
	"tsc_known_freq": true, "tsc_reliable": true, "constant_tsc": true, "nonstop_tsc": true,
	"nonstop_tsc_s3": true, "tsc_scale": true, "extapic": true, "cr8_legacy": true, "xtopology": true,
	"extd_apicid": true, "cpuid": true, "cpuid_fault": true, "rep_good": true, "nopl": true,
	"pti": true, "arch_capabilities": true, "core_capabilities": true, "split_lock_detect": true,
	"bus_lock_detect": true, "ibt": true, "pconfig": true, "tme": true, "sme": true, "osvw": true,
	"skinit": true, "wdt": true, "topoext": true, "cpb": true, "hw_pstate": true, "succor": true,
	"overflow_recov": true, "wbnoinvd": true, "flush_l1d": true, "md_clear": true, "ssbd": true,
	"virt_ssbd": true, "ibrs": true, "ibpb": true, "stibp": true, "ibrs_enhanced": true,
	"amd_ssbd": true, "amd_stibp": true, "amd_ppin": true, "intel_ppin": true, "retpoline": true,
	"retpoline_amd": true, "rsb_ctxsw": true, "use_ibpb": true, "use_ibrs_fw": true,
	// virtualization
	"hypervisor": true, "vmx": true, "svm": true, "smx": true, "tpr_shadow": true, "vnmi": true,
	"flexpriority": true, "ept": true, "ept_ad": true, "vpid": true, "vmmcall": true, "npt": true,
	"lbrv": true, "svm_lock": true, "nrip_save": true, "vmcb_clean": true, "flushbyasid": true,
	"decodeassists": true, "pausefilter": true, "pfthreshold": true, "avic": true,
	"v_vmsave_vmload": true, "vgif": true, "v_spec_ctrl": true, "x2avic": true, "sev": true,
	"sev_es": true, "sev_snp": true,
	// power, thermal, performance monitoring, resource control
	"acpi": true, "tm": true, "tm2": true, "pbe": true, "est": true, "dts": true, "dtherm": true,
	"ida": true, "arat": true, "pln": true, "pts": true, "hwp": true, "hwp_notify": true,
	"hwp_act_window": true, "hwp_epp": true, "hwp_pkg_req": true, "hfi": true, "epb": true,
	"aperfmperf": true, "arch_perfmon": true, "pebs": true, "bts": true, "ibs": true,
	"perfctr_core": true, "perfctr_nb": true, "perfctr_llc": true, "bpext": true, "intel_pt": true,
	"cqm": true, "cqm_llc": true, "cqm_occup_llc": true, "cqm_mbm_total": true,
	"cqm_mbm_local": true, "rdt_a": true, "mba": true, "cat_l2": true, "cat_l3": true,
	"cdp_l2": true, "cdp_l3": true, "ht": true, "ss": true, "cmp_legacy": true,
	// performance hints without an instruction of their own
	"erms": true, "fsrm": true, "fzrm": true, "fsrs": true, "fsrc": true,
}

// Relevant reports whether a /proc/cpuinfo flag can matter to a process.
func Relevant(flag string) bool { return flag != "" && !systemOnly[flag] }

// ISA returns the relevant flags, sorted and without duplicates.
func ISA(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, f := range flags {
		if f = strings.TrimSpace(f); Relevant(f) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// Parse splits a comma-separated flag list (node or pod annotation).
func Parse(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Intersect returns the relevant flags every set contains.
func Intersect(sets ...[]string) []string {
	if len(sets) == 0 {
		return nil
	}
	common := ISA(sets[0])
	for _, s := range sets[1:] {
		in := map[string]bool{}
		for _, f := range s {
			in[f] = true
		}
		common = slices.DeleteFunc(common, func(f string) bool { return !in[f] })
	}
	return common
}

// x86-64 microarchitecture levels (psABI) in /proc/cpuinfo names. v3 and v4
// add aes and pclmulqdq, which every v3 CPU has (Haswell, Zen and later)
// and without which TLS would fall back to software AES.
var (
	levelV1 = []string{"cmov", "cx8", "fpu", "fxsr", "mmx", "syscall", "sse", "sse2", "lm", "clflush", "tsc", "sep"}
	levelV2 = append(slices.Clone(levelV1), "cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3")
	levelV3 = append(slices.Clone(levelV2), "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe", "xsave", "aes", "pclmulqdq")
	levelV4 = append(slices.Clone(levelV3), "avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl")
	levels  = map[string][]string{"x86-64-v1": levelV1, "x86-64-v2": levelV2, "x86-64-v3": levelV3, "x86-64-v4": levelV4}
)

// Resolve turns a baseline setting into the feature list: "auto" is what
// all given nodes share, "x86-64-v1" … "x86-64-v4" a fixed level. ok is
// false for "off", an unknown setting, or "auto" without nodes.
func Resolve(setting string, nodes [][]string) (baseline []string, ok bool) {
	switch s := strings.ToLower(strings.TrimSpace(setting)); s {
	case "auto", "":
		if len(nodes) == 0 {
			return nil, false
		}
		return Intersect(nodes...), true
	default:
		l, known := levels[s]
		if !known {
			return nil, false
		}
		return ISA(l), true
	}
}

// Masked returns the relevant host features outside the baseline – the
// ones a pod's runtimes must not use on this host.
func Masked(host, baseline []string) []string {
	in := map[string]bool{}
	for _, f := range baseline {
		in[f] = true
	}
	var out []string
	for _, f := range ISA(host) {
		if !in[f] {
			out = append(out, f)
		}
	}
	return out
}

// HostFlags reads the CPU flags of this machine (/proc/cpuinfo, first CPU).
func HostFlags() ([]string, error) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}
	return parseCPUInfo(string(b)), nil
}

func parseCPUInfo(s string) []string {
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			if k = strings.TrimSpace(k); k == "flags" || k == "Features" { // x86, arm64
				return strings.Fields(v)
			}
		}
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package cpufeat

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The lab: guests on a Xeon E5-1650 v3 (Haswell) and v4 (Broadwell).
var (
	haswell   = Parse("fpu,sse,sse2,pni,ssse3,sse4_1,sse4_2,popcnt,avx,avx2,bmi1,bmi2,fma,f16c,abm,movbe,aes,pclmulqdq,xsave,erms,smep,pti,hypervisor")
	broadwell = append(slices.Clone(haswell), "adx", "rdseed", "rtm", "hle", "3dnowprefetch", "smap")
)

func TestRelevant(t *testing.T) {
	for _, f := range []string{"smap", "pti", "hypervisor", "vmx", "erms", "fsrm", ""} {
		if Relevant(f) {
			t.Errorf("%q counted as relevant", f)
		}
	}
	for _, f := range []string{"adx", "rtm", "avx2", "avx512f", "3dnowprefetch"} {
		if !Relevant(f) {
			t.Errorf("%q not relevant", f)
		}
	}
}

func TestResolveAndMasked(t *testing.T) {
	base, ok := Resolve("auto", [][]string{haswell, broadwell})
	if !ok || slices.Contains(base, "adx") || !slices.Contains(base, "avx2") || slices.Contains(base, "smep") {
		t.Fatalf("auto baseline = %v, %v", base, ok)
	}
	if got := Masked(broadwell, base); !reflect.DeepEqual(got, []string{"3dnowprefetch", "adx", "hle", "rdseed", "rtm"}) {
		t.Fatalf("masked on Broadwell = %v", got)
	}
	if got := Masked(haswell, base); len(got) != 0 {
		t.Fatalf("nothing to mask on the oldest node: %v", got)
	}
	v3, ok := Resolve("x86-64-v3", nil)
	if !ok || !slices.Contains(v3, "avx2") || slices.Contains(v3, "avx512f") || slices.Contains(v3, "adx") {
		t.Fatalf("x86-64-v3 = %v", v3)
	}
	if _, ok := Resolve("off", [][]string{haswell}); ok {
		t.Fatal("off resolved")
	}
	if _, ok := Resolve("auto", nil); ok {
		t.Fatal("auto without nodes resolved")
	}
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestEnvLab(t *testing.T) {
	env, set := Env([]string{"PATH=/usr/bin", "GODEBUG=http2client=0"}, []string{"3dnowprefetch", "adx", "hle", "rdseed", "rtm"})
	m := envMap(env)
	if m["PATH"] != "/usr/bin" {
		t.Error("PATH changed")
	}
	if m["GODEBUG"] != "http2client=0,cpu.adx=off" {
		t.Errorf("GODEBUG = %q (the image's setting must stay)", m["GODEBUG"])
	}
	if m["GLIBC_TUNABLES"] != "glibc.cpu.hwcaps=-RTM" {
		t.Errorf("GLIBC_TUNABLES = %q", m["GLIBC_TUNABLES"])
	}
	// adx = W1 bit 19, hle 4, rdseed 18, rtm 11
	if want := "~0x0:~0x" + "c0810"; m["OPENSSL_ia32cap"] != want {
		t.Errorf("OPENSSL_ia32cap = %q, want %q", m["OPENSSL_ia32cap"], want)
	}
	if j := m["JAVA_TOOL_OPTIONS"]; !strings.HasPrefix(j, "-XX:+IgnoreUnrecognizedVMOptions ") ||
		!strings.Contains(j, "-XX:-UseBMI2Instructions") || !strings.Contains(j, "-XX:-UseRTMLocking") {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", j)
	}
	if _, ok := m["ATEN_CPU_CAPABILITY"]; ok {
		t.Error("PyTorch limited although no vector feature is masked")
	}
	if !slices.Contains(set, "GODEBUG") || !slices.Contains(set, "GLIBC_TUNABLES") {
		t.Errorf("set = %v", set)
	}
}

func TestEnvMerges(t *testing.T) {
	env, _ := Env([]string{
		"GLIBC_TUNABLES=glibc.malloc.arena_max=2:glibc.cpu.hwcaps=-AVX512F",
		"OPENSSL_ia32cap=~0x2",
		"JAVA_TOOL_OPTIONS=-Xmx1g",
		"DOTNET_EnableAVX2=1",
	}, []string{"avx2", "avx512f"})
	m := envMap(env)
	if want := "glibc.malloc.arena_max=2:glibc.cpu.hwcaps=-AVX512F,-AVX2,-AVX2_Usable,-AVX512F,-AVX512F_Usable"; m["GLIBC_TUNABLES"] != want {
		t.Errorf("GLIBC_TUNABLES = %q, want %q", m["GLIBC_TUNABLES"], want)
	}
	if m["OPENSSL_ia32cap"] != "~0x2" {
		t.Errorf("an explicit OPENSSL_ia32cap must stay: %q", m["OPENSSL_ia32cap"])
	}
	if m["JAVA_TOOL_OPTIONS"] != "-XX:+IgnoreUnrecognizedVMOptions -Xmx1g -XX:UseAVX=1" {
		t.Errorf("JAVA_TOOL_OPTIONS = %q", m["JAVA_TOOL_OPTIONS"])
	}
	if m["DOTNET_EnableAVX2"] != "1" || m["DOTNET_EnableAVX512F"] != "0" {
		t.Errorf("dotnet: AVX2=%q AVX512F=%q", m["DOTNET_EnableAVX2"], m["DOTNET_EnableAVX512F"])
	}
	if m["ATEN_CPU_CAPABILITY"] != "default" {
		t.Errorf("ATEN_CPU_CAPABILITY = %q", m["ATEN_CPU_CAPABILITY"])
	}
	if env2, set := Env([]string{"A=1"}, nil); len(set) != 0 || len(env2) != 1 {
		t.Error("nothing masked must change nothing")
	}
}

func TestParseCPUInfo(t *testing.T) {
	x86 := "processor\t: 0\nmodel name\t: Xeon\nflags\t\t: fpu sse2 avx2\n"
	arm := "processor\t: 0\nBogoMIPS\t: 243.75\nFeatures\t: fp asimd aes pmull sha2 atomics\n"
	if got := parseCPUInfo(x86); strings.Join(got, ",") != "fpu,sse2,avx2" {
		t.Errorf("x86: %v", got)
	}
	if got := parseCPUInfo(arm); strings.Join(got, ",") != "fp,asimd,aes,pmull,sha2,atomics" {
		t.Errorf("arm64: %v", got)
	}
}

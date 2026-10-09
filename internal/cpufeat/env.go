// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package cpufeat

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Runtime switches per /proc/cpuinfo flag. Each runtime takes only names it
// knows; a feature a runtime does not dispatch on has no entry.

// glibc: glibc.cpu.hwcaps=-NAME (2.26+; unknown names are ignored, so the
// pre-2.33 spellings go along). RTM matters most: on CPUs with TSX glibc
// picks string functions that execute XTEST. XSAVEC is used by the dynamic
// linker's lazy binding.
var glibcNames = map[string][]string{
	"avx": {"AVX", "AVX_Usable"}, "avx2": {"AVX2", "AVX2_Usable"}, "fma": {"FMA", "FMA_Usable"},
	"fma4": {"FMA4", "FMA4_Usable"}, "bmi1": {"BMI1"}, "bmi2": {"BMI2"}, "abm": {"LZCNT"},
	"movbe": {"MOVBE"}, "popcnt": {"POPCNT"}, "sse4_1": {"SSE4_1"}, "sse4_2": {"SSE4_2"},
	"ssse3": {"SSSE3"}, "f16c": {"F16C"}, "rtm": {"RTM"}, "xsavec": {"XSAVEC"},
	"avx512f": {"AVX512F", "AVX512F_Usable"}, "avx512cd": {"AVX512CD"}, "avx512bw": {"AVX512BW"},
	"avx512dq": {"AVX512DQ", "AVX512DQ_Usable"}, "avx512vl": {"AVX512VL"},
}

// Go: GODEBUG=cpu.NAME=off (the runtime's internal/cpu options for amd64).
var goNames = map[string]string{
	"adx": "adx", "aes": "aes", "pclmulqdq": "pclmulqdq", "rdtscp": "rdtscp", "sha_ni": "sha",
	"popcnt": "popcnt", "pni": "sse3", "sse4_1": "sse41", "sse4_2": "sse42", "ssse3": "ssse3",
	"avx": "avx", "avx2": "avx2", "bmi1": "bmi1", "bmi2": "bmi2", "fma": "fma",
	"avx512f": "avx512f", "avx512bw": "avx512bw", "avx512vl": "avx512vl",
}

// OpenSSL: OPENSSL_ia32cap="~W0:~W1" clears capability bits. W0 is
// CPUID(1) EDX | ECX<<32, W1 is CPUID(7) EBX | ECX<<32.
var opensslBits = map[string]struct {
	word int
	bit  uint
}{
	"pni": {0, 32}, "pclmulqdq": {0, 33}, "ssse3": {0, 41}, "fma": {0, 44}, "sse4_1": {0, 51},
	"sse4_2": {0, 52}, "movbe": {0, 54}, "popcnt": {0, 55}, "aes": {0, 57}, "avx": {0, 60},
	"f16c": {0, 61}, "rdrand": {0, 62},
	"bmi1": {1, 3}, "hle": {1, 4}, "avx2": {1, 5}, "bmi2": {1, 8}, "rtm": {1, 11},
	"avx512f": {1, 16}, "avx512dq": {1, 17}, "rdseed": {1, 18}, "adx": {1, 19},
	"avx512ifma": {1, 21}, "avx512cd": {1, 28}, "sha_ni": {1, 29}, "avx512bw": {1, 30},
	"avx512vl": {1, 31}, "avx512vbmi": {1, 33}, "avx512_vbmi2": {1, 38}, "gfni": {1, 40},
	"vaes": {1, 41}, "vpclmulqdq": {1, 42}, "avx512_vnni": {1, 43},
}

// .NET: DOTNET_EnableNAME=0 (and COMPlus_ for .NET before 6).
var dotnetNames = map[string]string{
	"avx": "AVX", "avx2": "AVX2", "avx512f": "AVX512F", "bmi1": "BMI1", "bmi2": "BMI2",
	"fma": "FMA", "abm": "LZCNT", "popcnt": "POPCNT", "aes": "AES", "pclmulqdq": "PCLMULQDQ",
	"pni": "SSE3", "ssse3": "SSSE3", "sse4_1": "SSE41", "sse4_2": "SSE42", "movbe": "MOVBE",
	"avx_vnni": "AVXVNNI", "serialize": "X86Serialize",
}

// Java (HotSpot): JAVA_TOOL_OPTIONS. Unknown -XX options would stop the JVM
// from starting (UseRTMLocking is gone since JDK 23), hence
// IgnoreUnrecognizedVMOptions first.
var javaOptions = map[string][]string{
	"bmi1":      {"-XX:-UseBMI1Instructions", "-XX:-UseCountTrailingZerosInstruction"},
	"bmi2":      {"-XX:-UseBMI2Instructions"},
	"adx":       {"-XX:-UseBMI2Instructions"}, // the multiply intrinsics need BMI2 and ADX
	"abm":       {"-XX:-UseCountLeadingZerosInstruction"},
	"popcnt":    {"-XX:-UsePopCountInstruction"},
	"aes":       {"-XX:-UseAES", "-XX:-UseAESIntrinsics", "-XX:-UseAESCTRIntrinsics"},
	"sha_ni":    {"-XX:-UseSHA"},
	"fma":       {"-XX:-UseFMA"},
	"pclmulqdq": {"-XX:-UseCLMUL"},
	"rtm":       {"-XX:-UseRTMLocking"},
}

// Env adds the runtime switches for the masked features to a container's
// environment (KEY=VALUE entries, as in an OCI spec). Values the image or
// the pod already set are extended, not replaced; OPENSSL_ia32cap is left
// alone when set. Returns the new environment and the variables it set.
func Env(env []string, masked []string) ([]string, []string) {
	if len(masked) == 0 {
		return env, nil
	}
	b := &envBuilder{out: slices.Clone(env), masked: map[string]bool{}}
	for _, f := range masked {
		b.masked[f] = true
	}
	b.ordered = slices.Sorted(maps.Keys(b.masked))
	b.glibc()
	b.goDebug()
	b.openssl()
	b.dotnet()
	b.java()
	b.pytorch()
	return b.out, b.set
}

// envBuilder is one run of Env.
type envBuilder struct {
	out     []string
	set     []string
	masked  map[string]bool
	ordered []string // masked, sorted
}

func (b *envBuilder) get(k string) (string, int) {
	for i, kv := range b.out {
		if name, v, ok := strings.Cut(kv, "="); ok && name == k {
			return v, i
		}
	}
	return "", -1
}

func (b *envBuilder) put(k, v string) {
	if _, i := b.get(k); i >= 0 {
		b.out[i] = k + "=" + v
	} else {
		b.out = append(b.out, k+"="+v)
	}
	b.set = append(b.set, k)
}

func (b *envBuilder) glibc() {
	var hw []string
	for _, f := range b.ordered {
		for _, n := range glibcNames[f] {
			hw = append(hw, "-"+n)
		}
	}
	if len(hw) > 0 {
		cur, _ := b.get("GLIBC_TUNABLES")
		b.put("GLIBC_TUNABLES", mergeTunables(cur, strings.Join(hw, ",")))
	}
}

func (b *envBuilder) goDebug() {
	var gd []string
	for _, f := range b.ordered {
		if n, ok := goNames[f]; ok {
			gd = append(gd, "cpu."+n+"=off")
		}
	}
	if len(gd) > 0 {
		cur, _ := b.get("GODEBUG")
		b.put("GODEBUG", joinNonEmpty(",", cur, strings.Join(gd, ",")))
	}
}

func (b *envBuilder) openssl() {
	var words [2]uint64
	for _, f := range b.ordered {
		if bit, ok := opensslBits[f]; ok {
			words[bit.word] |= 1 << bit.bit
		}
	}
	if words != [2]uint64{} {
		if _, i := b.get("OPENSSL_ia32cap"); i < 0 {
			b.put("OPENSSL_ia32cap", fmt.Sprintf("~0x%x:~0x%x", words[0], words[1]))
		}
	}
}

func (b *envBuilder) dotnet() {
	for _, f := range b.ordered {
		if n, ok := dotnetNames[f]; ok {
			for _, prefix := range []string{"DOTNET_Enable", "COMPlus_Enable"} {
				if _, i := b.get(prefix + n); i < 0 {
					b.put(prefix+n, "0")
				}
			}
		}
	}
}

func (b *envBuilder) java() {
	m := b.masked
	var jo []string
	switch {
	case m["avx"]:
		jo = append(jo, "-XX:UseAVX=0")
	case m["avx2"]:
		jo = append(jo, "-XX:UseAVX=1")
	case m["avx512f"]:
		jo = append(jo, "-XX:UseAVX=2")
	}
	switch {
	case m["pni"] || m["ssse3"]:
		jo = append(jo, "-XX:UseSSE=2")
	case m["sse4_1"] || m["sse4_2"]:
		jo = append(jo, "-XX:UseSSE=3")
	}
	for _, f := range b.ordered {
		for _, o := range javaOptions[f] {
			if !slices.Contains(jo, o) {
				jo = append(jo, o)
			}
		}
	}
	if len(jo) > 0 {
		cur, _ := b.get("JAVA_TOOL_OPTIONS")
		b.put("JAVA_TOOL_OPTIONS", joinNonEmpty(" ", "-XX:+IgnoreUnrecognizedVMOptions", cur, strings.Join(jo, " ")))
	}
}

func (b *envBuilder) pytorch() {
	m := b.masked
	if _, i := b.get("ATEN_CPU_CAPABILITY"); i >= 0 {
		return
	}
	switch {
	case m["avx"] || m["avx2"] || m["fma"]:
		b.put("ATEN_CPU_CAPABILITY", "default")
	case m["avx512f"] || m["avx512bw"] || m["avx512vl"] || m["avx512dq"]:
		b.put("ATEN_CPU_CAPABILITY", "avx2")
	}
}

// mergeTunables adds -NAME entries to glibc.cpu.hwcaps in a GLIBC_TUNABLES
// value ("name=value:name=value").
func mergeTunables(cur, hwcaps string) string {
	const key = "glibc.cpu.hwcaps="
	parts := strings.Split(cur, ":")
	for i, p := range parts {
		if v, ok := strings.CutPrefix(p, key); ok {
			parts[i] = key + joinNonEmpty(",", v, hwcaps)
			return strings.Join(parts, ":")
		}
	}
	return joinNonEmpty(":", cur, key+hwcaps)
}

func joinNonEmpty(sep string, parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), sep)
}

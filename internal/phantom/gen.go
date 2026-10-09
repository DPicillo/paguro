// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package phantom

// The eBPF object is compiled with clang and embedded via bpf2go. The
// generated files (phantom_bpfel.go, phantom_bpfel.o) are committed so a
// normal `go build` needs no clang. Regenerate after changing bpf/phantom.c:
//
//	make bpf-generate                # clang in a container, nothing local needed
//	go generate ./internal/phantom/  # with a local clang and llvm-strip
//
// BPF2GO_CC selects the compiler (default: clang), e.g. BPF2GO_CC=clang-19,
// and BPF2GO_STRIP the llvm-strip that removes DWARF (default: llvm-strip
// with the compiler's version suffix). On Debian/Ubuntu the asm/ headers
// live in the multiarch include directory.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type xl_key -type xl_val -type ctl phantom bpf/phantom.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu

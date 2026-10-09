#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Build-time helper: turns dynamically linked binaries into a self-contained
# bundle that runs on any glibc-based Linux host, independent of the host's
# glibc version (Ubuntu 22.04/24.04, Amazon Linux 2023 with glibc 2.34, ...).
#
#   bundle.sh <dest-prefix> <binary>...
#   bundle.sh --licenses <dest> <binary>...   (copyright files, see below)
#
# Layout (dest-prefix is /opt/paguro on the host):
#   <dest>/bin/<name>           the binary, patched with patchelf:
#                                 PT_INTERP -> /opt/paguro/lib/ld-linux-*.so.*
#                                 DT_RPATH  -> /opt/paguro/lib
#   <dest>/lib/                 every shared library the binaries need,
#                               including glibc and the dynamic loader
#
# Why not LD_LIBRARY_PATH + wrapper script: runc execs "criu" and CRIU execs
# helpers (iptables-restore, action scripts); an exported LD_LIBRARY_PATH would
# leak our libraries into those host programs. DT_RPATH (not RUNPATH) is used
# because it also applies to indirect dependencies (libnftables -> libnftnl).
# The absolute interpreter path works because the bundle is always installed
# at the fixed prefix /opt/paguro (in the image and on the host).
set -euo pipefail

prefix=/opt/paguro

# bundle.sh --licenses <dest> <binary>...: copy the Debian copyright file of
# every package that provided a bundled library or one of the binaries
# (license notices that must travel with the binaries).
if [ "${1:-}" = "--licenses" ]; then
	out=$2
	shift 2
	mkdir -p "$out"
	for f in "$prefix"/lib/* "$@"; do
		pkg=$(dpkg -S "*/$(basename "$f")" 2>/dev/null | head -1 | cut -d: -f1) || true
		if [ -n "$pkg" ] && [ -f "/usr/share/doc/$pkg/copyright" ]; then
			cp "/usr/share/doc/$pkg/copyright" "$out/$pkg.copyright"
		fi
	done
	ls "$out"
	exit 0
fi

dest=$1
shift
mkdir -p "$dest/bin" "$dest/lib"

loader=""
for bin in "$@"; do
	name=$(basename "$bin")
	install -m 0755 "$bin" "$dest/bin/$name"
	# ldd output: "libfoo.so.1 => /lib/x86_64-linux-gnu/libfoo.so.1 (0x...)"
	# and "/lib64/ld-linux-x86-64.so.2 (0x...)" for the loader.
	while read -r lib; do
		[ -n "$lib" ] || continue
		cp -L "$lib" "$dest/lib/$(basename "$lib")"
	done < <(ldd "$bin" | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^\//) { print $i; break }}')
	l=$(ldd "$bin" | awk '/ld-linux/{for(i=1;i<=NF;i++) if ($i ~ /^\//) {print $i; exit}}')
	[ -n "$l" ] && loader=$(basename "$l")
done
[ -n "$loader" ] || { echo "bundle.sh: no dynamic loader found" >&2; exit 1; }
chmod 0755 "$dest/lib/$loader"

for bin in "$@"; do
	name=$(basename "$bin")
	patchelf --set-interpreter "$prefix/lib/$loader" --force-rpath --set-rpath "$prefix/lib" "$dest/bin/$name"
done
# Libraries look up their own deps via the executable's DT_RPATH; drop any
# RUNPATH they carry so nothing points back into the build system.
for so in "$dest"/lib/*.so*; do
	[ "$(basename "$so")" = "$loader" ] && continue
	patchelf --remove-rpath "$so" 2>/dev/null || true
done
echo "bundled into $dest (loader $loader):"
ls -la "$dest/bin" "$dest/lib"

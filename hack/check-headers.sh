#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Fails if a source file lacks its SPDX license identifier (docs/THIRD-PARTY.md).
set -euo pipefail
cd "$(dirname "$0")/.."
# Listed first: inside a process substitution a failing git (no checkout)
# would go unnoticed and check nothing.
files=$(git ls-files '*.go' '*.sh' '*.mk' 'Makefile' '*Dockerfile' 'internal/phantom/bpf/*.c')
[ -n "$files" ] || { echo "no files to check (not a git checkout?)" >&2; exit 1; }
missing=0
while IFS= read -r f; do
	if ! head -3 "$f" | grep -q "SPDX-License-Identifier:"; then
		echo "missing SPDX header: $f"
		missing=1
	fi
done <<<"$files"
exit $missing

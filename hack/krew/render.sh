#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Picillo
#
# Renders the krew manifest (hack/krew/paguro.yaml) for a release: the
# version and the SHA-256 sums of the plugin archives, read from the
# release's checksum file (make plugin-dist: kubectl-paguro_<tag>_checksums.txt).
#
#   hack/krew/render.sh v0.1.0 > paguro.yaml             # checksums from the GitHub release
#   hack/krew/render.sh v0.1.0 dist/plugin/kubectl-paguro_v0.1.0_checksums.txt
#
# The output is plugins/paguro.yaml in a pull request to kubernetes-sigs/krew-index
# (docs/RELEASING.md, "krew").
set -euo pipefail
cd "$(dirname "$0")/../.."

tag=${1:?usage: hack/krew/render.sh <tag> [checksums file]}
sums=${2:-}
repo=${PAGURO_GITHUB_REPO:-DPicillo/paguro}
case "$tag" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*) echo "not a release tag: $tag" >&2; exit 1 ;;
esac
case "$tag" in
*-*) echo "warning: $tag is a release candidate; krew-index takes releases only" >&2 ;;
esac

if [ -z "$sums" ]; then
	sums=$(mktemp)
	trap 'rm -f "$sums"' EXIT
	curl -fsSL "https://github.com/$repo/releases/download/$tag/kubectl-paguro_${tag}_checksums.txt" -o "$sums"
fi

args=(-e "s#@VERSION@#$tag#g")
for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64; do
	sum=$(awk -v f="kubectl-paguro_${tag}_${platform}.tar.gz" '$2 == f || $2 == "*"f {print $1}' "$sums")
	if ! [[ $sum =~ ^[0-9a-f]{64}$ ]]; then
		echo "no SHA-256 for kubectl-paguro_${tag}_${platform}.tar.gz in $sums" >&2
		exit 1
	fi
	args+=(-e "s#@SHA256_${platform^^}@#$sum#g")
done

# Without the template's own header comment: krew-index wants the manifest only.
out=$(sed "${args[@]}" hack/krew/paguro.yaml | sed '1,/^apiVersion:/{/^#/d}')
if grep -q '@[A-Z0-9_]*@' <<<"$out"; then
	echo "unfilled placeholders left in the manifest" >&2
	exit 1
fi
printf '%s\n' "$out"

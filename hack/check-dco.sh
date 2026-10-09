#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Picillo
#
# Developer Certificate of Origin: every commit in BASE..HEAD (merges
# excepted) must carry a Signed-off-by trailer of its author
# (CONTRIBUTING.md). Run by the CI for pull requests; locally:
#
#   hack/check-dco.sh origin/main HEAD
set -euo pipefail

base=${1:?usage: hack/check-dco.sh <base> <head>}
head=${2:-HEAD}
# Listed first: inside a process substitution an invalid base or head
# would go unnoticed and check nothing.
commits=$(git rev-list --no-merges "$base..$head") || { echo "invalid range $base..$head" >&2; exit 1; }
missing=0
checked=0
while IFS= read -r c; do
	[ -n "$c" ] || continue
	checked=$((checked + 1))
	author=$(git show -s --format='%an <%ae>' "$c")
	if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$c" | grep -qxF "$author"; then
		echo "missing 'Signed-off-by: $author': $(git show -s --format='%h %s' "$c")"
		missing=$((missing + 1))
	fi
done <<<"$commits"

if [ "$missing" -gt 0 ]; then
	echo "$missing of $checked commit(s) not signed off – git rebase --signoff $base (CONTRIBUTING.md)"
	exit 1
fi
echo "$checked commit(s) signed off"

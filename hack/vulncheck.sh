#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Picillo
#
# govulncheck with reviewed exceptions: fails on every known vulnerability
# Paguro's code reaches (symbol level) unless hack/vulncheck-accepted.txt
# lists its ID with a reason. Needs network access (vuln.go.dev).
set -euo pipefail
cd "$(dirname "$0")/.."
GOVULNCHECK=${GOVULNCHECK:-govulncheck}
accepted=$(grep -oE '^GO-[0-9]+-[0-9]+' hack/vulncheck-accepted.txt || true)
"$GOVULNCHECK" -format json ./... | python3 -c '
import json, sys
accepted = set(sys.argv[1].split())
dec, buf, found = json.JSONDecoder(), sys.stdin.read(), {}
i = 0
while i < len(buf):
    while i < len(buf) and buf[i].isspace():
        i += 1
    if i >= len(buf):
        break
    obj, i = dec.raw_decode(buf, i)
    f = obj.get("finding")
    if f and f.get("trace") and f["trace"][0].get("function"):
        found.setdefault(f["osv"], f.get("fixed_version", "no fix"))
bad = {k: v for k, v in found.items() if k not in accepted}
for k in sorted(found):
    print(("accepted " if k in accepted else "VULNERABLE ") + k + " (fixed in " + found[k] + ")")
for k in sorted(accepted - set(found)):
    print("stale exception (no longer found): " + k)
sys.exit(1 if bad else 0)
' "$accepted"

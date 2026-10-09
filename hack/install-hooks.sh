#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Installs a pre-push hook that runs `make ci` (the checks of
# .github/workflows/ci.yaml) before anything leaves this machine.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
cat > .git/hooks/pre-push <<'HOOK'
#!/bin/bash
# Installed by hack/install-hooks.sh. Skip once with: git push --no-verify
exec make ci
HOOK
chmod +x .git/hooks/pre-push
echo "pre-push hook installed"

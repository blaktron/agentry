#!/usr/bin/env bash
# Git acceptance: the git protocol conformance matrix is green, including
# the rejected cases (oversize pushes, wrong credentials, tag permissions).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== git acceptance =="
./scripts/conformance/git.sh
echo "== git acceptance PASSED =="

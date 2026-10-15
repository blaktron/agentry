#!/usr/bin/env bash
# M2 acceptance (PLAN §18.2): git conformance matrix green; oversize,
# wrong-auth, and tag-permission cases rejected (all inside the matrix).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== M2 acceptance =="
./scripts/conformance/git.sh
echo "== M2 acceptance PASSED =="

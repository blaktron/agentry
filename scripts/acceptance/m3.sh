#!/usr/bin/env bash
# M3 acceptance (PLAN §18.2): publish→install round-trip for all 3 kinds ×
# both sources, byte-reproducible archives, yank semantics, and the state
# machine property (no path to published skips the gate).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
. scripts/acceptance/lib.sh
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

echo "== M3 acceptance =="
gotest "archives byte-reproducible" -timeout 20m ./pkg/archive -run TestArchiveReproducible -count=1
gotest "state machine edges (§7)" -timeout 20m ./internal/registry -run TestStateMachineEdges -count=1
gotest "publish→install 3 kinds × 2 sources" -timeout 20m ./internal/gitsrv -run TestM3PublishInstallRoundTrip -count=1
gotest "yank semantics (§5.5)" -timeout 20m ./internal/gitsrv -run TestM3YankSemantics -count=1
gotest "authz matrix incl. version routes" -timeout 20m ./internal/api -run TestAuthzMatrix -count=1
echo "== M3 acceptance PASSED =="

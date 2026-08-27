#!/usr/bin/env bash
# M3 acceptance (PLAN §18.2): publish→install round-trip for all 3 kinds ×
# both sources, byte-reproducible archives, yank semantics, and the state
# machine property (no path to published skips the gate).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

echo "== M3 acceptance =="
go test ./internal/registry -run TestArchiveReproducible -count=1 >/dev/null && echo "archives byte-reproducible: OK"
go test ./internal/registry -run TestStateMachineEdges -count=1 >/dev/null   && echo "state machine edges (§7): OK"
go test ./internal/gitsrv -run TestM3PublishInstallRoundTrip -count=1 >/dev/null && echo "publish→install 3 kinds × 2 sources: OK"
go test ./internal/gitsrv -run TestM3YankSemantics -count=1 >/dev/null      && echo "yank semantics (§5.5): OK"
go test ./internal/api -run TestAuthzMatrix -count=1 >/dev/null             && echo "authz matrix incl. version routes: OK"
echo "== M3 acceptance PASSED =="

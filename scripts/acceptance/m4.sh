#!/usr/bin/env bash
# M4 acceptance (PLAN §18.2): attack-corpus gate (100% recall, no benign
# regressions), state-machine property (no path to published skips the gate),
# attestation verified offline, policy tighten-only, extractor fuzz-safe.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

echo "== M4 acceptance =="
./scripts/dev/sync-rules.sh --check
go test ./internal/scan -run TestAttackCorpusGate -count=1 >/dev/null  && echo "attack-corpus gate (recall+precision, §17.3): OK"
go test ./internal/scan -run TestGate -count=1 >/dev/null              && echo "gate severity table (§8.5): OK"
go test ./internal/scan -run 'TestPolicyTightenOnly' -count=1 >/dev/null && echo "policy tighten-only (§8.6): OK"
go test ./internal/scan -run TestAttestationRoundTrip -count=1 >/dev/null && echo "DSSE attestation verify (§8.8): OK"
go test ./internal/scan -run TestExtractRejects -count=1 >/dev/null    && echo "hardened extractor (§8.2): OK"
go test ./internal/scan -run TestPipeline -count=1 >/dev/null          && echo "pipeline: benign publishes+signs, malicious gates (§7,§8): OK"
go test ./internal/api  -run 'TestReviewQueue|TestOrgReview|TestOrgPolicy|TestPlatformAction|TestReviewApprovalFlow' -count=1 >/dev/null && echo "review/policy/platform authz (§8.6,§12.2): OK"
echo "== M4 acceptance PASSED =="

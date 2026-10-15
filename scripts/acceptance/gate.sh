#!/usr/bin/env bash
# Pipeline gate acceptance: attack-corpus gate (100% recall, no benign
# regressions), state-machine property (no path to published skips the gate),
# attestation verified offline, policy tighten-only, extractor fuzz-safe.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
. scripts/acceptance/lib.sh
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

echo "== pipeline gate acceptance =="
./scripts/dev/sync-rules.sh --check
gotest "attack-corpus gate (recall+precision)" -timeout 20m ./internal/scan -run TestAttackCorpusGate -count=1

# The five incident reproductions, named individually so a missing
# one fails by name rather than by a corpus count. The postmark pair runs
# through S9's content diff as a PAIR — v1 staged as the previous published
# version — which is the only path that exercises the rug-pull defense.
gotest "  incident: postmark v1 baseline clean" -timeout 20m ./internal/scan -run 'TestAttackCorpusGate/incident-postmark-v1$' -count=1
gotest "  incident: postmark v2 rug-pull diff (S9+S6)" -timeout 20m ./internal/scan -run 'TestAttackCorpusGate/incident-postmark-v2$' -count=1
gotest "  incident: Amazon Q wiper prose (S4 destructive)" -timeout 20m ./internal/scan -run 'TestAttackCorpusGate/incident-amazonq-wiper' -count=1
gotest "  incident: ClawHavoc publisher anomaly (S8)" -timeout 20m ./internal/scan -run 'TestAttackCorpusGate/incident-clawhavoc' -count=1
gotest "  incident: GlassWorm invisible payload (S3)" -timeout 20m ./internal/scan -run 'TestAttackCorpusGate/incident-glassworm' -count=1

# Scanner depth beyond the corpus tree: the boundaries a fixture tree
# cannot express — must-not-fire cases, and the EXIF pair, whose images are
# generated in-test to keep the corpus text-only.
gotest "scanner depth S6-S9" -timeout 20m ./internal/scan -run 'TestS6|TestS7|TestS8|TestS9|TestBumpSize' -count=1
gotest "image alt-text + EXIF extraction (S3)" -timeout 20m ./internal/scan -run 'TestImageMetadataInjectionFixture|TestMarkdownAltTextIsScanned|TestExtractImageText' -count=1

# The fuzz corpora are committed; running the targets as ordinary
# tests replays every committed seed without invoking the mutator.
gotest "fuzz seed corpora (extractor, manifest, sanitizer)" -timeout 20m ./pkg/archive ./internal/render ./pkg/manifest -run 'Fuzz' -count=1

gotest "gate severity table" -timeout 20m ./internal/scan -run TestGate -count=1
gotest "policy tighten-only" -timeout 20m ./internal/scan -run 'TestPolicyTightenOnly' -count=1
gotest "DSSE attestation verify" -timeout 20m ./internal/scan -run TestAttestationRoundTrip -count=1
gotest "hardened extractor" -timeout 20m ./pkg/archive -run TestExtractRejects -count=1
gotest "pipeline: benign publishes+signs, malicious gates" -timeout 20m ./internal/scan -run TestPipeline -count=1
gotest "review/policy/platform authz" -timeout 20m ./internal/api  -run 'TestReviewQueue|TestOrgReview|TestOrgPolicy|TestPlatformAction|TestReviewApprovalFlow' -count=1
echo "== pipeline gate acceptance PASSED =="

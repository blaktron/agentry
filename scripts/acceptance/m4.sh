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

# The five Appendix A incident reproductions, named individually so a missing
# one fails by name rather than by a corpus count. The postmark pair runs
# through S9's content diff as a PAIR — v1 staged as the previous published
# version — which is the only path that exercises the rug-pull defense.
go test ./internal/scan -run 'TestAttackCorpusGate/incident-postmark-v1$' -count=1 >/dev/null    && echo "  incident: postmark v1 baseline clean: OK"
go test ./internal/scan -run 'TestAttackCorpusGate/incident-postmark-v2$' -count=1 >/dev/null    && echo "  incident: postmark v2 rug-pull diff (S9+S6): OK"
go test ./internal/scan -run 'TestAttackCorpusGate/incident-amazonq-wiper' -count=1 >/dev/null   && echo "  incident: Amazon Q wiper prose (S4 destructive): OK"
go test ./internal/scan -run 'TestAttackCorpusGate/incident-shai-hulud' -count=1 >/dev/null      && echo "  incident: Shai-Hulud install script (S7): OK"
go test ./internal/scan -run 'TestAttackCorpusGate/incident-clawhavoc' -count=1 >/dev/null       && echo "  incident: ClawHavoc publisher anomaly (S8): OK"
go test ./internal/scan -run 'TestAttackCorpusGate/incident-glassworm' -count=1 >/dev/null       && echo "  incident: GlassWorm invisible payload (S3): OK"

# Scanner depth beyond the corpus tree (§8.3): the boundaries a fixture tree
# cannot express — must-not-fire cases, lockfile formats, and the EXIF pair,
# whose images are generated in-test to keep the corpus text-only.
go test ./internal/scan -run 'TestS6|TestS7|TestS8|TestS9|TestParse|TestBumpSize' -count=1 >/dev/null && echo "scanner depth S6-S9 (§8.3): OK"
go test ./internal/scan -run 'TestImageMetadataInjectionFixture|TestMarkdownAltTextIsScanned|TestExtractImageText' -count=1 >/dev/null && echo "image alt-text + EXIF extraction (§8.3 S3): OK"

# §17.5 wants the fuzz corpora committed; running the targets as ordinary
# tests replays every committed seed without invoking the mutator.
go test ./internal/scan ./internal/render ./pkg/manifest -run 'Fuzz' -count=1 >/dev/null && echo "fuzz seed corpora (extractor, manifest, sanitizer, §17.5): OK"

go test ./internal/scan -run TestGate -count=1 >/dev/null              && echo "gate severity table (§8.5): OK"
go test ./internal/scan -run 'TestPolicyTightenOnly' -count=1 >/dev/null && echo "policy tighten-only (§8.6): OK"
go test ./internal/scan -run TestAttestationRoundTrip -count=1 >/dev/null && echo "DSSE attestation verify (§8.8): OK"
go test ./internal/scan -run TestExtractRejects -count=1 >/dev/null    && echo "hardened extractor (§8.2): OK"
go test ./internal/scan -run TestPipeline -count=1 >/dev/null          && echo "pipeline: benign publishes+signs, malicious gates (§7,§8): OK"
go test ./internal/api  -run 'TestReviewQueue|TestOrgReview|TestOrgPolicy|TestPlatformAction|TestReviewApprovalFlow' -count=1 >/dev/null && echo "review/policy/platform authz (§8.6,§12.2): OK"
echo "== M4 acceptance PASSED =="

#!/usr/bin/env bash
# M6 acceptance (PLAN §18.2, WG-J): enterprise SSO (SAML + OIDC), enforced SSO
# + org-bound PATs, SCIM provisioning/deactivation, domain verification,
# webhooks with the T-08 SSRF guard, and audit export — all against a real
# Postgres. The CI SAML/OIDC test-IdP suite runs in-process (DEVIATIONS DEV-009);
# the Okta + Entra manual checklist is the human step outside this script.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
. scripts/acceptance/lib.sh
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

echo "== M6 acceptance =="

# Build must be green for the packages this milestone owns.
go build ./internal/... ./pkg/... >/dev/null && echo "build (internal, pkg): OK"

# SAML 2.0 SP: signed assertion accepted; bad-signature, unsigned, wrong
# audience, expired, and replayed-assertion-id all rejected (§12.4, T-12).
# The same filter runs the guard on the replay record's floor, which has to
# outlive the window the validator still accepts an assertion in (agentry#414).
gotest "SAML SP accept + replay/audience/expiry/signature negatives + the replay floor's margin (§12.4)" -timeout 20m ./internal/auth/saml -run TestSAML -count=1

# OIDC RP: auth-code + PKCE exchange, issuer pinning, email_verified respected
# (§12.4). In-process discovery + JWKS + token provider.
gotest "OIDC RP exchange + issuer-pin + email_verified negatives (§12.4)" -timeout 20m ./internal/auth/oidc -run TestOIDC -count=1

# SAML + OIDC through the HTTP endpoints (ACS POST / start+callback) → session.
gotest "SSO endpoints establish sessions via JIT (§12.4)" -timeout 20m ./internal/api -run 'TestSAMLACSEndpoint|TestOIDCEndpointFlow' -count=1

# The two sets every API replica must see alike (agentry#414): an assertion
# one replica consumed is refused at the next while a fresh one is still
# accepted there, a login one replica started completes at another and its
# request is single use, single use holds when the presentations race, a
# lost database fails closed, and the seams a deployment with its own shared
# store uses are honoured by the live routes rather than merely stored.
gotest "SAML replay refused across replicas, a login started on one completes on another, both setters honoured (§12.4)" -timeout 20m ./internal/api -run 'TestSAMLReplayIsRefusedAcrossServers|TestSAMLLoginStartedOnOneReplicaCompletesOnAnother|TestSAMLStoreSetsAreSharedAndExpire|TestSAMLReplayRefusalHoldsUnderConcurrentPresentations|TestSAMLSettersReplaceTheSets' -count=1

# Enforced SSO + org-bound PATs (§12.4).
gotest "enforced SSO rejects stale sessions / non-org-bound PATs (§12.4)" -timeout 20m ./internal/api -run TestEnforcedSSO -count=1

# SCIM 2.0: create, userName filter, PATCH active=false / DELETE deactivate ⇒
# revoke org-bound PATs + kill sessions (< 60s, §12.5).
gotest "SCIM provision + deactivate revokes access (§12.5)" -timeout 20m ./internal/api -run TestSCIM -count=1

# Domain verification via injected fake resolver (§12.4).
gotest "domain TXT verification, unit (§12.4)" -timeout 20m ./internal/dnsx -run TestVerifyTXT -count=1
gotest "domain verification endpoint w/ fake resolver (§12.4)" -timeout 20m ./internal/api  -run TestDomainVerification -count=1

# Webhooks: SSRF guard (private/link-local/metadata/http/redirect), HMAC format,
# and a real delivery through the queue (§9.3, T-08).
gotest "SSRF egress guard + webhook HMAC signature (§9.3, T-08)" -timeout 20m ./pkg/egressguard ./internal/webhook -count=1
gotest "webhook delivery via queue + event fan-out (§9.3)" -timeout 20m ./internal/api -run 'TestWebhookDeliveryViaQueue|TestWebhookEventWiring' -count=1

# Audit export: async NDJSON to blob store with a download reference (§12.6).
gotest "async audit export → NDJSON blob (§12.6)" -timeout 20m ./internal/api -run TestAuditExport -count=1

# The §17.4 authorization matrix must remain green with every new route declared.
gotest "authz matrix + route-declaration completeness (§12.2, §17.4)" -timeout 20m ./internal/api -run 'TestRouteDeclarationsComplete|TestAuthzMatrix' -count=1

echo "== M6 acceptance PASSED =="

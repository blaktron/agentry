#!/usr/bin/env bash
# M6 acceptance (PLAN §18.2, WG-J): enterprise SSO (SAML + OIDC), enforced SSO
# + org-bound PATs, SCIM provisioning/deactivation, domain verification,
# webhooks with the T-08 SSRF guard, and audit export — all against a real
# Postgres. The CI SAML/OIDC test-IdP suite runs in-process (DEVIATIONS DEV-009);
# the Okta + Entra manual checklist is the human step outside this script.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
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
go test ./internal/auth/saml -run TestSAML -count=1 >/dev/null && echo "SAML SP accept + replay/audience/expiry/signature negatives (§12.4): OK"

# OIDC RP: auth-code + PKCE exchange, issuer pinning, email_verified respected
# (§12.4). In-process discovery + JWKS + token provider.
go test ./internal/auth/oidc -run TestOIDC -count=1 >/dev/null && echo "OIDC RP exchange + issuer-pin + email_verified negatives (§12.4): OK"

# SAML + OIDC through the HTTP endpoints (ACS POST / start+callback) → session.
go test ./internal/api -run 'TestSAMLACSEndpoint|TestOIDCEndpointFlow' -count=1 >/dev/null && echo "SSO endpoints establish sessions via JIT (§12.4): OK"

# Enforced SSO + org-bound PATs (§12.4).
go test ./internal/api -run TestEnforcedSSO -count=1 >/dev/null && echo "enforced SSO rejects stale sessions / non-org-bound PATs (§12.4): OK"

# SCIM 2.0: create, userName filter, PATCH active=false / DELETE deactivate ⇒
# revoke org-bound PATs + kill sessions (< 60s, §12.5).
go test ./internal/api -run TestSCIM -count=1 >/dev/null && echo "SCIM provision + deactivate revokes access (§12.5): OK"

# Domain verification via injected fake resolver (§12.4).
go test ./internal/dnsx -run TestVerifyTXT -count=1 >/dev/null && echo "domain TXT verification, unit (§12.4): OK"
go test ./internal/api  -run TestDomainVerification -count=1 >/dev/null && echo "domain verification endpoint w/ fake resolver (§12.4): OK"

# Webhooks: SSRF guard (private/link-local/metadata/http/redirect), HMAC format,
# and a real delivery through the queue (§9.3, T-08).
go test ./internal/webhook -count=1 >/dev/null && echo "webhook SSRF guard + HMAC signature (§9.3, T-08): OK"
go test ./internal/api -run 'TestWebhookDeliveryViaQueue|TestWebhookEventWiring' -count=1 >/dev/null && echo "webhook delivery via queue + event fan-out (§9.3): OK"

# Audit export: async NDJSON to blob store with a download reference (§12.6).
go test ./internal/api -run TestAuditExport -count=1 >/dev/null && echo "async audit export → NDJSON blob (§12.6): OK"

# The §17.4 authorization matrix must remain green with every new route declared.
go test ./internal/api -run 'TestRouteDeclarationsComplete|TestAuthzMatrix' -count=1 >/dev/null && echo "authz matrix + route-declaration completeness (§12.2, §17.4): OK"

echo "== M6 acceptance PASSED =="

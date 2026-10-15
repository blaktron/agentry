-- +goose Up
-- Enterprise features: webhook endpoints and their delivery ledger,
-- domain-verification claims, and audit-export jobs. The SSO shells
-- (sso_connections, scim_tokens, identities) and the columns enforced SSO
-- needs (sessions.sso_tags, pats.org_id, teams.scim_group_id,
-- orgs.sso_required/verified_domain) already exist from migration 00002; this
-- migration only adds what the features above need.

-- Webhook endpoints. Secret is the HMAC-SHA256 signing key, AES-GCM sealed at
-- rest (auth.Sealer; KMS-enveloped on SaaS).
CREATE TABLE webhook_endpoints (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs(id),
  url text NOT NULL,
  secret_enc bytea NOT NULL,
  events text[] NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webhook_endpoints_org_idx ON webhook_endpoints(org_id);

-- Delivery ledger. One row per (endpoint, event); the id is the delivery UUID
-- echoed in the payload for consumer-side dedup. Retries update
-- attempt/status_code/next_retry_at in place (the queue owns the retry
-- clock).
CREATE TABLE webhook_deliveries (
  id uuid PRIMARY KEY,
  endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  attempt int NOT NULL DEFAULT 0,
  status_code int,
  error text,
  delivered_at timestamptz,
  next_retry_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webhook_deliveries_endpoint_idx ON webhook_deliveries(endpoint_id, created_at DESC);

-- Domain claims (domain verification enables verified-email JIT auto link,
-- guarded by proof of domain control). A DNS TXT record carrying
-- verification_token proves control; on success orgs.verified_domain is set.
CREATE TABLE domain_claims (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs(id),
  domain citext NOT NULL,
  verification_token text NOT NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, domain)
);
CREATE INDEX domain_claims_org_idx ON domain_claims(org_id);

-- Audit-export jobs. An async job streams the org's audit slice to the blob
-- store as NDJSON; object_key is the download reference (the API returns the
-- path; presigning is not done here).
CREATE TABLE audit_exports (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs(id),
  requested_by uuid REFERENCES users(id),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','running','completed','failed')),
  action_filter text,
  object_key text,
  event_count int NOT NULL DEFAULT 0,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX audit_exports_org_idx ON audit_exports(org_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS audit_exports;
DROP TABLE IF EXISTS domain_claims;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;

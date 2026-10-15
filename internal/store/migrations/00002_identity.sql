-- +goose Up
-- Identity core: global handle namespace, users, orgs, memberships, teams,
-- PATs, sessions, SSO shells, and the append-only audit log. UUIDs are UUIDv7
-- generated app-side.

CREATE TABLE handles (
  id uuid PRIMARY KEY,
  handle citext UNIQUE NOT NULL CHECK (handle ~ '^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$'),
  kind text NOT NULL CHECK (kind IN ('user','org')),
  reserved boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY REFERENCES handles(id),
  email citext UNIQUE NOT NULL,
  email_verified_at timestamptz,
  display_name text NOT NULL DEFAULT '',
  password_hash text,
  totp_secret_enc bytea,
  totp_enabled boolean NOT NULL DEFAULT false,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended','deleted')),
  deleted_tombstone jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE orgs (
  id uuid PRIMARY KEY REFERENCES handles(id),
  display_name text NOT NULL,
  sso_required boolean NOT NULL DEFAULT false,
  verified_domain citext,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- SSO connection shells (referenced by identities); the logic is in
-- application code.
CREATE TABLE sso_connections (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs(id),
  kind text NOT NULL CHECK (kind IN ('saml','oidc')),
  config jsonb NOT NULL DEFAULT '{}',
  enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, kind)
);

CREATE TABLE scim_tokens (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs(id),
  token_sha256 bytea UNIQUE NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identities (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id),
  provider_kind text NOT NULL CHECK (provider_kind IN ('oidc','saml','social')),
  sso_connection_id uuid REFERENCES sso_connections(id),
  subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (sso_connection_id, subject)
);
CREATE INDEX identities_user_idx ON identities(user_id);

CREATE TABLE memberships (
  org_id uuid NOT NULL REFERENCES orgs(id),
  user_id uuid NOT NULL REFERENCES users(id),
  role text NOT NULL CHECK (role IN ('owner','admin','security_reviewer','member')),
  via_scim boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships(user_id);

CREATE TABLE teams (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs(id),
  slug citext NOT NULL,
  scim_group_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, slug)
);

CREATE TABLE team_members (
  team_id uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (team_id, user_id)
);

CREATE TABLE pats (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id),
  name text NOT NULL,
  token_sha256 bytea UNIQUE NOT NULL,
  token_prefix text NOT NULL,
  scopes text[] NOT NULL,
  org_id uuid REFERENCES orgs(id),
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX pats_user_idx ON pats(user_id);
CREATE INDEX pats_prefix_idx ON pats(token_prefix);

-- Server-side sessions. A hosted deployment may front them with Redis;
-- Postgres is the durable store and the self-host default.
CREATE TABLE sessions (
  id uuid PRIMARY KEY,
  token_sha256 bytea UNIQUE NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id),
  csrf_token text NOT NULL,
  sso_tags jsonb NOT NULL DEFAULT '{}',        -- {"<org_id>": "<refreshed_at>"}
  ip inet,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE email_verifications (
  token_sha256 bytea PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only audit log, monthly range partitions.
CREATE TABLE audit_events (
  id uuid NOT NULL,
  occurred_at timestamptz NOT NULL,
  actor_id uuid,
  actor_kind text NOT NULL CHECK (actor_kind IN ('user','pat','scim','system')),
  org_id uuid,
  action text NOT NULL,
  target_kind text,
  target_id uuid,
  ip inet,
  user_agent text,
  detail jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);

-- Safety net for writes outside materialized monthly partitions.
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;
CREATE INDEX audit_events_org_idx ON audit_events (org_id, occurred_at DESC);
CREATE INDEX audit_events_action_idx ON audit_events (action, occurred_at DESC);

-- +goose StatementBegin
-- Creates the monthly partition covering `d` if missing. The audit writer
-- calls this on month rollover; migrations call it for the current month.
CREATE FUNCTION audit_ensure_partition(d date) RETURNS void AS $$
DECLARE
  part_start date := date_trunc('month', d)::date;
  part_end   date := (date_trunc('month', d) + interval '1 month')::date;
  part_name  text := 'audit_events_' || to_char(part_start, 'YYYYMM');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
    EXECUTE format(
      'CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
      part_name, part_start, part_end);
  END IF;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

SELECT audit_ensure_partition(now()::date);
SELECT audit_ensure_partition((now() + interval '1 month')::date);

-- +goose StatementBegin
-- Audit rows are immutable regardless of connection role (role-level REVOKEs
-- additionally apply on hosted deployments where roles are split).
CREATE FUNCTION audit_events_block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_events_no_update
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_block_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
DROP FUNCTION IF EXISTS audit_events_block_mutation();
DROP FUNCTION IF EXISTS audit_ensure_partition(date);
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS email_verifications;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS pats;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS identities;
DROP TABLE IF EXISTS scim_tokens;
DROP TABLE IF EXISTS sso_connections;
DROP TABLE IF EXISTS orgs;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS handles;

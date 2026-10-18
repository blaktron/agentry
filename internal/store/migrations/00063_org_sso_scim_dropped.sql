-- +goose Up
-- The server has no organization single sign-on (SAML or OpenID Connect
-- connections) and no SCIM endpoint of its own: an organization's identity
-- provider reaches it through an extension, which provisions and
-- deprovisions members through the members seam. So the connections, the
-- SCIM tokens, the SAML replay and request sets and the sessions' SAML
-- logout columns go.
--
-- An identity linked through an organization's connection could only ever
-- be used by that connection's sign-in, which the server does not have,
-- and with the connection gone nothing could find it to delete it when the
-- organization is decommissioned; such links are deleted. Every identity a
-- sign-in still uses (sso_connection_id NULL) is untouched, and the column
-- stays for the readers that select on it.
DELETE FROM identities WHERE sso_connection_id IS NOT NULL;
ALTER TABLE identities DROP CONSTRAINT identities_sso_connection_id_fkey;
ALTER TABLE sessions
  DROP COLUMN saml_session_index,
  DROP COLUMN saml_name_id,
  DROP COLUMN sso_connection_id;
ALTER TABLE teams DROP COLUMN scim_group_id;
DROP TABLE scim_tokens;
DROP TABLE sso_connections;
DROP TABLE saml_requests;
DROP TABLE saml_consumed_assertions;

-- +goose Down
CREATE TABLE saml_consumed_assertions (
  id         text PRIMARY KEY CHECK (length(id) <= 1024),
  expires_at timestamptz NOT NULL
);
CREATE INDEX saml_consumed_assertions_expires_at_idx ON saml_consumed_assertions (expires_at);
CREATE TABLE saml_requests (
  id         text PRIMARY KEY CHECK (length(id) <= 1024),
  expires_at timestamptz NOT NULL
);
CREATE INDEX saml_requests_expires_at_idx ON saml_requests (expires_at);
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
ALTER TABLE teams ADD COLUMN scim_group_id text;
ALTER TABLE sessions
  ADD COLUMN sso_connection_id uuid REFERENCES sso_connections(id),
  ADD COLUMN saml_name_id text,
  ADD COLUMN saml_session_index text;
CREATE INDEX sessions_saml_slo_idx ON sessions (sso_connection_id, saml_name_id)
  WHERE saml_name_id IS NOT NULL;
ALTER TABLE identities ADD CONSTRAINT identities_sso_connection_id_fkey
  FOREIGN KEY (sso_connection_id) REFERENCES sso_connections(id);

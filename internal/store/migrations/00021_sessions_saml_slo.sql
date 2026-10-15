-- +goose Up
-- SAML Single Logout: a session established through a SAML connection
-- remembers the connection, the asserted NameID and the IdP's SessionIndex,
-- so an IdP-initiated LogoutRequest can revoke exactly the sessions it names,
-- and an SP-initiated logout can tell the IdP whom it is logging out.
ALTER TABLE sessions
  ADD COLUMN sso_connection_id uuid REFERENCES sso_connections(id),
  ADD COLUMN saml_name_id text,
  ADD COLUMN saml_session_index text;
CREATE INDEX sessions_saml_slo_idx ON sessions (sso_connection_id, saml_name_id)
  WHERE saml_name_id IS NOT NULL;

-- +goose Down
DROP INDEX sessions_saml_slo_idx;
ALTER TABLE sessions
  DROP COLUMN saml_session_index,
  DROP COLUMN saml_name_id,
  DROP COLUMN sso_connection_id;

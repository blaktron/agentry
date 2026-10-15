-- +goose Up
-- Membership is a state, not only a role. A person the IdP provisioned, or
-- the domain folded in, is `pending`: they hold no seat and the organization
-- confers nothing on them until an admin approves them. Every membership that
-- exists today was granted by an admin, which is what `active` means, so the
-- default backfills them correctly.
ALTER TABLE memberships
  ADD COLUMN state text NOT NULL DEFAULT 'active' CHECK (state IN ('pending','active'));
CREATE INDEX memberships_org_state_idx ON memberships (org_id, state);

-- An invitation is a credential, not a record: the token is stored only as
-- its SHA-256, shown once at creation, single-use, bound to the invited
-- address and expiring in seven days. It reserves its seat from the moment it
-- is sent, so the seat wall is met by the admin who invites rather than by
-- the person who accepts.
CREATE TABLE org_invitations (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES orgs(id),
  email        citext NOT NULL,
  role         text NOT NULL CHECK (role IN ('admin','security_reviewer','member')),
  token_sha256 bytea NOT NULL UNIQUE,
  invited_by   uuid REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  accepted_at  timestamptz,
  accepted_by  uuid REFERENCES users(id)
);
CREATE INDEX org_invitations_org_idx ON org_invitations (org_id);
-- At most one unaccepted invitation per address per organization: a second
-- one would reserve a second seat for the same person. An expired invitation
-- is still unaccepted, so re-inviting deletes it first (CreateInvitation's
-- caller does, audited) rather than leaving a row nobody can supersede.
CREATE UNIQUE INDEX org_invitations_open_idx
  ON org_invitations (org_id, email) WHERE accepted_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS org_invitations;
DROP INDEX IF EXISTS memberships_org_state_idx;
ALTER TABLE memberships DROP COLUMN IF EXISTS state;

-- +goose Up
-- The owner role retires; admins hold what owners held (agentry#360, plan
-- organization-subscriptions D14): "there should be no owner role, merely
-- an admin role which can be passed to other users". Every owner becomes
-- an admin; the CHECK constraint stops accepting the old value, so no row
-- can carry it again. security_reviewer stays a valid value — the role
-- survives inside a first-party organization (D20), and whether it may be
-- assigned is the API's rule, not the schema's.
UPDATE memberships SET role = 'admin', updated_at = now() WHERE role = 'owner';
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships
  ADD CONSTRAINT memberships_role_check
  CHECK (role IN ('admin','security_reviewer','member'));

-- Who created the organization, and whether it has been activated. On the
-- hosted product an organization is a paid thing that starts out awaiting
-- payment (a standing the billing extension owns); the core records only
-- what it needs to refuse a second one per account: an org created where an
-- admission extension runs has activated_at NULL until that extension
-- activates it. A registry with no extension activates at creation. Every
-- organization that exists today is in use, so it is activated as of its
-- creation; its creator was never recorded and stays unknown.
ALTER TABLE orgs
  ADD COLUMN created_by uuid REFERENCES users(id),
  ADD COLUMN activated_at timestamptz;
UPDATE orgs SET activated_at = created_at;
CREATE INDEX orgs_pending_by_creator_idx ON orgs (created_by) WHERE activated_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS orgs_pending_by_creator_idx;
ALTER TABLE orgs DROP COLUMN IF EXISTS activated_at, DROP COLUMN IF EXISTS created_by;
-- The former owners cannot be told from the other admins; they stay admins.
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships
  ADD CONSTRAINT memberships_role_check
  CHECK (role IN ('owner','admin','security_reviewer','member'));

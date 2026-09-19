-- +goose Up
-- The fold-in (agentry#364, plan organization-subscriptions §4 "Fold-in",
-- §5.5; D22, D25): an existing account whose verified address is at an
-- organization's domain becomes a pending member at its next directory
-- sign-in, or when a sweep runs over the accounts already known at the
-- domain. Two facts the membership row did not carry, and one it never
-- could:

-- Which door a pending membership came through. via_scim was the only
-- provisioning door until now; the domain is the second, and the org
-- console says which is which (plan §7 M9).
ALTER TABLE memberships ADD COLUMN via_domain boolean NOT NULL DEFAULT false;

-- When the organization's admins were mailed about this pending member.
-- The admins' mail is a daily batch, not a mail per fold-in: the digest
-- reports every pending member it has not reported yet and marks them
-- here, so a person is named to the admins once. NULL on an active row
-- means nothing.
ALTER TABLE memberships ADD COLUMN admins_notified_at timestamptz;
CREATE INDEX memberships_pending_unnotified_idx
  ON memberships (org_id) WHERE state = 'pending' AND admins_notified_at IS NULL;

-- A decline is remembered (D25): declining a pending member deletes the
-- membership row, so the memory of it lives here, and the fold-in does not
-- fire again for that person at that organization. An admin's invitation
-- supersedes it — the row goes when the membership is activated — and an
-- erased organization or account takes its rows with it.
CREATE TABLE fold_in_declines (
  org_id      uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  declined_by uuid REFERENCES users(id) ON DELETE SET NULL,
  declined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

-- +goose Down
DROP TABLE IF EXISTS fold_in_declines;
DROP INDEX IF EXISTS memberships_pending_unnotified_idx;
ALTER TABLE memberships DROP COLUMN IF EXISTS admins_notified_at;
ALTER TABLE memberships DROP COLUMN IF EXISTS via_domain;

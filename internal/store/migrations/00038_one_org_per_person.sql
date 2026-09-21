-- +goose Up
-- One organization per person (D26) at the database. Every door counted
-- the person's active memberships in application code, under the TARGET
-- organization's row lock — which does not serialise against a different
-- organization — so a person holding invitations to two organizations,
-- accepted at the same moment, ended up active in both, with two seats
-- debited across two tenants (security review 2026-09-20 §5.8.3;
-- agentry#412). The doors now lock the person's row first; this index is
-- the wall behind them, as orgs_pipeline_skip_private is behind the flag.
CREATE UNIQUE INDEX memberships_one_active_per_user
  ON memberships (user_id) WHERE state = 'active';

-- +goose Down
DROP INDEX IF EXISTS memberships_one_active_per_user;

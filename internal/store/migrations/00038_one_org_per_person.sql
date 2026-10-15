-- +goose Up
-- One organization per person, at the database. Every door counted the
-- person's active memberships in application code, under the TARGET
-- organization's row lock — which does not serialise against a different
-- organization — so a person holding invitations to two organizations,
-- accepted at the same moment, ended up active in both, with two seats
-- debited across two tenants. The doors lock the person's row first; this
-- index is the wall behind them, as agents_pipeline_skip_private is behind
-- the flag. It refuses to be built over a database that already holds a
-- person active in two organizations: that is a data question for the
-- operator to settle (which membership stands), not one for a migration to
-- guess at, so the migration stops there and the server does not start until
-- it is settled.
CREATE UNIQUE INDEX memberships_one_active_per_user
  ON memberships (user_id) WHERE state = 'active';

-- +goose Down
DROP INDEX IF EXISTS memberships_one_active_per_user;

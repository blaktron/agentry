-- +goose Up
-- Account installs: a signed-in person's record, on the registry, of a
-- QuickAgent release they accepted for their account — the version, the
-- declared capabilities they consented to as the release declared them, and
-- which of the unsigned and unscanned consents the release needed. One record
-- per QuickAgent per account, as the desktop keeps one runner record per
-- QuickAgent. It is an acceptance, not a laying-down: nothing is written on
-- any machine, and it bumps no download counter. The ref is stored as the
-- person knew it, so a record whose QuickAgent they can no longer read is
-- listed and removed by that name and never by where the QuickAgent went. The
-- version row is referenced without a cascade because version rows are never
-- deleted (00004); the person's and the agent's rows cascade.
CREATE TABLE account_installs (
  user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_id           uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  version_id         uuid NOT NULL REFERENCES agent_versions(id),
  ref_namespace      text NOT NULL,
  ref_name           text NOT NULL,
  capabilities       jsonb NOT NULL DEFAULT '{}',
  accepted_unsigned  boolean NOT NULL DEFAULT false,
  accepted_unscanned boolean NOT NULL DEFAULT false,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, agent_id)
);
-- An organization's erasure removes the records of its agents, as it
-- does their stars.
CREATE INDEX account_installs_agent_idx ON account_installs(agent_id);

-- +goose Down
DROP TABLE IF EXISTS account_installs;

-- +goose Up
-- A third run mode, persistent: a conversation the runner keeps between
-- sessions. The registry stores it as it stores the other two; whether a
-- release that declares it runs is the runner's decision.
ALTER TABLE agents DROP CONSTRAINT agents_modes_valid;
ALTER TABLE agents ADD CONSTRAINT agents_modes_valid
  CHECK (modes <@ ARRAY['autonomous','interactive','persistent']::text[]);

-- +goose Down
-- Refused while any agent still declares persistent: dropping the mode from
-- a release's row would change what its readers are told it supports.
ALTER TABLE agents DROP CONSTRAINT agents_modes_valid;
ALTER TABLE agents ADD CONSTRAINT agents_modes_valid
  CHECK (modes <@ ARRAY['autonomous','interactive']::text[]);

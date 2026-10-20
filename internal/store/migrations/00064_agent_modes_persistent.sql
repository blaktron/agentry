-- +goose Up
-- A third run mode, persistent: a conversation the runner keeps between
-- sessions. The registry stores it as it stores the other two; whether a
-- release that declares it runs is the runner's decision.
ALTER TABLE agents DROP CONSTRAINT agents_modes_valid;
ALTER TABLE agents ADD CONSTRAINT agents_modes_valid
  CHECK (modes <@ ARRAY['autonomous','interactive','persistent']::text[]);

-- +goose Down
-- Fails while any agent row still lists persistent, rather than dropping the
-- mode from it: that would change what the row's readers are told it supports.
ALTER TABLE agents DROP CONSTRAINT agents_modes_valid;
ALTER TABLE agents ADD CONSTRAINT agents_modes_valid
  CHECK (modes <@ ARRAY['autonomous','interactive']::text[]);

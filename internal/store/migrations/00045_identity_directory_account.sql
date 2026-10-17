-- +goose Up
-- The directory's own id for the account a sign-in is linked to, where one
-- was recorded: a directory reads the account by it instead of narrowing by
-- an address it does not keep unique. NULL where none was recorded.
ALTER TABLE identities ADD COLUMN directory_account_id bigint
  CHECK (directory_account_id IS NULL OR directory_account_id > 0);

-- +goose Down
ALTER TABLE identities DROP COLUMN directory_account_id;

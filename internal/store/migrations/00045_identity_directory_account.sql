-- +goose Up
-- The directory's own id for the account a directory sign-in is linked to
-- (agentry#727, DEV-170 addendum): the directory's `agentry` scope sends it
-- in the ID token, and the registry records it on the `authentik:` identity
-- at every sign-in. Every directory lookup the registry makes (the settings
-- page's sign-in facts and authenticators, account erasure) reads the
-- account by it instead of narrowing by an address the directory does not
-- keep unique. NULL for an identity that has not signed in since, and for
-- every identity of another provider.
ALTER TABLE identities ADD COLUMN directory_account_id bigint
  CHECK (directory_account_id IS NULL OR directory_account_id > 0);

-- +goose Down
ALTER TABLE identities DROP COLUMN directory_account_id;

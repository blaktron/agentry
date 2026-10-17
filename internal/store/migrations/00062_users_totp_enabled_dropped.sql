-- +goose Up
-- The server keeps no second factor of its own, so the flag that said one
-- was enrolled has nothing to say. A sign-in's second factor is recorded in
-- idp_mfa_at, from the OpenID provider's claims.
ALTER TABLE users DROP COLUMN totp_enabled;

-- +goose Down
ALTER TABLE users ADD COLUMN totp_enabled boolean NOT NULL DEFAULT false;

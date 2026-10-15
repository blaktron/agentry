-- +goose Up
-- When the directory service asserted a second factor at sign-in (an `amr`
-- claim naming an MFA method, RFC 8176), the registry records it here so the
-- "2FA before public publish" gate has evidence to accept instead of trusting
-- the directory blindly. A timestamp, not a boolean: "when did we last see
-- MFA for this account".
ALTER TABLE users ADD COLUMN idp_mfa_at timestamptz;

-- +goose Down
ALTER TABLE users DROP COLUMN idp_mfa_at;

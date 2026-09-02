-- +goose Up
-- The S8 IP-cluster signal (§8.3 "mass-upload anomalies across an account
-- or IP cluster"; agentry#27, DEV-026.1). Not an address: a keyed hash
-- HMAC(month key, address) with a "YYYY-MM:" prefix, where the month key is
-- derived from the deployment's sealing key and the calendar month. Two
-- submissions from one address in one month share a value; across months
-- (or deployments) they do not, and the address is not recoverable from
-- the value. Set once at insert; the immutability trigger leaves it alone.
ALTER TABLE agent_versions ADD COLUMN submitter_ip_hash text;
CREATE INDEX agent_versions_ip_hash_idx ON agent_versions (submitter_ip_hash, created_at);

-- +goose Down
DROP INDEX agent_versions_ip_hash_idx;
ALTER TABLE agent_versions DROP COLUMN submitter_ip_hash;

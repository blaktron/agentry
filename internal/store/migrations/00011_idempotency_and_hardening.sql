-- +goose Up
-- Three additive changes (never edit an applied migration — §4.3):
--   1. idempotency_keys: the §9.1 "mutating POSTs accept Idempotency-Key"
--      replay store.
--   2. A stricter agent_versions immutability trigger: the 00004 version let a
--      row be rolled BACK to 'submitted' and then rewritten, which defeats the
--      whole guarantee.
--   3. A TRUNCATE guard on audit_events: the 00002 trigger covers UPDATE and
--      DELETE, but TRUNCATE fires neither, so the append-only log could be
--      emptied in one statement.

-- ============================ Idempotency keys ============================

-- One row per (user, endpoint, key). request_hash pins the key to the body it
-- was first used with, so a client reusing a key for a DIFFERENT request gets
-- a conflict rather than the wrong cached answer. The stored response is
-- replayed verbatim on a retry (§9.1).
CREATE TABLE idempotency_keys (
  key text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint text NOT NULL,
  request_hash text NOT NULL,
  response_status int,
  response_body jsonb,
  resource_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (user_id, endpoint, key)
);
CREATE INDEX idempotency_keys_expiry_idx ON idempotency_keys(expires_at);

-- ============================ Version immutability ============================

-- +goose StatementBegin
-- Replaces the 00004 definition. Same field list, plus the missing guard: a
-- row past 'submitted' may never go BACK to 'submitted'. Without it the
-- sequence (UPDATE … SET status='submitted'; UPDATE … SET manifest=…) rewrote
-- the manifest and archive digest of a published version, because the second
-- statement saw OLD.status = 'submitted' and skipped every check.
CREATE OR REPLACE FUNCTION agent_versions_enforce_immutability() RETURNS trigger AS $$
BEGIN
  IF OLD.status <> 'submitted' THEN
    IF NEW.status = 'submitted' THEN
      RAISE EXCEPTION 'agent_versions status cannot regress to submitted (was %)', OLD.status;
    END IF;
    IF NEW.agent_id      IS DISTINCT FROM OLD.agent_id
    OR NEW.version       IS DISTINCT FROM OLD.version
    OR NEW.commit_sha    IS DISTINCT FROM OLD.commit_sha
    OR NEW.manifest      IS DISTINCT FROM OLD.manifest
    OR NEW.capabilities  IS DISTINCT FROM OLD.capabilities
    OR NEW.archive_digest IS DISTINCT FROM OLD.archive_digest
    OR NEW.archive_key   IS DISTINCT FROM OLD.archive_key
    OR NEW.archive_size  IS DISTINCT FROM OLD.archive_size
    OR NEW.channel       IS DISTINCT FROM OLD.channel
    OR NEW.submitted_by  IS DISTINCT FROM OLD.submitted_by
    OR NEW.source        IS DISTINCT FROM OLD.source
    OR NEW.created_at    IS DISTINCT FROM OLD.created_at
    THEN
      RAISE EXCEPTION 'agent_versions row is immutable past submitted (only state-machine fields may change)';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================ Audit TRUNCATE guard ============================

-- +goose StatementBegin
CREATE FUNCTION audit_events_block_truncate() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only (TRUNCATE refused)';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Truncating the partitioned parent cascades to every partition, so the parent
-- trigger is the main gate; truncating a partition DIRECTLY bypasses it, hence
-- the per-partition triggers below and in audit_ensure_partition.
CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_block_truncate();

-- +goose StatementBegin
DO $$
DECLARE part regclass;
BEGIN
  FOR part IN
    SELECT inhrelid::regclass FROM pg_inherits
    WHERE inhparent = 'audit_events'::regclass
  LOOP
    EXECUTE format(
      'CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON %s '
      'FOR EACH STATEMENT EXECUTE FUNCTION audit_events_block_truncate()', part);
  END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Same contract as 00002's version, with the TRUNCATE guard attached to each
-- partition it creates (the writer calls this on month rollover).
CREATE OR REPLACE FUNCTION audit_ensure_partition(d date) RETURNS void AS $$
DECLARE
  part_start date := date_trunc('month', d)::date;
  part_end   date := (date_trunc('month', d) + interval '1 month')::date;
  part_name  text := 'audit_events_' || to_char(part_start, 'YYYYMM');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
    EXECUTE format(
      'CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
      part_name, part_start, part_end);
    EXECUTE format(
      'CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON %I '
      'FOR EACH STATEMENT EXECUTE FUNCTION audit_events_block_truncate()', part_name);
  END IF;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================ Audit retention ============================

-- +goose StatementBegin
-- §4.3: 400 days hot, then archive (the NDJSON stream already has the data,
-- §12.6). Rows cannot be DELETEd — the append-only trigger refuses — so
-- retention drops whole monthly partitions, which is also O(1). The name
-- pattern guard keeps audit_events_default (the safety-net partition, which
-- has no bounded range) out of scope.
CREATE FUNCTION audit_prune_partitions(cutoff date) RETURNS int AS $$
DECLARE
  part   record;
  n      int := 0;
  keep   date := date_trunc('month', cutoff)::date;
BEGIN
  FOR part IN
    SELECT c.relname AS name
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    WHERE i.inhparent = 'audit_events'::regclass
      AND c.relname ~ '^audit_events_[0-9]{6}$'
  LOOP
    IF (to_date(right(part.name, 6), 'YYYYMM') + interval '1 month')::date <= keep THEN
      EXECUTE format('DROP TABLE %I', part.name);
      n := n + 1;
    END IF;
  END LOOP;
  RETURN n;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================ Supporting indexes ============================

-- GET /agents/{ns}/{name}/activity reads the audit log by target (§9.2).
CREATE INDEX audit_events_target_idx ON audit_events (target_kind, target_id, occurred_at DESC);

-- Social identities (§12.1) carry no sso_connection_id, so the
-- UNIQUE (sso_connection_id, subject) constraint from 00002 does not
-- constrain them (NULLs are distinct). One subject, one identity.
CREATE UNIQUE INDEX identities_social_subject_idx
  ON identities (subject) WHERE sso_connection_id IS NULL;

-- +goose Down
DROP INDEX IF EXISTS identities_social_subject_idx;
DROP INDEX IF EXISTS audit_events_target_idx;
DROP FUNCTION IF EXISTS audit_prune_partitions(date);
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
DROP FUNCTION IF EXISTS audit_events_block_truncate() CASCADE;
DROP TABLE IF EXISTS idempotency_keys;

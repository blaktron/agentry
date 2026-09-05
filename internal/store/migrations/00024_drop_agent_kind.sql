-- +goose Up
-- The v1 kind column goes: the API speaks modes from 0.3.0 (DEV-088,
-- agentry#145) and nothing reads kind any more. Modes were backfilled from
-- it in 00023, so no information a client can ask for is lost.
ALTER TABLE agents DROP COLUMN kind;

-- +goose Down
-- Lossy by construction: the value is re-derived from modes — every
-- instruction package reads as prompt-agent (the kind that never needed
-- an entrypoint), and a blocked row with no modes reads as the withdrawn
-- mcp-server kind it must have been.
ALTER TABLE agents ADD COLUMN kind text NOT NULL DEFAULT 'prompt-agent'
  CHECK (kind IN ('skill','prompt-agent','mcp-server'));
UPDATE agents SET kind = 'mcp-server' WHERE cardinality(modes) = 0 AND quarantine_state = 'blocked';

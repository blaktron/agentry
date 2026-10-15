-- +goose Up
-- An erased organization keeps nothing that named its founder either: one
-- created awaiting activation and then erased still carried created_by with
-- activated_at NULL, so the pending-organization rule refused its founder a
-- new organization, naming the retired handle. The erasure clears created_by;
-- this clears it for any organization erased before.
UPDATE orgs SET created_by = NULL WHERE state = 'decommissioned' AND created_by IS NOT NULL;

-- +goose Down
-- The founder of an erased organization is not recoverable; nothing to do.
SELECT 1;

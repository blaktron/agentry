-- +goose Up
-- An erased organization keeps nothing that named its founder either
-- (agentry#363, found on dev): one created awaiting activation and then
-- erased still carried created_by with activated_at NULL, so the pending
-- rule of agentry#360 refused its founder a new organization, naming the
-- retired handle. The erasure clears created_by from now on; this clears
-- it for any organization erased before.
UPDATE orgs SET created_by = NULL WHERE state = 'decommissioned' AND created_by IS NOT NULL;

-- +goose Down
-- The founder of an erased organization is not recoverable; nothing to do.
SELECT 1;

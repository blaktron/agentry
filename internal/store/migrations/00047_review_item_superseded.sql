-- +goose Up
-- A review item the gate itself takes back: when a new ruleset is registered,
-- every version waiting in needs_review is judged again under it, and one
-- that now passes is published by the gate. Its item leaves the queue as
-- `superseded`, never as `approved`: no person decided on it, and an approved
-- item is what a rescan reads as a person's decision on a finding. decided_by
-- stays NULL; decided_at and the rationale name the ruleset.
ALTER TABLE review_items DROP CONSTRAINT review_items_state_check;
ALTER TABLE review_items ADD CONSTRAINT review_items_state_check
  CHECK (state IN ('pending','approved','rejected','superseded'));

-- +goose Down
-- A superseded item becomes rejected, not approved, so that no rescan reads
-- it as a person's approval. Its version keeps whatever status it has.
UPDATE review_items SET state = 'rejected' WHERE state = 'superseded';
ALTER TABLE review_items DROP CONSTRAINT review_items_state_check;
ALTER TABLE review_items ADD CONSTRAINT review_items_state_check
  CHECK (state IN ('pending','approved','rejected'));

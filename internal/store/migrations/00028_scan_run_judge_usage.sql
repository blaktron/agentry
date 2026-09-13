-- +goose Up
-- The judge's token use per scan run (plan subscription-tiers §10): what a
-- review costs, as the provider reported it. NULL is "the provider reported
-- none" (the static and classifier judges, an endpoint without a usage
-- block) and is distinct from zero. Recorded on the run, never in the S10
-- report, whose digest is the signed subject and must not vary between two
-- runs of the same bytes.
ALTER TABLE scan_runs
  ADD COLUMN judge_prompt_tokens     integer,
  ADD COLUMN judge_completion_tokens integer;

-- +goose Down
ALTER TABLE scan_runs
  DROP COLUMN judge_prompt_tokens,
  DROP COLUMN judge_completion_tokens;

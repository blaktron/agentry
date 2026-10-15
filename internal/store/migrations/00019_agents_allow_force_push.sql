-- +goose Up
-- Per-agent setting: force-push to the default branch is denied unless the
-- maintainers opt in. Off by default (the tag→submit flow and the release
-- history assume a linear default branch), and shown/mutable only to callers
-- with maintain.
ALTER TABLE agents ADD COLUMN allow_force_push boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE agents DROP COLUMN allow_force_push;

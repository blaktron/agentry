-- +goose Up
-- A built-in agent: one of the packages the CLI embeds and runs as part of
-- the application, published in the registry for reading. The directory
-- labels it Built-in in place of its run mode. Only platform staff set it,
-- and only on an agent of a first-party namespace; the API decides both,
-- since neither can be said in a CHECK. Nothing else reads it: no gate, scan,
-- install or run path changes on it.
ALTER TABLE agents ADD COLUMN builtin boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE agents DROP COLUMN builtin;

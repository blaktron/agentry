# Migrations

Goose migrations for the core schema, embedded into the binary by
`store.go` and applied by `store.Migrate`. Files are named
`NNNNN_description.sql` and applied in numeric order.

The sequence runs 00001 to 00011, then continues at 00013: number 00012
was never issued. Goose tolerates gaps, and renumbering an applied
migration would break every existing `goose_db_version` table. Nothing
was deleted; the schema is complete as the files stand.

Goose loads only `*.sql` files from this directory; this file is inert.

## The `approved` status

`00004_versions.sql` lists `approved` in the `agent_versions.status`
CHECK constraint. The value is reserved and never written: review
publishes directly (`needs_review` to `published`), so the invariant "no
path to published skips the gate" is a property of one edge. Narrowing an
applied CHECK constraint is a migration for no behavioural gain, so the
value stays. The same note sits on `registry.StatusApproved` and the
OpenAPI `VersionStatus` description.

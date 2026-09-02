# Migration numbering

The sequence runs 00001…00011, then **00013** — number 00012 was never
issued (a numbering slip during authoring, noticed after 00013 had been
applied to live databases; goose tolerates gaps and renumbering an applied
migration would break every existing `goose_db_version` table). Nothing was
deleted: the schema is complete as the files stand. Recorded so nobody
burns an afternoon hunting for a dropped migration (workspace ANALYSIS.md
M3, in blaktron/agentry-notes).

Goose only loads `*.sql` from this directory; this file is inert.

# The `approved` status

`00004_versions.sql` lists `approved` in the `agent_versions.status` CHECK
constraint. It is **reserved and never written** (DEV-046): review
publishes directly (`needs_review → published`), so the invariant "no path
to published skips the gate" is a property of one edge. Narrowing an
applied CHECK constraint is a migration for no behavioural gain, so the
value stays; the same note sits on `registry.StatusApproved` and the
OpenAPI `VersionStatus` description.

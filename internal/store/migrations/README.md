# Migration numbering

The sequence runs 00001…00011, then **00013** — number 00012 was never
issued (a numbering slip during authoring, noticed after 00013 had been
applied to live databases; goose tolerates gaps and renumbering an applied
migration would break every existing `goose_db_version` table). Nothing was
deleted: the schema is complete as the files stand. Recorded so nobody
burns an afternoon hunting for a dropped migration (workspace ANALYSIS.md
M3, in blaktron/agentry-notes).

Goose only loads `*.sql` from this directory; this file is inert.

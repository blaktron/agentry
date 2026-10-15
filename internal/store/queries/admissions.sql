-- name: RecordAdmittedStore :exec
-- An admission ticket whose operation is being stored, in the storing
-- transaction. A ticket is recorded once; a second store under the same
-- ticket keeps the first row.
INSERT INTO admitted_stores (ticket, kind) VALUES ($1, $2)
ON CONFLICT (ticket) DO NOTHING;


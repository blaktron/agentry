-- Git hosting bookkeeping. Owned by internal/gitsrv.

-- name: TouchRepoOnPush :exec
-- Records that a push landed when its size could not be measured:
-- last_push_at advances and size_bytes keeps its previous value.
-- UpdateRepoOnPush is the normal path; this one exists so a DiskUsage failure
-- never writes a fabricated size (a 0 would read as "empty repo" everywhere
-- downstream).
UPDATE repos SET last_push_at = now() WHERE id = $1;

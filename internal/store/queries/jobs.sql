-- Durable job queue (M4/WG-H, D-05). SKIP LOCKED claim; River swaps in later.

-- name: EnqueueJob :one
INSERT INTO jobs (id, kind, queue, args, max_attempts, run_at)
VALUES ($1, $2, $3, $4, $5, coalesce(sqlc.narg('run_at'), now()))
RETURNING *;

-- name: ClaimJob :one
UPDATE jobs SET state = 'running', locked_at = now(), attempt = attempt + 1
WHERE id = (
  SELECT id FROM jobs
  WHERE jobs.state = 'available' AND jobs.queue = $1 AND jobs.run_at <= now()
  ORDER BY run_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1
)
RETURNING *;

-- name: CompleteJob :exec
UPDATE jobs SET state = 'completed', finished_at = now(), last_error = NULL WHERE id = $1;

-- name: RetryJob :exec
UPDATE jobs SET state = 'available', last_error = $2, run_at = $3, locked_at = NULL WHERE id = $1;

-- name: FailJob :exec
UPDATE jobs SET state = 'failed', last_error = $2, finished_at = now() WHERE id = $1;

-- name: CountJobs :one
SELECT count(*) FROM jobs WHERE queue = $1 AND state = $2;

-- name: ResetStuckJobs :execrows
UPDATE jobs SET state = 'available', locked_at = NULL
WHERE state = 'running' AND locked_at < $1;

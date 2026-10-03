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

-- name: QueueBacklog :one
-- Depth and oldest-waiting-job age for one queue, feeding the §16.2
-- QueueDepth/QueueAgeSeconds metrics and the §16.3 "queue age > 15 min" page
-- alarm. Counts only jobs that are actually waiting to be picked up: a job
-- already running is not backlog, and counting it would make a single slow
-- handler look like a stalled queue.
--
-- run_at <= now() matters as much as state: a retry scheduled for the future
-- is deliberately waiting, and including it would show permanent backlog on a
-- queue that is keeping up. Served by jobs_poll_idx (queue, state, run_at)
-- WHERE state = 'available' — the same partial index the claim uses.
SELECT
  count(*)::bigint AS depth,
  coalesce(extract(epoch FROM (now() - min(run_at))), 0)::double precision AS oldest_seconds
FROM jobs
WHERE queue = $1 AND state = 'available' AND run_at <= now();

-- name: CountWaitingJobsOfKind :one
-- The pg driver's half of queue.Client.CountWaiting: jobs of a kind not yet
-- started (queued, scheduled for later, or waiting out a retry). A
-- self-rescheduling job enqueues its successor only when none is waiting.
SELECT count(*)::bigint FROM jobs
WHERE kind = $1 AND state = 'available';

-- name: ResetStuckJobs :execrows
UPDATE jobs SET state = 'available', locked_at = NULL
WHERE state = 'running' AND locked_at < $1;

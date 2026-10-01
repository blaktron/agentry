-- The Writing Voice (plan writing-voice.md §4, agentry#809). Every read and
-- write names the person: a voice is found only by its owner.

-- name: CreateVoice :one
-- A person's voice row, made with the first version they put; a second
-- caller racing the first finds the row the first made.
INSERT INTO voices (user_id, wrapper_kind, wrapper_recipient, wrapped_key)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET updated_at = voices.updated_at
RETURNING *;

-- name: GetVoice :one
SELECT * FROM voices WHERE user_id = $1;

-- name: GetVoiceForUpdate :one
SELECT * FROM voices WHERE user_id = $1 FOR UPDATE;

-- name: ListVoiceVersions :many
SELECT * FROM voice_versions WHERE user_id = $1 ORDER BY slot;

-- name: GetVoiceVersionInSlot :one
SELECT * FROM voice_versions WHERE user_id = $1 AND slot = $2;

-- name: GetVoiceVersion :one
SELECT * FROM voice_versions WHERE id = $1;

-- name: DeleteVoiceVersionInSlot :execrows
DELETE FROM voice_versions WHERE user_id = $1 AND slot = $2;

-- name: InsertPendingVoiceVersion :one
-- A new version for review. The pending one it replaces, if any, is
-- deleted first in the same transaction (one pending a person, D13).
INSERT INTO voice_versions (user_id, slot, review_state, source, sealed, digest, bytes)
VALUES ($1, 'pending', 'reviewing', $2, $3, $4, $5)
RETURNING *;

-- name: InsertLiveVoiceVersion :one
-- A version made live without a review of its own: a restore of the
-- previous version, reviewed under the question set in use now.
INSERT INTO voice_versions (user_id, slot, review_state, source, sealed, digest, bytes, review, question_set, reviewed_at)
VALUES ($1, 'live', 'passed', $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: CountVoiceReviewAttempt :one
-- One more try at a version's review; only a version still being reviewed
-- is counted, so a job for a replaced or decided version finds nothing.
UPDATE voice_versions SET review_attempts = review_attempts + 1, updated_at = now()
WHERE id = $1 AND slot = 'pending' AND review_state = 'reviewing'
RETURNING *;

-- name: FlagVoiceVersion :one
-- A flagged review: the version stays pending, with its findings, and the
-- live one stays live (D7).
UPDATE voice_versions
SET review_state = 'flagged', review = $2, question_set = $3, reviewed_at = now(), updated_at = now()
WHERE id = $1 AND slot = 'pending' AND review_state = 'reviewing'
RETURNING *;

-- name: NoteVoiceReview :exec
-- A review that could not finish: what it read so far, kept on the version
-- while it stays in review.
UPDATE voice_versions SET review = $2, updated_at = now()
WHERE id = $1 AND slot = 'pending' AND review_state = 'reviewing';

-- name: MoveVoiceVersionSlot :execrows
UPDATE voice_versions SET slot = sqlc.arg(to_slot), updated_at = now()
WHERE user_id = sqlc.arg(user_id) AND slot = sqlc.arg(from_slot) AND review_state = 'passed';

-- name: PassVoiceVersion :one
-- A clean review: the pending version becomes the live one. The caller
-- has moved the live one to previous first.
UPDATE voice_versions
SET slot = 'live', review_state = 'passed', review = $2, question_set = $3, reviewed_at = now(), updated_at = now()
WHERE id = $1 AND slot = 'pending' AND review_state = 'reviewing'
RETURNING *;

-- name: SwapLiveAndPreviousVoice :execrows
-- A Restore of a version reviewed under the question set in use: live and
-- previous trade places in one statement (the slot constraint is checked
-- at its end).
UPDATE voice_versions
SET slot = CASE slot WHEN 'live' THEN 'previous' ELSE 'live' END, updated_at = now()
WHERE user_id = $1 AND slot IN ('live', 'previous');

-- name: SetVoiceWentLive :one
-- A version went live. The first time, the account's always-attach flag
-- comes on (D11); after that it stays as the person set it.
UPDATE voices
SET always_attach = CASE WHEN went_live THEN always_attach ELSE true END, went_live = true, updated_at = now()
WHERE user_id = $1
RETURNING *;

-- name: SetVoiceAlwaysAttach :one
UPDATE voices SET always_attach = $2, updated_at = now() WHERE user_id = $1 RETURNING *;

-- name: TouchVoice :exec
UPDATE voices SET updated_at = now() WHERE user_id = $1;

-- name: DeleteVoice :execrows
-- The person's voice and every version of it: a delete, the account
-- erasure, a data clear.
DELETE FROM voices WHERE user_id = $1;

-- name: ListStalledVoiceReviews :many
-- Versions still in review whose last try is older than the cutoff: a job
-- that ran out of attempts, or was lost. The sweep queues them again.
SELECT id, user_id FROM voice_versions
WHERE slot = 'pending' AND review_state = 'reviewing' AND updated_at < sqlc.arg(cutoff)
ORDER BY updated_at
LIMIT 100;

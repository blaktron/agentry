-- Session-management queries behind GET/DELETE /user/sessions. Distinct from
-- the auth-path queries in auth.sql: those establish and touch the
-- credential, these let a user see and revoke their own sessions.

-- ListActiveUserSessions returns the caller's live sessions, newest activity
-- first. Expired and revoked rows are excluded — a session list is a list of
-- ways someone can still act as you, not a history.
-- name: ListActiveUserSessions :many
SELECT id, ip, user_agent, created_at, last_seen_at
FROM sessions
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
ORDER BY last_seen_at DESC, id;

-- RevokeUserSessionByID revokes one session, scoped to its owner so a caller
-- can never revoke another user's session by guessing an id. Returns the
-- number of rows changed (0 = not found OR not yours — indistinguishable on
-- purpose).
-- name: RevokeUserSessionByID :execrows
UPDATE sessions SET revoked_at = now()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- RevokeOtherUserSessions revokes every live session of a user except the one
-- named by $2 ("sign out everywhere else"). Passing a nil UUID revokes all of
-- them, since no session row has the nil id.
-- name: RevokeOtherUserSessions :execrows
UPDATE sessions SET revoked_at = now()
WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL;

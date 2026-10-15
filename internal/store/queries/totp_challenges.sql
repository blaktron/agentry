-- The consumed set of the 2FA social login's second leg.

-- name: ConsumeTOTPChallenge :execrows
-- Records the challenge's id as consumed. A row already there means it was
-- completed before, and the zero rows affected say so. Two replicas
-- completing one challenge at once cannot both win: the loser of the
-- insert waits on the winner's row and finds the conflict.
INSERT INTO totp_consumed_challenges (id, expires_at) VALUES ($1, $2)
ON CONFLICT (id) DO NOTHING;

-- name: DeleteExpiredTOTPChallenges :execrows
DELETE FROM totp_consumed_challenges WHERE expires_at <= now();

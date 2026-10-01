-- +goose Up
-- The Writing Voice (plan writing-voice.md §4, D2, D11, D13; agentry#809):
-- the one VOICE.md a person keeps in Agentry, the instructions a run follows
-- for how it writes. It is not a knowledge pack: one per person, no name,
-- no tree. The voice row holds the data key every version is sealed under,
-- only as the person's key wrapper (the knowledge store's) wrapped it, and
-- the account's always-attach flag (D11). The user's row is never deleted
-- (an erasure anonymizes it), so the account erasure and a data clear
-- delete the voice by name, as they do the person's packs.
CREATE TABLE voices (
  user_id           uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  wrapper_kind      text NOT NULL,
  wrapper_recipient text NOT NULL,
  wrapped_key       bytea NOT NULL,
  -- always_attach is on when a voice first goes live (D11) and the person's
  -- to change after; went_live says whether one ever has, so the first
  -- time is told apart from the next.
  always_attach     boolean NOT NULL DEFAULT false,
  went_live         boolean NOT NULL DEFAULT false,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

-- At most three versions a person (D13): the live one runs attach, one
-- pending (in review, or flagged with its findings), and the previous one
-- for Restore. Each is its VOICE.md sealed under the voice's data key
-- (pkg/packseal), a few tens of KiB, so it lives in the row, not the blob
-- store. The review report keeps no excerpt: it is in the clear beside a
-- sealed text.
CREATE TABLE voice_versions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES voices(user_id) ON DELETE CASCADE,
  slot          text NOT NULL CHECK (slot IN ('live', 'pending', 'previous')),
  -- A pending version is reviewing or flagged; a live or previous one
  -- passed its review (or was a live one's, restored under the same set).
  review_state  text NOT NULL CHECK (review_state IN ('reviewing', 'flagged', 'passed')),
  source        text NOT NULL CHECK (source IN ('build', 'ai-edit', 'edit', 'upload', 'restore')),
  sealed        bytea NOT NULL,
  digest        text NOT NULL,
  bytes         integer NOT NULL,
  review        jsonb,
  question_set  text NOT NULL DEFAULT '',
  -- review_attempts counts the review's tries; reviewed_at is when its
  -- verdict was recorded.
  review_attempts integer NOT NULL DEFAULT 0,
  reviewed_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  -- Deferrable so a Restore swaps live and previous in one statement.
  CONSTRAINT voice_versions_one_per_slot UNIQUE (user_id, slot) DEFERRABLE INITIALLY IMMEDIATE,
  CHECK ((slot = 'pending') = (review_state <> 'passed'))
);

-- +goose Down
DROP TABLE voice_versions;
DROP TABLE voices;

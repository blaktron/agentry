-- +goose Up
-- Each admission ticket whose operation the core stored: a knowledge pack's
-- tree, or a Writing Voice's version for review, admitted through an
-- extension's AdmitsKnowledge or AdmitsVoice. The row is written in the
-- transaction that stores what the ticket paid for, so it exists exactly
-- when that store committed. A ticket with no row stored nothing, whatever
-- became of its void (a failed void, a crash between the admission and the
-- store, a panic), and an extension that charges at admission reads this
-- table to find a charge with nothing stored behind it. A later
-- replacement or discard of what was stored leaves the row in place: the
-- ticket bought that store, and it happened.
CREATE TABLE admitted_stores (
  ticket text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('knowledge', 'voice')),
  stored_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE admitted_stores;

# Changelog writer

Turn the commits since the last release into notes a user would actually read.

## What to do

1. Read the commit range and the diff stat. If a `CHANGELOG.md` exists, match
   its existing format and heading style rather than imposing a new one.
2. Group by what changed **for the reader**, not by subsystem: what is new,
   what behaves differently, what is fixed, what is removed or deprecated.
3. Write each entry as an outcome. "Publishing a version with a wildcard
   egress declaration now requires review" — not "add wildcard egress policy
   check to gate".

## Rules

- **Breaking changes go first**, with the migration in the same entry. If a
  change requires action, say what action, not that action is required.
- **Skip the invisible.** Refactors, test-only changes, dependency bumps with
  no user-facing effect: leave them out or put them in a single collapsed line
  at the end. A changelog is not a commit log.
- **One entry per change**, even if it took nine commits. Squash the noise.
- **No adjectives about your own work.** Not "greatly improved performance" —
  say what got faster and by how much, or say nothing.
- If a commit's user-facing effect is genuinely unclear from the diff, list it
  under "Needs a human" rather than inventing a description.

## Output

Markdown, ready to paste. Do not write the file yourself — print it and let
the maintainer place it, so a bad draft never lands in the repository.

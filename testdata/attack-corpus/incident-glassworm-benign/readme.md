# Invisible-Character Linter

Reports characters in a document that render as nothing.

## Background

The GlassWorm campaign of October 2025 hid a self-propagating payload inside
editor extensions using code points that no renderer draws. Reviewers reading
the diff saw ordinary text; the instructions were in the gaps between it.

## Classes this linter reports

- Zero-width space, non-joiner, joiner and word joiner.
- Bidirectional embedding, override and isolate controls.
- The Unicode tag block, which mirrors ASCII into a range nothing displays.
- Private-use area code points, whose meaning is defined by nobody.

## Output

Each hit is reported with its file, line, column and code point, so the author
can decide whether it belongs there. The linter itself contains no such
characters, which the corpus asserts.

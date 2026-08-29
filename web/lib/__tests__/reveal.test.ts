import { describe, expect, it } from "vitest";
import { isInvisible } from "../reveal";

// The invisible-character list is security-critical and duplicated across
// two languages (§10.3, the GlassWorm lesson):
//
//   Go         internal/render/render.go   func isInvisible(r rune) bool
//   TypeScript web/lib/reveal.tsx           export function isInvisible(cp)
//
// The Go side reveals characters inside server-sanitized README HTML; this
// side reveals them in finding excerpts and the reviewer's file viewer. A
// character revealed by one and not the other is a hiding place, so the
// classes below are pinned here in the same order the Go switch lists them.
// If you change either list, change both — and update these expectations,
// which is the point of them being explicit.

const ZERO_WIDTH = [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff];
const BIDI_CONTROLS = [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069];
const TAG_BLOCK = [0xe0000, 0xe0001, 0xe0041, 0xe007f];
const PRIVATE_USE = [0xe000, 0xf8ff, 0xf0000, 0xffffd, 0x100000, 0x10fffd];
const SOFT_HYPHEN = [0x00ad];
// Format characters (Unicode Cf) outside the explicit ranges above, caught by
// the \p{Cf} fallback both implementations share.
const OTHER_FORMAT = [
  0x0600, // ARABIC NUMBER SIGN
  0x061c, // ARABIC LETTER MARK
  0x070f, // SYRIAC ABBREVIATION MARK
  0x200e, // LEFT-TO-RIGHT MARK
  0x200f, // RIGHT-TO-LEFT MARK
  0x2061, // FUNCTION APPLICATION (invisible math operator)
  0xfff9, // INTERLINEAR ANNOTATION ANCHOR
];

describe("isInvisible", () => {
  it.each([
    ["zero-width", ZERO_WIDTH],
    ["bidi control", BIDI_CONTROLS],
    ["Unicode tag block", TAG_BLOCK],
    ["private use area", PRIVATE_USE],
    ["soft hyphen", SOFT_HYPHEN],
    ["other Cf format character", OTHER_FORMAT],
  ])("reveals every %s codepoint", (_label, codepoints) => {
    for (const cp of codepoints) {
      expect(isInvisible(cp), `U+${cp.toString(16).toUpperCase()} must be revealed`).toBe(true);
    }
  });

  it("leaves ordinary text alone", () => {
    for (const ch of "Hello, world! 123 — naïve ✅ 日本語") {
      expect(isInvisible(ch.codePointAt(0)!), `${ch} must not be revealed`).toBe(false);
    }
  });

  it("leaves whitespace that renders as whitespace alone", () => {
    // A space, tab or newline is visible as layout; replacing it with a chip
    // would make the reviewer's file viewer unreadable for no safety gain.
    for (const cp of [0x20, 0x09, 0x0a, 0x0d]) {
      expect(isInvisible(cp)).toBe(false);
    }
  });

  it("does not reveal characters just outside the explicit ranges", () => {
    for (const cp of [
      0x200a, // HAIR SPACE — Zs, renders as space
      0x2028, // LINE SEPARATOR — Zl
      0x2065, // unassigned
      0xe0080, // unassigned, past the tag block
    ]) {
      expect(isInvisible(cp), `U+${cp.toString(16).toUpperCase()} is outside the classes`).toBe(false);
    }
  });
});

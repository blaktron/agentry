// URL and redirect-target helpers shared by pages, route handlers, and the
// unit tests. Deliberately free of `server-only` (unlike lib/forms.ts): the
// validation below is the kind of thing that must be unit-testable, and it
// is needed by server components as well as route handlers.

// hasControlChars reports whether s contains a C0 control character or DEL.
// Written as a codepoint scan rather than a regex literal so the source
// carries no invisible bytes of its own.
function hasControlChars(s: string): boolean {
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20 || cp === 0x7f) return true;
  }
  return false;
}

// safeNext validates a caller-supplied in-app redirect target.
//
// The only accepted shape is a path-absolute reference: it must start with a
// single "/" and stay on this origin. The rejected cases are the ones a
// browser resolves differently from a naive `startsWith("/")` check:
//
//   "//evil.example"   scheme-relative — a different origin entirely
//   "/\evil.example"   browsers normalize the backslash to "/", so this is
//                      the same open redirect wearing a different hat
//   embedded CR/LF/TAB some parsers strip them before resolving, which can
//                      turn an inert-looking string into a live target
export function safeNext(v: unknown, fallback: string): string {
  if (typeof v !== "string" || v === "") return fallback;
  if (!v.startsWith("/")) return fallback;
  if (v.length > 1 && (v[1] === "/" || v[1] === "\\")) return fallback;
  if (hasControlChars(v)) return fallback;
  return v;
}

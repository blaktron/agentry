// Invisible-Unicode revelation for the review UI (§10.3, the GlassWorm
// lesson): any content a reviewer reads must show zero-width/bidi/tag-block
// characters as visible placeholders — the reviewer must never see less than
// the scanner saw.
//
// This is the browser-side half of a rule enforced in two places. The
// authority is `isInvisible` in internal/render/render.go (Go, applied to
// sanitized README HTML server-side); this function is the TypeScript mirror
// used where the web tier renders text itself (finding excerpts, the review
// file viewer). The two lists MUST stay identical — a character revealed by
// one and not the other is a hiding place. The class list is pinned by
// lib/__tests__/reveal.test.ts on this side and by
// internal/render/render_test.go on the other, and the shared attack corpus
// is rendered through both.

const CF_RE = /\p{Cf}/u;

export function isInvisible(cp: number): boolean {
  if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff) return true; // zero-width
  if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) return true; // bidi controls
  if (cp >= 0xe0000 && cp <= 0xe007f) return true; // Unicode tag block
  if ((cp >= 0xe000 && cp <= 0xf8ff) || (cp >= 0xf0000 && cp <= 0xffffd) || (cp >= 0x100000 && cp <= 0x10fffd))
    return true; // private use areas
  if (cp === 0x00ad) return true; // soft hyphen
  return CF_RE.test(String.fromCodePoint(cp)); // any other format character
}

// RevealText renders text with invisible characters replaced by visible
// placeholder chips. React escapes everything — this component never emits
// raw HTML from user content.
export function RevealText({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  let run = "";
  let key = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (isInvisible(cp)) {
      if (run) {
        parts.push(run);
        run = "";
      }
      parts.push(
        <span key={key++} className="agy-invisible" title="invisible character revealed">
          U+{cp.toString(16).toUpperCase().padStart(4, "0")}
        </span>,
      );
    } else {
      run += ch;
    }
  }
  if (run) parts.push(run);
  return <>{parts}</>;
}

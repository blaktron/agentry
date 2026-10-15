package render

import (
	"regexp"
	"strings"
	"testing"
)

// FuzzSanitize is the markdown sanitizer round-trip fuzz target. It
// asserts three properties over arbitrary input:
//
//  1. Markdown never panics, whatever bytes it is handed. This package is the
//     only path by which author content reaches a browser, and every
//     byte of that content is untrusted.
//
//  2. The output is a FIXED POINT: sanitizing already-sanitized HTML produces
//     the same string. A sanitizer whose output is not stable under a second
//     pass has a re-entrancy bug, and re-entrancy bugs in sanitizers are how
//     mutation-XSS works — the browser's parse of the output differs from the
//     sanitizer's, and a second parse reveals markup the first pass "removed".
//
//  3. No TAG in the output is executable: no script/iframe/object/embed/svg
//     element, no `on…=` event attribute, no `javascript:` or `data:text/html`
//     URL. The check is scoped to tag regions on purpose. `javascript:alert(1)`
//     as visible paragraph text is inert — a reader sees the characters — and
//     asserting on the raw string would fail on that while saying nothing about
//     what a browser would run.
func FuzzSanitize(f *testing.F) {
	seeds := []string{
		"# hello\n\nplain paragraph\n",
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"[link](javascript:alert(1))",
		"[link](JaVaScRiPt:alert(1))",
		"<a href=\"data:text/html;base64,PHNjcmlwdD4=\">x</a>",
		"<div style=\"position:absolute;left:-9999px\">hidden</div>",
		"<!-- <script>alert(1)</script> -->",
		"<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
		"<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
		"<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
		"> quote\n\n| a | b |\n|---|---|\n| 1 | 2 |\n",
		"a\u200bb\u202ec\U000E0041d\ufeffe",
		"![alt](image.png \"title\")",
		"<a href=\"//evil.example\">protocol relative</a>",
		"```\n<script>alert(1)</script>\n```\n",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&#106;avascript:alert(1)",
		"\x00\xff\xfe",
		strings.Repeat("<b>", 200) + "x",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	r := New()
	f.Fuzz(func(t *testing.T, src string) {
		out, err := r.Markdown([]byte(src))
		if err != nil {
			return
		}
		for _, tag := range tagRegions(out) {
			if bad := executableConstruct(tag); bad != "" {
				t.Fatalf("sanitized output has an executable tag (%s)\ninput:  %q\ntag:    %q\noutput: %q",
					bad, src, tag, out)
			}
		}
		// Round trip: the sanitizer applied to its own output is a no-op.
		// Markdown() renders markdown, so feed the output back through the
		// policy + rel stamp + reveal pass directly — that is the composition
		// an attacker would try to exploit.
		again := r.sanitize(out)
		if again != out {
			t.Fatalf("sanitize is not idempotent\ninput:  %q\nfirst:  %q\nsecond: %q", src, out, again)
		}

		// PlainText shares the parser and must be crash-safe too. Its
		// documented contract is "tags stripped, invisible characters removed"
		// — not "no angle brackets": a code fence containing <script> yields
		// that string as literal text, correctly, and escaping is the caller's
		// job at the template. The invisible-character half IS asserted, since
		// nothing downstream restores it.
		for _, ch := range r.PlainText([]byte(src)) {
			if isInvisible(ch) {
				t.Fatalf("PlainText leaked invisible U+%04X from %q", ch, src)
			}
		}
	})
}

// tagRegions returns the text of every `<…>` region in html, lowercased.
func tagRegions(html string) []string {
	var out []string
	for i := 0; i < len(html); i++ {
		if html[i] != '<' {
			continue
		}
		j := strings.IndexByte(html[i:], '>')
		if j < 0 {
			break
		}
		out = append(out, strings.ToLower(html[i:i+j+1]))
		i += j
	}
	return out
}

// eventAttrRe matches an inline event-handler attribute inside a tag.
var eventAttrRe = regexp.MustCompile(`\son[a-z]+\s*=`)

// executableConstruct names the reason a tag is executable, or "" when it is
// inert.
func executableConstruct(tag string) string {
	for _, el := range []string{"script", "iframe", "object", "embed", "svg", "math", "base", "form"} {
		if strings.HasPrefix(tag, "<"+el) || strings.HasPrefix(tag, "</"+el) {
			return "<" + el + "> element"
		}
	}
	if eventAttrRe.MatchString(tag) {
		return "event-handler attribute"
	}
	for _, scheme := range []string{"javascript:", "vbscript:", "data:text/html"} {
		if strings.Contains(tag, scheme) {
			return scheme + " URL"
		}
	}
	return ""
}

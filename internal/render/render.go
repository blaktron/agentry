// Package render turns untrusted author markdown into safe HTML (§10.3,
// D-11). Hostile READMEs are a primary XSS vector (T-07), so this package is
// the only path by which user content reaches a browser, and it is
// deliberately strict: goldmark with raw HTML disabled, then a bluemonday
// allowlist, then invisible/bidi Unicode rendered as visible placeholders.
package render

import (
	"bytes"
	"fmt"
	htmlpkg "html"
	"strings"
	"unicode"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// MaxInputBytes caps rendering input (§19 instruction-file quota is 1 MB;
// give README the same ceiling).
const MaxInputBytes = 1 << 20

// Renderer converts markdown to sanitized HTML. Safe for concurrent use.
type Renderer struct {
	md     goldmark.Markdown
	policy *bluemonday.Policy
}

// New builds the renderer with the §10.3 policy.
func New() *Renderer {
	md := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM, // tables, strikethrough, task lists, autolinks
			extension.Footnote,
		),
		goldmark.WithParserOptions(
			// Author headings are demoted one level so a README's "# Title"
			// becomes an <h2> inside a page that already owns the <h1>. Two
			// <h1> elements break the document outline for screen readers, and
			// the fix belongs here rather than in one page's stylesheet: this
			// HTML is served by the API and may be embedded anywhere.
			parser.WithASTTransformers(util.Prioritized(demoteHeadings{}, 100)),
		),
		goldmark.WithRendererOptions(
			// Raw HTML never passes through (§10.3: "no raw HTML pass-through
			// ever"). Unsafe mode is simply not enabled; goldmark escapes it.
			goldmarkhtml.WithXHTML(),
		),
	)

	p := bluemonday.NewPolicy()

	// Block structure and inline emphasis only.
	p.AllowElements(
		"h1", "h2", "h3", "h4", "h5", "h6",
		"p", "br", "hr", "blockquote",
		"ul", "ol", "li", "dl", "dt", "dd",
		"strong", "em", "b", "i", "del", "s", "code", "pre", "kbd", "sup", "sub",
		"table", "thead", "tbody", "tfoot", "tr", "th", "td",
		"section", "span",
	)
	// Links: http(s) and mailto only, with rel hardening (§10.3).
	p.AllowAttrs("href").OnElements("a")
	p.AllowURLSchemes("http", "https", "mailto")
	p.RequireNoFollowOnLinks(true)
	p.RequireNoReferrerOnLinks(true)
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.AllowElements("a")
	// Images: proxied/relative sources only — see RewriteImages. No SVG.
	p.AllowAttrs("src", "alt", "title").OnElements("img")
	p.AllowElements("img")
	// Footnote/heading anchors emitted by goldmark itself.
	p.AllowAttrs("id").Matching(bluemonday.SpaceSeparatedTokens).OnElements("li", "section", "sup", "h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowAttrs("class").Matching(bluemonday.SpaceSeparatedTokens).OnElements("span", "section", "sup", "li")
	// Tables' alignment attribute is the one layout hint we keep.
	p.AllowAttrs("align").Matching(bluemonday.Paragraph).OnElements("th", "td")
	// NO style/class from users (§10.3) beyond the internal classes above;
	// bluemonday drops everything not explicitly allowed.

	return &Renderer{md: md, policy: p}
}

// Markdown renders markdown to sanitized HTML with invisible characters made
// visible. The output is a fragment (no <html>/<body>) intended for a
// container element with the `readme` class.
func (r *Renderer) Markdown(src []byte) (string, error) {
	if len(src) > MaxInputBytes {
		src = src[:MaxInputBytes]
	}
	var buf bytes.Buffer
	if err := r.md.Convert(src, &buf); err != nil {
		return "", fmt.Errorf("render: markdown: %w", err)
	}
	safe := r.policy.SanitizeBytes(buf.Bytes())
	return RevealInvisible(string(safe)), nil
}

// demoteHeadings shifts every author heading down one level (h1→h2 … h5→h6),
// leaving h6 alone since there is nowhere deeper to go.
type demoteHeadings struct{}

// Transform implements parser.ASTTransformer.
func (demoteHeadings) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if h, ok := n.(*ast.Heading); ok && h.Level < 6 {
			h.Level++
		}
		return ast.WalkContinue, nil
	})
}

// invisibleRanges are the codepoint classes that must never render as
// nothing in user content (§10.3, the GlassWorm lesson): zero-width and
// formatting characters, bidi controls, the Unicode tag block, and
// private-use areas.
func isInvisible(r rune) bool {
	switch {
	case r == 0x200B, r == 0x200C, r == 0x200D, r == 0x2060, r == 0xFEFF:
		return true // zero-width space/non-joiner/joiner/word-joiner/BOM
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true // bidi embedding/override/isolate controls
	case r >= 0xE0000 && r <= 0xE007F:
		return true // Unicode tag block (ASCII smuggling)
	case r >= 0xE000 && r <= 0xF8FF, r >= 0xF0000 && r <= 0xFFFFD, r >= 0x100000 && r <= 0x10FFFD:
		return true // private use areas
	case r == 0x00AD:
		return true // soft hyphen
	case unicode.Is(unicode.Cf, r):
		return true // any other format character
	}
	return false
}

// RevealInvisible replaces invisible characters in already-sanitized HTML
// with visible, escaped placeholders wrapped in a marker span. Text outside
// tags only — attribute values are left alone (they are already policy-
// filtered, and rewriting inside them could corrupt URLs).
func RevealInvisible(safeHTML string) string {
	var b strings.Builder
	b.Grow(len(safeHTML))
	inTag := false
	for _, r := range safeHTML {
		switch {
		case r == '<':
			inTag = true
			b.WriteRune(r)
		case r == '>':
			inTag = false
			b.WriteRune(r)
		case inTag:
			b.WriteRune(r)
		case isInvisible(r):
			fmt.Fprintf(&b, `<span class="agy-invisible">U+%04X</span>`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// PlainText renders markdown to plain text (search snippets, meta
// descriptions): tags stripped, invisible characters removed outright.
func (r *Renderer) PlainText(src []byte) string {
	if len(src) > MaxInputBytes {
		src = src[:MaxInputBytes]
	}
	var buf bytes.Buffer
	if err := r.md.Convert(src, &buf); err != nil {
		return ""
	}
	text := bluemonday.StrictPolicy().Sanitize(buf.String())
	text = htmlUnescape(text)
	var out strings.Builder
	for _, r := range text {
		if !isInvisible(r) {
			out.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

func htmlUnescape(s string) string { return htmlpkg.UnescapeString(s) }

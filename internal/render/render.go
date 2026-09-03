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
	"regexp"
	"strings"
	"unicode"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
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
// Options tunes a Renderer. The zero value is the strict default: images
// become placeholders.
type Options struct {
	// ImageProxy maps an absolute http(s) image URL to a same-origin proxy
	// URL (agentry#64, §10.3 "images proxied"). nil keeps the placeholder;
	// a returned false keeps the placeholder for that URL.
	ImageProxy func(dest string) (string, bool)
}

func New() *Renderer { return NewWithOptions(Options{}) }

// NewWithOptions builds a Renderer with the given options.
func NewWithOptions(opts Options) *Renderer {
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
			// Images become a visible placeholder (agentry#29, DEV-049):
			// the web app's CSP refuses every image source but its own, so
			// an <img> would render as nothing and the reader would not
			// know an image was there.
			renderer.WithNodeRenderers(util.Prioritized(imagePlaceholder{proxy: opts.ImageProxy}, 100)),
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
	// Images: none. §10.3's camo-style image proxy is NOT built (DEV-049),
	// and the web app's `img-src 'self' data:` CSP would refuse an
	// author's image anyway, which closes the tracking-pixel and
	// third-party-request hole §10.3 is about. Rather than an <img> that
	// renders as nothing, the markdown renderer above emits a visible
	// placeholder naming the alt text and the source (agentry#29); no
	// <img> element reaches the output at all.
	// Footnote/heading anchors emitted by goldmark itself.
	p.AllowAttrs("id").Matching(bluemonday.SpaceSeparatedTokens).OnElements("li", "section", "sup", "h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowAttrs("class").Matching(bluemonday.SpaceSeparatedTokens).OnElements("span", "section", "sup", "li")
	// Tables' alignment attribute is the one layout hint we keep.
	p.AllowAttrs("align").Matching(bluemonday.Paragraph).OnElements("th", "td")
	// Proxied images only (agentry#64): an absolute same-origin
	// <origin>/api/v1/img/<sig>/<ref> source (bluemonday admits URL
	// attributes by scheme, so the renderer signs absolute URLs), plain alt
	// text, lazy loading. Any other <img> is dropped by
	// the policy, so an author cannot smuggle a third-party request.
	p.AllowElements("img")
	p.AllowAttrs("src").Matching(regexp.MustCompile(`^https?://[^/\s"'<>]+/api/v1/img/[A-Za-z0-9_-]{16,64}/[A-Za-z0-9_-]+$`)).OnElements("img")
	p.AllowAttrs("alt").Matching(bluemonday.Paragraph).OnElements("img")
	p.AllowAttrs("loading").Matching(regexp.MustCompile(`^lazy$`)).OnElements("img")
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
	return r.sanitize(buf.String()), nil
}

// sanitize is the full post-render pass: the bluemonday policy, the
// rel="ugc" stamp, and invisible-character revealing. It is the composition
// FuzzSanitize round-trips, so it must be idempotent on its own output.
func (r *Renderer) sanitize(html string) string {
	return RevealInvisible(addUGC(r.policy.Sanitize(html)))
}

// relRe finds the rel attribute bluemonday emits on links. The sanitizer
// sets nofollow/noreferrer/noopener itself but has no switch for "ugc",
// the §10.3 hint that a link is user-generated content (DEV-039,
// agentry#34); this post-pass adds it. Attribute values in sanitized output
// are double-quoted and contain no quotes, so the pattern is exact.
var relRe = regexp.MustCompile(`(<a\b[^>]*\brel=")([^"]*)(")`)

func addUGC(html string) string {
	return relRe.ReplaceAllStringFunc(html, func(tag string) string {
		m := relRe.FindStringSubmatch(tag)
		for _, tok := range strings.Fields(m[2]) {
			if tok == "ugc" {
				return tag
			}
		}
		return m[1] + strings.TrimSpace(m[2]+" ugc") + m[3]
	})
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

// imagePlaceholder renders markdown images as a visible note instead of an
// <img> the browser would refuse (agentry#29). The alt text and the source
// are shown, HTML-escaped, so the reader can tell what was there and where
// it lives; the placeholder is a <span class="img-placeholder">, which the
// sanitizer's allowlist admits and the web app styles.
type imagePlaceholder struct {
	proxy func(dest string) (string, bool)
}

func (p imagePlaceholder) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindImage, p.render)
}

func (p imagePlaceholder) render(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	img, ok := node.(*ast.Image)
	if !ok {
		return ast.WalkContinue, nil
	}
	alt := strings.TrimSpace(string(imageAltText(source, img)))
	dest := strings.TrimSpace(string(img.Destination))
	// Absolute http(s) images go through the same-origin proxy when one is
	// configured (agentry#64); everything else stays a visible placeholder.
	if p.proxy != nil && (strings.HasPrefix(dest, "https://") || strings.HasPrefix(dest, "http://")) {
		if src, ok := p.proxy(dest); ok {
			_, _ = w.WriteString(`<img src="` + htmlpkg.EscapeString(src) + `" alt="` + htmlpkg.EscapeString(alt) + `" loading="lazy">`)
			return ast.WalkSkipChildren, nil
		}
	}
	_, _ = w.WriteString(`<span class="img-placeholder" role="note">Image not shown — this page does not load images`)
	if alt != "" {
		_, _ = w.WriteString(": " + htmlpkg.EscapeString(alt))
	}
	if dest != "" {
		if len(dest) > 200 {
			dest = dest[:200] + "…"
		}
		_, _ = w.WriteString(" (" + htmlpkg.EscapeString(dest) + ")")
	}
	_, _ = w.WriteString("</span>")
	return ast.WalkSkipChildren, nil
}

// imageAltText concatenates the text segments under an image node — its
// alt text in markdown — without rendering child markup.
func imageAltText(source []byte, n ast.Node) []byte {
	var out []byte
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch t := c.(type) {
		case *ast.Text:
			out = append(out, t.Segment.Value(source)...)
		case *ast.RawHTML:
			// Angle-bracketed alt text parses as raw HTML; it is still just
			// the author's words here and is escaped on output.
			for i := 0; i < t.Segments.Len(); i++ {
				seg := t.Segments.At(i)
				out = append(out, seg.Value(source)...)
			}
		default:
			out = append(out, imageAltText(source, c)...)
		}
	}
	return out
}

package render

import (
	"strings"
	"testing"
)

func TestFencedCodeIsHighlightedWithClassesOnly(t *testing.T) {
	r := New()
	out, err := r.Markdown([]byte("```go\npackage main\n\nfunc main() { println(\"hi\") }\n```\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `<pre class="hl-chroma">`) {
		t.Fatalf("expected the chroma pre class:\n%s", out)
	}
	if !strings.Contains(out, `<span class="hl-`) {
		t.Fatalf("expected token spans:\n%s", out)
	}
	if strings.Contains(out, "style=") {
		t.Fatalf("highlighting must not emit inline styles:\n%s", out)
	}
	if !strings.Contains(out, "package") || !strings.Contains(out, "&#34;hi&#34;") && !strings.Contains(out, "&quot;hi&quot;") {
		t.Fatalf("code text must survive, escaped:\n%s", out)
	}
	// Unknown language: plain, still escaped, no guessing.
	out, err = r.Markdown([]byte("```nosuchlang\n<script>alert(1)</script>\n```\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "<script") || !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("code content must stay escaped:\n%s", out)
	}
	// Round trip (the FuzzSanitize contract) holds for highlighted output.
	if again := r.sanitize(out); again != out {
		t.Fatalf("sanitize not idempotent on highlighted output\nfirst:  %q\nsecond: %q", out, again)
	}
}

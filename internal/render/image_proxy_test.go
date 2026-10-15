package render

import (
	"strings"
	"testing"
)

func TestImagesRouteThroughTheProxy(t *testing.T) {
	r := NewWithOptions(Options{ImageProxy: func(dest string) (string, bool) {
		if strings.HasPrefix(dest, "https://cdn.example/") {
			return "https://registry.example/api/v1/img/abcdefghijklmnopqrstuvwxyz012345/aGVsbG8", true
		}
		return "", false
	}})
	out, err := r.Markdown([]byte("![Logo](https://cdn.example/logo.png)\n\n![local](./docs/a.png)\n\n![blocked](https://other.example/x.png)\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `<img src="https://registry.example/api/v1/img/abcdefghijklmnopqrstuvwxyz012345/aGVsbG8" alt="Logo" loading="lazy"`) {
		t.Fatalf("proxied image missing:\n%s", out)
	}
	if strings.Count(out, "<img") != 1 || !strings.Contains(out, "img-placeholder") {
		t.Fatalf("non-proxied images must stay placeholders:\n%s", out)
	}
	// A hand-written <img> to a third party never survives the policy.
	out, _ = r.Markdown([]byte(`<img src="https://evil.example/t.png">` + "\n"))
	if strings.Contains(out, "<img") {
		t.Fatalf("raw img must be dropped:\n%s", out)
	}
	if again := r.sanitize(out); again != out {
		t.Fatal("sanitize not idempotent")
	}
	// Default renderer: no proxy, placeholder.
	out, _ = New().Markdown([]byte("![Logo](https://cdn.example/logo.png)\n"))
	if strings.Contains(out, "<img") {
		t.Fatalf("default renderer must not emit img:\n%s", out)
	}
}

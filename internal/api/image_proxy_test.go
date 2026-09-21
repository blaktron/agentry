package api_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// The README image proxy (agentry#64) serves only URLs it signed, fetches
// through the guard, and re-encodes raster images; SVG is refused.
func TestImageProxy(t *testing.T) {
	var pngBytes bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 3, 2))
	img.Set(1, 1, color.RGBA{R: 200, A: 255})
	if err := png.Encode(&pngBytes, img); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logo.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(pngBytes.Bytes())
		case "/evil.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			_, _ = io.WriteString(w, `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer origin.Close()

	// The renderer signs URLs on the configured public origin; the test only
	// needs it to be absolute, then requests the path on its own server.
	env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = "https://registry.test" },
		func(s *api.Server) { s.SetImageProxyClient(origin.Client()) })
	user := env.register("img-owner")
	env.verifyEmail(user)
	sess := env.login(user)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": user, "name": "pics", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read")
	files := map[string]string{
		"agent.yaml": skillYAML(user, "pics", "1.0.0"),
		"README.md":  "# pics\n\n![Logo](" + origin.URL + "/logo.png)\n\n![Bad](" + origin.URL + "/evil.svg)\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}
	if status, body := env.uploadVersionCLI(user, "pics", pat, files); status != http.StatusAccepted {
		t.Fatalf("upload: %d %s", status, body)
	}
	env.waitStatus(user, "pics", "1.0.0", "published")

	res := env.do(sess, http.MethodGet, "/api/v1/agents/"+user+"/pics/readme", nil)
	html, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	srcs := []string{}
	for _, part := range strings.Split(string(html), `src="`)[1:] {
		srcs = append(srcs, part[:strings.IndexByte(part, '"')])
	}
	if len(srcs) != 2 || !strings.Contains(srcs[0], "/api/v1/img/") {
		t.Fatalf("rendered README must reference the proxy:\n%s", html)
	}
	// The renderer signs absolute URLs on the registry origin; hit the path.
	for i := range srcs {
		srcs[i] = srcs[i][strings.Index(srcs[i], "/api/v1/img/"):]
	}

	// PNG: served re-encoded with cache headers.
	res = env.do(sess, http.MethodGet, srcs[0], nil)
	got, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "image/png" || !strings.Contains(res.Header.Get("Cache-Control"), "max-age=86400") {
		t.Fatalf("png: %d %s %s", res.StatusCode, res.Header.Get("Content-Type"), res.Header.Get("Cache-Control"))
	}
	if cfg, err := png.DecodeConfig(bytes.NewReader(got)); err != nil || cfg.Width != 3 || cfg.Height != 2 {
		t.Fatalf("re-encoded png: %v %+v", err, cfg)
	}
	// SVG: refused.
	res = env.do(sess, http.MethodGet, srcs[1], nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("svg: got %d want 415", res.StatusCode)
	}
	// Tampered signature: not found, nothing fetched.
	tampered := strings.Replace(srcs[0], "/img/", "/img/x", 1)
	res = env.do(sess, http.MethodGet, tampered, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("bad signature: got %d want 404", res.StatusCode)
	}
}

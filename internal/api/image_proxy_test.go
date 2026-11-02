package api_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/logx"
)

// imageProxySealingKey is the sealing key the database-free proxy servers
// below run with; the proxy's signing key is derived from it.
var imageProxySealingKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

// signedImagePath is the proxy path for dest as a server with that sealing
// key signs it: an HMAC over the destination under a key derived from the
// sealing key, truncated to 32 characters, then the destination itself.
func signedImagePath(sealingKey, dest string) string {
	key := sha256.Sum256([]byte("img-proxy:" + sealingKey))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(dest))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
	return "/api/v1/img/" + sig + "/" + base64.RawURLEncoding.EncodeToString([]byte(dest))
}

// imageProxyServer is the assembled handler with no database. client, when
// set, replaces the guarded client the proxy fetches with.
func imageProxyServer(t *testing.T, client *http.Client) (*httptest.Server, *logSink) {
	t.Helper()
	cfg := config.Default()
	cfg.DevMode = true
	cfg.BaseURL = "https://registry.test"
	cfg.Auth.SealingKey = imageProxySealingKey
	var logs logSink
	s := api.New(cfg, nil, logx.New(logx.Options{W: &logs}))
	if client != nil {
		s.SetImageProxyClient(client)
	}
	srv := httptest.NewServer(api.NewHandler(s))
	t.Cleanup(srv.Close)
	return srv, &logs
}

// proxyGet fetches path from the proxy server and returns the response with
// its body read.
func proxyGet(t *testing.T, srv *httptest.Server, path string, h http.Header) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res, body
}

// The README image proxy serves only URLs it signed, fetches
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

	t.Run("a signature is good for its own destination only", func(t *testing.T) {
		proxy, _ := imageProxyServer(t, origin.Client())
		logo := signedImagePath(imageProxySealingKey, origin.URL+"/logo.png")
		svg := signedImagePath(imageProxySealingKey, origin.URL+"/evil.svg")
		if res, _ := proxyGet(t, proxy, logo, nil); res.StatusCode != http.StatusOK {
			t.Fatalf("a correctly signed destination: %d, want 200", res.StatusCode)
		}
		sigOf := func(p string) string { return strings.Split(strings.TrimPrefix(p, "/api/v1/img/"), "/")[0] }
		refOf := func(p string) string { return strings.Split(strings.TrimPrefix(p, "/api/v1/img/"), "/")[1] }
		for name, path := range map[string]string{
			"the signature of another destination":     "/api/v1/img/" + sigOf(svg) + "/" + refOf(logo),
			"a signature cut short":                    "/api/v1/img/" + sigOf(logo)[:16] + "/" + refOf(logo),
			"a signature from another key":             signedImagePath("c2VhbGluZy1rZXktb2YtYW5vdGhlci1zZXJ2ZXI=", origin.URL+"/logo.png"),
			"a ref padded with =":                      logo + "=",
			"a ref with a character outside base64url": logo + "!",
		} {
			if res, _ := proxyGet(t, proxy, path, nil); res.StatusCode != http.StatusNotFound {
				t.Errorf("%s: %d, want 404", name, res.StatusCode)
			}
		}
	})

	t.Run("a ref that is not clean base64url is refused whole", func(t *testing.T) {
		proxy, _ := imageProxyServer(t, origin.Client())
		// A destination whose length is a multiple of 3 encodes with no
		// partial group, so a stray character after it is the only fault.
		dest := origin.URL + "/logo.png?"
		for len(dest)%3 != 0 {
			dest += "a"
		}
		clean := signedImagePath(imageProxySealingKey, dest)
		if res, _ := proxyGet(t, proxy, clean, nil); res.StatusCode != http.StatusOK {
			t.Fatalf("the clean ref: %d, want 200", res.StatusCode)
		}
		for _, tail := range []string{"!", "=", "%20"} {
			if res, _ := proxyGet(t, proxy, clean+tail, nil); res.StatusCode != http.StatusNotFound {
				t.Errorf("a ref followed by %q: %d, want 404", tail, res.StatusCode)
			}
		}
	})

	t.Run("only https destinations are fetched", func(t *testing.T) {
		proxy, _ := imageProxyServer(t, origin.Client())
		plain := strings.Replace(origin.URL, "https://", "http://", 1) + "/logo.png"
		if res, _ := proxyGet(t, proxy, signedImagePath(imageProxySealingKey, plain), nil); res.StatusCode != http.StatusNotFound {
			t.Errorf("a signed http destination: %d, want 404", res.StatusCode)
		}
		if res, _ := proxyGet(t, proxy, signedImagePath(imageProxySealingKey, "ftp://images.example/logo.png"), nil); res.StatusCode != http.StatusNotFound {
			t.Errorf("a signed ftp destination: %d, want 404", res.StatusCode)
		}
	})

	t.Run("the destination length limit is exact", func(t *testing.T) {
		proxy, _ := imageProxyServer(t, origin.Client())
		base := origin.URL + "/logo.png?pad="
		exact := base + strings.Repeat("a", 1536-len(base))
		if res, _ := proxyGet(t, proxy, signedImagePath(imageProxySealingKey, exact), nil); res.StatusCode != http.StatusOK {
			t.Errorf("a 1536-byte destination: %d, want 200", res.StatusCode)
		}
		if res, _ := proxyGet(t, proxy, signedImagePath(imageProxySealingKey, exact+"a"), nil); res.StatusCode != http.StatusNotFound {
			t.Errorf("a 1537-byte destination: %d, want 404", res.StatusCode)
		}
	})

	t.Run("raster is re-encoded, anything else refused, limits exact", serveOnlyReencodedRaster)
}

// serveOnlyReencodedRaster checks what the proxy serves for each upstream answer: raster images re-encoded
// from their pixels under a pinned type and an inert policy, everything else
// refused, and the size limits exact.
func serveOnlyReencodedRaster(t *testing.T) {
	const trailer = "<script>alert('from upstream')</script>"
	img := image.NewRGBA(image.Rect(0, 0, 5, 3))
	img.Set(2, 1, color.RGBA{G: 200, A: 255})
	encode := func(t *testing.T, enc func(io.Writer) error) []byte {
		t.Helper()
		var b bytes.Buffer
		if err := enc(&b); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	pngBytes := encode(t, func(w io.Writer) error { return png.Encode(w, img) })
	jpegBytes := encode(t, func(w io.Writer) error { return jpeg.Encode(w, img, nil) })
	gifBytes := encode(t, func(w io.Writer) error { return gif.Encode(w, img, nil) })
	gray := func(w, h int) []byte {
		return encode(t, func(out io.Writer) error { return png.Encode(out, image.NewGray(image.Rect(0, 0, w, h))) })
	}
	atCap := append(append([]byte{}, pngBytes...), make([]byte, 5<<20-len(pngBytes))...)

	var mu sync.Mutex
	var seen []http.Header
	routes := map[string]func(http.ResponseWriter){
		"/png":  func(w http.ResponseWriter) { _, _ = w.Write(append(append([]byte{}, pngBytes...), trailer...)) },
		"/jpeg": func(w http.ResponseWriter) { _, _ = w.Write(append(append([]byte{}, jpegBytes...), trailer...)) },
		"/gif":  func(w http.ResponseWriter) { _, _ = w.Write(append(append([]byte{}, gifBytes...), trailer...)) },
		"/svg-as-png": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = io.WriteString(w, `<svg xmlns="http://www.w3.org/2000/svg"/>`)
		},
		"/html":           func(w http.ResponseWriter) { _, _ = io.WriteString(w, "<html><script>alert(1)</script></html>") },
		"/empty":          func(http.ResponseWriter) {},
		"/webp":           func(w http.ResponseWriter) { _, _ = io.WriteString(w, "RIFF\x00\x00\x00\x00WEBPVP8 ") },
		"/truncated":      func(w http.ResponseWriter) { _, _ = w.Write(pngBytes[:len(pngBytes)/2]) },
		"/not-found":      func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound); _, _ = w.Write(pngBytes) },
		"/server-down":    func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError); _, _ = w.Write(pngBytes) },
		"/at-byte-cap":    func(w http.ResponseWriter) { _, _ = w.Write(atCap) },
		"/over-byte-cap":  func(w http.ResponseWriter) { _, _ = w.Write(append(append([]byte{}, atCap...), 0)) },
		"/at-pixel-cap":   func(w http.ResponseWriter) { _, _ = w.Write(gray(4096, 4096)) },
		"/over-pixel-cap": func(w http.ResponseWriter) { _, _ = w.Write(gray(8192, 2049)) },
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		if serve, ok := routes[r.URL.Path]; ok {
			serve(w)
			return
		}
		http.NotFound(w, r)
	}))
	defer origin.Close()
	proxy, _ := imageProxyServer(t, origin.Client())
	fetch := func(path string) (*http.Response, []byte) {
		return proxyGet(t, proxy, signedImagePath(imageProxySealingKey, origin.URL+path), nil)
	}

	for _, c := range []struct {
		path, ctype string
		decode      func([]byte) (image.Config, error)
	}{
		{"/png", "image/png", func(b []byte) (image.Config, error) { return png.DecodeConfig(bytes.NewReader(b)) }},
		{"/jpeg", "image/jpeg", func(b []byte) (image.Config, error) { return jpeg.DecodeConfig(bytes.NewReader(b)) }},
		{"/gif", "image/gif", func(b []byte) (image.Config, error) { return gif.DecodeConfig(bytes.NewReader(b)) }},
	} {
		t.Run("serves "+c.ctype, func(t *testing.T) {
			res, body := fetch(c.path)
			if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != c.ctype {
				t.Fatalf("%d %q, want 200 %q", res.StatusCode, res.Header.Get("Content-Type"), c.ctype)
			}
			if cfg, err := c.decode(body); err != nil || cfg.Width != 5 || cfg.Height != 3 {
				t.Fatalf("served image: %v %+v, want 5x3", err, cfg)
			}
			if bytes.Contains(body, []byte(trailer)) {
				t.Fatal("the upstream bytes reached the browser")
			}
			for k, v := range map[string]string{
				"X-Content-Type-Options":  "nosniff",
				"Content-Security-Policy": "default-src 'none'; sandbox",
				"Content-Disposition":     "inline",
				"Cache-Control":           "public, max-age=86400, immutable",
			} {
				if got := res.Header.Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
		})
	}

	for _, c := range []struct {
		path string
		want int
	}{
		{"/svg-as-png", http.StatusUnsupportedMediaType},
		{"/html", http.StatusUnsupportedMediaType},
		{"/empty", http.StatusUnsupportedMediaType},
		{"/webp", http.StatusUnsupportedMediaType},
		{"/truncated", http.StatusUnsupportedMediaType},
		{"/not-found", http.StatusBadGateway},
		{"/server-down", http.StatusBadGateway},
		{"/at-byte-cap", http.StatusOK},
		{"/over-byte-cap", http.StatusRequestEntityTooLarge},
		{"/at-pixel-cap", http.StatusOK},
		{"/over-pixel-cap", http.StatusRequestEntityTooLarge},
	} {
		t.Run("upstream "+strings.TrimPrefix(c.path, "/"), func(t *testing.T) {
			res, body := fetch(c.path)
			if res.StatusCode != c.want {
				t.Fatalf("%d, want %d: %.80s", res.StatusCode, c.want, body)
			}
			if c.want != http.StatusOK && strings.Contains(res.Header.Get("Content-Type"), "image/") {
				t.Fatalf("a refusal served as an image: %q", res.Header.Get("Content-Type"))
			}
		})
	}
	t.Run("an unreachable origin", func(t *testing.T) {
		gone := httptest.NewTLSServer(http.NotFoundHandler())
		dest := gone.URL + "/png"
		gone.Close()
		if res, _ := proxyGet(t, proxy, signedImagePath(imageProxySealingKey, dest), nil); res.StatusCode != http.StatusBadGateway {
			t.Fatalf("%d, want 502", res.StatusCode)
		}
	})

	t.Run("nothing identifies the viewer upstream", func(t *testing.T) {
		mu.Lock()
		seen = nil
		mu.Unlock()
		res, _ := proxyGet(t, proxy, signedImagePath(imageProxySealingKey, origin.URL+"/png"), http.Header{
			"Cookie":          {"agentry_session=viewer-session"},
			"Referer":         {"https://registry.test/agents/someone/thing"},
			"Authorization":   {"Bearer viewer-token"},
			"X-Forwarded-For": {"203.0.113.9"},
			"User-Agent":      {"viewer-browser/1"},
		})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%d, want 200", res.StatusCode)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != 1 {
			t.Fatalf("the origin saw %d requests, want 1", len(seen))
		}
		got := seen[0]
		if ua := got.Get("User-Agent"); ua != "agentry-image-proxy/1 (+https://github.com/blaktron/agentry)" {
			t.Errorf("User-Agent = %q", ua)
		}
		if a := got.Get("Accept"); a != "image/png, image/jpeg, image/gif" {
			t.Errorf("Accept = %q", a)
		}
		for _, h := range []string{"Cookie", "Referer", "Authorization", "X-Forwarded-For"} {
			if v := got.Get(h); v != "" {
				t.Errorf("the viewer's %s reached the origin: %q", h, v)
			}
		}
	})
}

// The proxy reaches the network only through the egress guard: with its own
// client, a destination on a private, loopback, link-local or metadata
// address is refused before anything is sent, answered 502, and logged.
func TestImageProxyRefusesPrivateDestinations(t *testing.T) {
	var hits sync.Mutex
	var reached []string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Lock()
		reached = append(reached, r.URL.Path)
		hits.Unlock()
		w.Header().Set("Content-Type", "image/png")
		var b bytes.Buffer
		_ = png.Encode(&b, image.NewGray(image.Rect(0, 0, 1, 1)))
		_, _ = w.Write(b.Bytes())
	}))
	defer origin.Close()
	proxy, logs := imageProxyServer(t, nil)
	for _, dest := range []string{
		origin.URL + "/logo.png",
		"https://10.0.0.1/logo.png",
		"https://192.168.1.10/logo.png",
		"https://169.254.169.254/latest/meta-data/",
		"https://[::1]/logo.png",
		"https://[::ffff:10.0.0.1]/logo.png",
	} {
		t.Run(dest, func(t *testing.T) {
			res, body := proxyGet(t, proxy, signedImagePath(imageProxySealingKey, dest), nil)
			if res.StatusCode != http.StatusBadGateway || strings.TrimSpace(string(body)) != "image unavailable" {
				t.Fatalf("%d %q, want 502 image unavailable", res.StatusCode, body)
			}
		})
	}
	hits.Lock()
	defer hits.Unlock()
	if len(reached) != 0 {
		t.Fatalf("a private destination was requested: %v", reached)
	}
	var refused int
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["event"] == "ssrf.refused" && m["level"] == "WARN" {
			refused++
		}
	}
	if refused != 6 {
		t.Fatalf("ssrf.refused lines = %d, want one per refused destination (6):\n%s", refused, logs.String())
	}
}

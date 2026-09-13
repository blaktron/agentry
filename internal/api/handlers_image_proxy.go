package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/webhook"
)

// Camo-style image proxy (§10.3 "images proxied and re-encoded so no visitor
// browser makes a third-party request"; DEV-049.1 → agentry#64).
//
//   - The renderer rewrites absolute image URLs in READMEs to
//     /api/v1/img/<sig>/<ref>: ref is the base64url URL, sig an HMAC over it
//     under a key derived from the sealing key. Only URLs the registry
//     itself rendered can be fetched — this is not an open proxy.
//   - Fetches go through the webhook SSRF guard (public unicast only, every
//     redirect hop), with a time limit and a byte cap.
//   - Only raster formats the standard library decodes (PNG, JPEG, GIF) are
//     served, always re-encoded — upstream bytes never reach a browser. SVG
//     and everything else is refused (415).
//   - Responses are edge-cacheable; nothing identifies the viewer upstream.

const (
	imgMaxBytes  = 5 << 20
	imgMaxPixels = 4096 * 4096
	imgTimeout   = 8 * time.Second
)

func (s *Server) imgProxyKey() []byte {
	sum := sha256.Sum256([]byte("img-proxy:" + s.cfg.Auth.SealingKey))
	return sum[:]
}

func imgSig(key []byte, dest string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(dest))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
}

// imageProxyURL signs dest for the renderer; false for non-http(s) or
// over-long destinations, which then stay placeholders.
func (s *Server) imageProxyURL(dest string) (string, bool) {
	if len(dest) > 1536 {
		return "", false
	}
	u, err := url.Parse(dest)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	// Absolute on the registry's own origin: the sanitizer admits URL
	// attributes by scheme, and the page's img-src 'self' still applies.
	origin := strings.TrimRight(s.cfg.BaseURL, "/")
	if origin == "" {
		return "", false
	}
	return origin + "/api/v1/img/" + imgSig(s.imgProxyKey(), dest) + "/" + base64.RawURLEncoding.EncodeToString([]byte(dest)), true
}

func (s *Server) imageProxyClient() *http.Client {
	if s.imgHTTPClient != nil {
		return s.imgHTTPClient
	}
	c := webhook.NewHTTPClient(webhook.Guard{}, nil)
	c.Timeout = imgTimeout
	return c
}

// serveImageProxy implements GET /api/v1/img/{sig}/{ref}.
func (s *Server) serveImageProxy(w http.ResponseWriter, r *http.Request) {
	sig, ref := r.PathValue("sig"), r.PathValue("ref")
	raw, err := base64.RawURLEncoding.DecodeString(ref)
	if err != nil || len(raw) == 0 || len(raw) > 1536 {
		http.NotFound(w, r)
		return
	}
	dest := string(raw)
	if !hmac.Equal([]byte(sig), []byte(imgSig(s.imgProxyKey(), dest))) {
		http.NotFound(w, r)
		return
	}
	u, err := url.Parse(dest)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.NotFound(w, r)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, dest, nil)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	req.Header.Set("User-Agent", "agentry-image-proxy/1 (+https://github.com/blaktron/agentry)")
	req.Header.Set("Accept", "image/png, image/jpeg, image/gif")
	res, err := s.imageProxyClient().Do(req)
	if err != nil {
		var blocked *webhook.ErrBlockedAddress
		if errors.As(err, &blocked) {
			s.log.WarnContext(r.Context(), "image proxy: target refused by the private-range guard", logevent.SSRFRefused.Attr(), "host", blocked.Host)
		}
		http.Error(w, "image unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		http.Error(w, "image unavailable", http.StatusBadGateway)
		return
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, imgMaxBytes+1))
	if err != nil {
		http.Error(w, "image unavailable", http.StatusBadGateway)
		return
	}
	if len(body) > imgMaxBytes {
		http.Error(w, "image too large", http.StatusRequestEntityTooLarge)
		return
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		http.Error(w, "unsupported image format", http.StatusUnsupportedMediaType)
		return
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > imgMaxPixels {
		http.Error(w, "image too large", http.StatusRequestEntityTooLarge)
		return
	}
	var out bytes.Buffer
	var ctype string
	switch format {
	case "gif":
		g, err := gif.DecodeAll(bytes.NewReader(body))
		if err != nil || len(g.Image) == 0 {
			http.Error(w, "unsupported image format", http.StatusUnsupportedMediaType)
			return
		}
		if err := gif.EncodeAll(&out, g); err != nil {
			http.Error(w, "image unavailable", http.StatusBadGateway)
			return
		}
		ctype = "image/gif"
	case "jpeg":
		img, err := jpeg.Decode(bytes.NewReader(body))
		if err != nil {
			http.Error(w, "unsupported image format", http.StatusUnsupportedMediaType)
			return
		}
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 85}); err != nil {
			http.Error(w, "image unavailable", http.StatusBadGateway)
			return
		}
		ctype = "image/jpeg"
	case "png":
		img, err := png.Decode(bytes.NewReader(body))
		if err != nil {
			http.Error(w, "unsupported image format", http.StatusUnsupportedMediaType)
			return
		}
		if err := png.Encode(&out, img); err != nil {
			http.Error(w, "image unavailable", http.StatusBadGateway)
			return
		}
		ctype = "image/png"
	default:
		http.Error(w, "unsupported image format", http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", "inline")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Bytes())
}

package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
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

// newImgProxyKey derives the proxy's signing key. The signature is the
// route's only gate, so the key must never be a value the open-source tree
// gives away: with a sealing key it is derived from that, as before; with
// none — which only dev mode permits, the sealer having refused to start
// otherwise — it is a random per-process key. It used to be
// sha256("img-proxy:") in that case, and anyone could sign any destination
// (security review 2026-09-20 §5.1). Signatures are minted at render time
// and never stored, so a key that changes at restart costs at most a
// cached page's images until the edge revalidates.
func newImgProxyKey(sealingKey string) []byte {
	if sealingKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic(fmt.Sprintf("image proxy: no entropy for the signing key: %v", err))
		}
		return key
	}
	sum := sha256.Sum256([]byte("img-proxy:" + sealingKey))
	return sum[:]
}

func (s *Server) imgProxyKey() []byte { return s.imgKey }

func imgSig(key []byte, dest string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(dest))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:32]
}

// imageProxyURL signs dest for the renderer; false for non-https or
// over-long destinations, which then stay placeholders. https only: a
// signed destination is a GET the registry makes on a publisher's say-so,
// and it is never a cleartext one.
func (s *Server) imageProxyURL(dest string) (string, bool) {
	if len(dest) > 1536 {
		return "", false
	}
	u, err := url.Parse(dest)
	if err != nil || u.Scheme != "https" || u.Host == "" {
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
	if err != nil || u.Scheme != "https" {
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
	out, ctype, err := reencodeRaster(body, rasterGIF|rasterJPEG|rasterPNG)
	switch {
	case errors.Is(err, errRasterUnsupported):
		http.Error(w, "unsupported image format", http.StatusUnsupportedMediaType)
		return
	case errors.Is(err, errRasterTooLarge):
		http.Error(w, "image too large", http.StatusRequestEntityTooLarge)
		return
	case err != nil:
		http.Error(w, "image unavailable", http.StatusBadGateway)
		return
	}
	writeRaster(w, out, ctype, "public, max-age=86400, immutable")
}

// rasterFormats names which of the standard library's decoders a caller
// admits. The proxy takes all three; a logo takes PNG and JPEG only, since
// an animated GIF is not a logo.
type rasterFormats uint8

const (
	rasterGIF rasterFormats = 1 << iota
	rasterJPEG
	rasterPNG
)

var (
	// errRasterUnsupported is a format no admitted decoder reads: SVG and
	// everything else. There is no sanitiser for SVG in this repository
	// and there will not be one by accident; a refused format is a 415.
	errRasterUnsupported = errors.New("unsupported image format")
	// errRasterTooLarge is more pixels than the decoder may allocate.
	errRasterTooLarge = errors.New("image too large")
)

// reencodeRaster decodes body with the standard library and encodes it
// again from the decoded pixels, so the bytes a browser receives were
// written by this process and never by whoever supplied the upload
// (§10.3; DEV-049.1). The image proxy and the organization logo
// (agentry#367) share it: one path, one set of refusals. The format is
// what the bytes are, not what a header or a file name claimed.
func reencodeRaster(body []byte, admit rasterFormats) ([]byte, string, error) {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(body))
	if err != nil {
		return nil, "", errRasterUnsupported
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > imgMaxPixels {
		return nil, "", errRasterTooLarge
	}
	var out bytes.Buffer
	switch {
	case format == "gif" && admit&rasterGIF != 0:
		g, err := gif.DecodeAll(bytes.NewReader(body))
		if err != nil || len(g.Image) == 0 {
			return nil, "", errRasterUnsupported
		}
		if err := gif.EncodeAll(&out, g); err != nil {
			return nil, "", err
		}
		return out.Bytes(), "image/gif", nil
	case format == "jpeg" && admit&rasterJPEG != 0:
		img, err := jpeg.Decode(bytes.NewReader(body))
		if err != nil {
			return nil, "", errRasterUnsupported
		}
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 85}); err != nil {
			return nil, "", err
		}
		return out.Bytes(), "image/jpeg", nil
	case format == "png" && admit&rasterPNG != 0:
		img, err := png.Decode(bytes.NewReader(body))
		if err != nil {
			return nil, "", errRasterUnsupported
		}
		if err := png.Encode(&out, img); err != nil {
			return nil, "", err
		}
		return out.Bytes(), "image/png", nil
	}
	return nil, "", errRasterUnsupported
}

// writeRaster serves re-encoded pixels the only way this registry serves
// an image: the type pinned and not sniffed, nothing but the image
// allowed to run or load from it, inline, and cacheable as the caller
// says.
func writeRaster(w http.ResponseWriter, out []byte, ctype, cacheControl string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Content-Security-Policy", inertDocumentCSP)
	w.Header().Set("Content-Disposition", "inline")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

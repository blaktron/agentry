package api_test

// The organization's logo (agentry#367, M17; plan
// organization-subscriptions.md §5.9, D17): uploaded by an admin behind
// Features.Branding, decoded and encoded again through the image proxy's
// path so the upload's bytes are never served, stored under the
// organization, served with a pinned type and a content-versioned URL.
// Never SVG: there is no sanitiser, and the refusal is what stands in.

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/entitlements"
)

// tinyPNG is a 4×4 PNG with a distinctive pixel, so a re-encode can be
// told apart from the upload by bytes and told the same by pixels.
func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	img.Set(1, 2, color.NRGBA{R: 200, G: 30, B: 40, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	// A private chunk after IEND would survive a byte copy and never a
	// decode: the mark that the served bytes were written by the server.
	return append(b.Bytes(), []byte("\x00\x00\x00\x04tEXtSMUGGLED")...)
}

func tinyJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

const tinySVG = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`

// putLogo uploads bytes as the one multipart part and returns the status
// and the body.
func putLogo(t *testing.T, env *testEnv, who caller, org string, body []byte, filename string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, _ := mw.CreateFormFile("file", filename)
	_, _ = part.Write(body)
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPut, env.srv.URL+"/api/v1/orgs/"+org+"/logo", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if who.pat != "" {
		req.Header.Set("Authorization", "Bearer "+who.pat)
	} else if who.session != "" {
		req.AddCookie(&http.Cookie{Name: "agentry_session", Value: who.session})
		req.Header.Set("X-Agentry-CSRF", who.csrf)
	}
	res, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	rb, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(rb)
}

func getLogo(t *testing.T, env *testEnv, org string) (*http.Response, []byte) {
	t.Helper()
	res, err := env.srv.Client().Get(env.srv.URL + "/api/v1/orgs/" + org + "/logo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	return res, body
}

func TestOrgLogoIsReencodedStoredAndServed(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("lg-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "lgorg" + env.sfx
	env.createOrg(admin, orgH)

	// None yet: the resource carries no URL, the route is a 404.
	var o struct {
		LogoUrl *string `json:"logoUrl"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &o, http.StatusOK)
	if o.LogoUrl != nil {
		t.Fatalf("a new organization has a logo URL: %q", *o.LogoUrl)
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusNotFound {
		t.Fatalf("no logo: got %d want 404", res.StatusCode)
	}

	// Upload a PNG with a smuggled trailer. What is served decodes to the
	// same pixels and is not the same bytes: the trailer is gone.
	upload := tinyPNG(t)
	code, body := putLogo(t, env, admin, orgH, upload, "logo.png")
	if code != http.StatusOK || !strings.Contains(body, `"logoUrl"`) {
		t.Fatalf("upload: %d %s", code, body)
	}
	res, served := getLogo(t, env, orgH)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("serve: got %d", res.StatusCode)
	}
	if bytes.Equal(served, upload) {
		t.Fatal("the upload's bytes were served as delivered")
	}
	if bytes.Contains(served, []byte("SMUGGLED")) {
		t.Fatal("the upload's trailer survived into what is served")
	}
	img, err := png.Decode(bytes.NewReader(served))
	if err != nil {
		t.Fatalf("served logo does not decode as PNG: %v", err)
	}
	if c := img.At(1, 2); !colorClose(c, color.NRGBA{R: 200, G: 30, B: 40, A: 255}) {
		t.Fatalf("the pixels changed: %v", c)
	}
	for k, want := range map[string]string{
		"Content-Type":            "image/png",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Content-Disposition":     "inline",
	} {
		if got := res.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") || !strings.Contains(cc, "max-age=31536000") {
		t.Errorf("Cache-Control = %q, want a year, immutable", cc)
	}

	// The resource and a search hit carry the URL, versioned by content.
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &o, http.StatusOK)
	if o.LogoUrl == nil || !strings.HasPrefix(*o.LogoUrl, "/api/v1/orgs/"+orgH+"/logo?v=") {
		t.Fatalf("resource logoUrl = %v", o.LogoUrl)
	}
	first := *o.LogoUrl

	// Replace with a JPEG: a new URL, the old object gone, JPEG served.
	code, _ = putLogo(t, env, admin, orgH, tinyJPEG(t), "photo.jpg")
	if code != http.StatusOK {
		t.Fatalf("replace: %d", code)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &o, http.StatusOK)
	if o.LogoUrl == nil || *o.LogoUrl == first {
		t.Fatalf("a replaced logo kept its URL: %v", o.LogoUrl)
	}
	res, served = getLogo(t, env, orgH)
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatalf("replaced logo: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if _, err := jpeg.Decode(bytes.NewReader(served)); err != nil {
		t.Fatalf("served logo does not decode as JPEG: %v", err)
	}

	// Remove: 204, then 404, and the resource carries no URL. Removing
	// nothing is done.
	res2 := env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/logo", nil)
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusNoContent {
		t.Fatalf("remove: %d", res2.StatusCode)
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusNotFound {
		t.Fatalf("after removal: got %d want 404", res.StatusCode)
	}
	o.LogoUrl = nil // the answer omits the field; a reused value would keep the old one
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &o, http.StatusOK)
	if o.LogoUrl != nil {
		t.Fatalf("after removal the resource still carries %q", *o.LogoUrl)
	}
	res2 = env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/logo", nil)
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusNoContent {
		t.Fatalf("remove again: %d", res2.StatusCode)
	}
}

func colorClose(a color.Color, want color.NRGBA) bool {
	r, g, b, _ := a.RGBA()
	near := func(x uint32, y uint8) bool {
		d := int(x>>8) - int(y)
		return d >= -2 && d <= 2
	}
	return near(r, want.R) && near(g, want.G) && near(b, want.B)
}

func TestOrgLogoRefusesWhatItCannotMakeSafe(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("lgr-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "lgrorg" + env.sfx
	env.createOrg(admin, orgH)

	// SVG, however it is named: 415, and nothing stored.
	for _, name := range []string{"logo.svg", "logo.png"} {
		code, body := putLogo(t, env, admin, orgH, []byte(tinySVG), name)
		if code != http.StatusUnsupportedMediaType || !strings.Contains(body, "unsupported-image") {
			t.Fatalf("SVG as %s: %d %s", name, code, body)
		}
	}
	// A GIF is a raster the proxy serves and a logo does not: 415.
	if code, _ := putLogo(t, env, admin, orgH, gifBytes(), "logo.gif"); code != http.StatusUnsupportedMediaType {
		t.Fatalf("GIF: %d", code)
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusNotFound {
		t.Fatalf("a refused upload left a logo: %d", res.StatusCode)
	}

	// Over the size cap: 413 before a byte is decoded.
	big := append(tinyPNG(t), bytes.Repeat([]byte{0}, 300<<10)...)
	if code, body := putLogo(t, env, admin, orgH, big, "big.png"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("300 KB: %d %s", code, body)
	}

	// Not an admin: a member may not set it, and nobody outside may.
	memberH := env.register("lgr-member")
	env.verifyEmail(memberH)
	env.seedMembership(orgH, memberH, "member", "active")
	if code, _ := putLogo(t, env, env.login(memberH), orgH, tinyPNG(t), "logo.png"); code != http.StatusForbidden {
		t.Fatalf("a member set the logo: %d", code)
	}
	outsiderH := env.register("lgr-outsider")
	env.verifyEmail(outsiderH)
	if code, _ := putLogo(t, env, env.login(outsiderH), orgH, tinyPNG(t), "logo.png"); code != http.StatusForbidden {
		t.Fatalf("an outsider set the logo: %d", code)
	}
	if code, _ := putLogo(t, env, anonymous, orgH, tinyPNG(t), "logo.png"); code != http.StatusUnauthorized {
		t.Fatalf("anonymous set the logo: %d", code)
	}
}

// gifBytes is the smallest valid GIF.
func gifBytes() []byte {
	return []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")
}

// The tier decides: without branding the upload is refused with the
// reason, and a logo already set is left as it is — nothing is deleted by
// a subscription change.
func TestOrgLogoIsGatedOnTheTier(t *testing.T) {
	env := newTestEnvWith(t, onTier(func(f *entitlements.Features) { f.Branding = false }))
	adminH := env.register("lgt-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "lgtorg" + env.sfx
	env.createOrg(admin, orgH)

	code, body := putLogo(t, env, admin, orgH, tinyPNG(t), "logo.png")
	if code != http.StatusForbidden || !strings.Contains(body, "feature-not-included") {
		t.Fatalf("without branding: %d %s", code, body)
	}

	// With it, set; without it again, still served and still removable.
	env.setEntitlements(tierResolverFor(func(f *entitlements.Features) { f.Branding = true }))
	if code, _ := putLogo(t, env, admin, orgH, tinyPNG(t), "logo.png"); code != http.StatusOK {
		t.Fatalf("with branding: %d", code)
	}
	env.setEntitlements(tierResolverFor(func(f *entitlements.Features) { f.Branding = false }))
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusOK {
		t.Fatalf("a downgrade removed the logo: %d", res.StatusCode)
	}
	res := env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/logo", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("removing after a downgrade: %d — configuration the organization owns must stay removable", res.StatusCode)
	}

	// An unknown entitlement refuses the upload, as every gate does.
	env.setEntitlements(brokenTierResolver())
	if code, _ := putLogo(t, env, admin, orgH, tinyPNG(t), "logo.png"); code < 400 {
		t.Fatalf("an unknown entitlement admitted an upload: %d", code)
	}
}

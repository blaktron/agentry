package api_test

// The organization's logo: uploaded by an admin behind
// Features.Branding, decoded and encoded again through the image proxy's
// path so the upload's bytes are never served, stored under the
// organization, served with a pinned type and a content-versioned URL.
// Never SVG: there is no sanitiser, and the refusal is what stands in.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
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

// tinyGIF is a raster the proxy serves and a logo does not.
func tinyGIF(t *testing.T) []byte {
	t.Helper()
	img := image.NewPaletted(image.Rect(0, 0, 1, 1), color.Palette{color.Black, color.White})
	var b bytes.Buffer
	if err := gif.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// putLogo uploads bytes as the one multipart part and returns the status
// and the body.
func putLogo(t *testing.T, env *testEnv, who caller, org string, body []byte, filename string) (int, string) {
	t.Helper()
	return putLogoPart(t, env, who, org, "file", filename, body)
}

// putLogoPart is putLogo with the part's form field named.
func putLogoPart(t *testing.T, env *testEnv, who caller, org, field, filename string, body []byte) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, _ := mw.CreateFormFile(field, filename)
	_, _ = part.Write(body)
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPut, env.srv.URL+"/api/v1/orgs/"+org+"/logo", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	env.authenticate(req, who)
	res, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	rb, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(rb)
}

// pngClaiming is a PNG signature and header that claim w by h pixels
// (8-bit grey) and carry nothing else: enough for the decoder to read
// the size and not enough to decode.
func pngClaiming(w, h uint32) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8] = 8
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	_ = binary.Write(&b, binary.BigEndian, uint32(len(ihdr)))
	b.WriteString("IHDR")
	b.Write(ihdr)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte("IHDR"), ihdr...)))
	return b.Bytes()
}

// logoKeyOf is the object key the organization's row names for its logo, or "" for none.
func logoKeyOf(t *testing.T, env *testEnv, org string) string {
	t.Helper()
	var key *string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT o.logo_object_key FROM orgs o JOIN handles h ON h.id = o.id WHERE h.handle = $1`, org).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if key == nil {
		return ""
	}
	return *key
}

// setLogoKey writes a key straight into the organization's row ("" for
// none), for a row that names what the upload route never wrote.
func setLogoKey(t *testing.T, env *testEnv, org, key string) {
	t.Helper()
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE orgs SET logo_object_key = NULLIF($2, '') WHERE id = (SELECT id FROM handles WHERE handle = $1)`, org, key); err != nil {
		t.Fatal(err)
	}
}

// logoAudit is one logo event of the organization's audit log.
type logoAudit struct {
	Action string
	Detail map[string]any
}

// orgLogoAudit is every logo event recorded against the organization,
// oldest first.
func orgLogoAudit(t *testing.T, env *testEnv, org string) []logoAudit {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT a.action, a.detail FROM audit_events a JOIN handles h ON h.id = a.org_id
		 WHERE h.handle = $1 AND a.action LIKE 'org.logo_%' ORDER BY a.occurred_at, a.id`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []logoAudit
	for rows.Next() {
		var a logoAudit
		var detail []byte
		if err := rows.Scan(&a.Action, &detail); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(detail, &a.Detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
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
	orgID := env.createOrg(admin, orgH)
	blobs := env.srvObj.Blobs()
	ctx := context.Background()

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
	servedPNG := served
	img, err := png.Decode(bytes.NewReader(served))
	if err != nil {
		t.Fatalf("served logo does not decode as PNG: %v", err)
	}
	// PNG is lossless and an opaque NRGBA pixel round-trips exactly.
	if c := color.NRGBAModel.Convert(img.At(1, 2)); c != (color.NRGBA{R: 200, G: 30, B: 40, A: 255}) {
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
	// The bare path is answered but not kept: nothing enforces that a
	// link carried the version, and a browser holding the bare path as
	// immutable would show a replaced logo for a year.
	if cc := res.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("bare path Cache-Control = %q, want no-cache", cc)
	}

	// The resource carries the URL, versioned by content, and that URL —
	// and only that URL — is served as immutable for a year.
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &o, http.StatusOK)
	if o.LogoUrl == nil || !strings.HasPrefix(*o.LogoUrl, "/api/v1/orgs/"+orgH+"/logo?v=") {
		t.Fatalf("resource logoUrl = %v", o.LogoUrl)
	}
	first := *o.LogoUrl
	// The upload's answer is that same URL, and the version in it is the
	// first 16 hex characters of the digest of what is served, which is
	// also the name of the stored object, under the organization.
	var put struct {
		LogoUrl string `json:"logoUrl"`
	}
	if err := json.Unmarshal([]byte(body), &put); err != nil || put.LogoUrl != first {
		t.Fatalf("the upload answered %q (%v), the resource carries %q", put.LogoUrl, err, first)
	}
	servedSum := sha256.Sum256(served)
	servedHex := hex.EncodeToString(servedSum[:])
	if want := "/api/v1/orgs/" + orgH + "/logo?v=" + servedHex[:16]; first != want {
		t.Fatalf("logoUrl = %q, want %q", first, want)
	}
	pngKey := logoKeyOf(t, env, orgH)
	if want := "orgs/" + orgID + "/logo/" + servedHex + ".png"; pngKey != want {
		t.Fatalf("stored logo key = %q, want %q", pngKey, want)
	}
	vres, err := env.srv.Client().Get(env.srv.URL + first)
	if err != nil {
		t.Fatal(err)
	}
	_ = vres.Body.Close()
	if cc := vres.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") || !strings.Contains(cc, "max-age=31536000") {
		t.Errorf("versioned URL Cache-Control = %q, want a year, immutable", cc)
	}
	sres, err := env.srv.Client().Get(env.srv.URL + "/api/v1/orgs/" + orgH + "/logo?v=notthisone")
	if err != nil {
		t.Fatal(err)
	}
	_ = sres.Body.Close()
	if cc := sres.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("a stale version's Cache-Control = %q, want no-cache", cc)
	}

	// Replace with a JPEG: a new URL, the old object gone, JPEG served.
	// The format is what the bytes are: a JPEG sent under a .png name is
	// stored and served as a JPEG.
	code, _ = putLogo(t, env, admin, orgH, tinyJPEG(t), "photo.png")
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
	jpegKey := logoKeyOf(t, env, orgH)
	if !strings.HasPrefix(jpegKey, "orgs/"+orgID+"/logo/") || !strings.HasSuffix(jpegKey, ".jpg") {
		t.Fatalf("stored JPEG key = %q", jpegKey)
	}
	if gone, err := blobs.Exists(ctx, pngKey); err != nil || gone {
		t.Fatalf("the replaced logo's object still exists (%v, %v)", gone, err)
	}
	if kept, err := blobs.Exists(ctx, jpegKey); err != nil || !kept {
		t.Fatalf("the new logo's object is not stored (%v, %v)", kept, err)
	}
	// The same image again is the same object: it is neither a new URL nor
	// the replaced object deleted under the row that names it.
	again := *o.LogoUrl
	if code, _ := putLogo(t, env, admin, orgH, tinyJPEG(t), "photo.jpg"); code != http.StatusOK {
		t.Fatalf("upload of the same logo again: %d", code)
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &o, http.StatusOK)
	if o.LogoUrl == nil || *o.LogoUrl != again || logoKeyOf(t, env, orgH) != jpegKey {
		t.Fatalf("the same logo again changed the URL: %v, want %q", o.LogoUrl, again)
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusOK {
		t.Fatalf("the same logo again left the row naming a deleted object: %d", res.StatusCode)
	}
	if kept, err := blobs.Exists(ctx, jpegKey); err != nil || !kept {
		t.Fatalf("the same logo again deleted its own object (%v, %v)", kept, err)
	}

	// Remove: 204, then 404, and the resource carries no URL. Removing
	// nothing is done.
	res2 := env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/logo", nil)
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusNoContent {
		t.Fatalf("remove: %d", res2.StatusCode)
	}
	if gone, err := blobs.Exists(ctx, jpegKey); err != nil || gone {
		t.Fatalf("a removed logo's object still exists (%v, %v)", gone, err)
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

	// Each change is in the organization's audit log, with what it set or
	// removed; removing nothing records nothing.
	events := orgLogoAudit(t, env, orgH)
	wantActions := []string{"org.logo_set", "org.logo_set", "org.logo_set", "org.logo_removed"}
	if len(events) != len(wantActions) {
		t.Fatalf("logo audit = %+v, want %v", events, wantActions)
	}
	for i, want := range wantActions {
		if events[i].Action != want {
			t.Fatalf("logo audit = %+v, want %v", events, wantActions)
		}
	}
	if d := events[0].Detail; d["key"] != pngKey || d["type"] != "image/png" || d["bytes"] != float64(len(servedPNG)) {
		t.Fatalf("the first set recorded %v, want key %q, type image/png, %d bytes", d, pngKey, len(servedPNG))
	}
	if d := events[1].Detail; d["key"] != jpegKey || d["type"] != "image/jpeg" || d["bytes"] != float64(len(served)) {
		t.Fatalf("the JPEG set recorded %v, want key %q, type image/jpeg, %d bytes", d, jpegKey, len(served))
	}
	if d := events[3].Detail; d["key"] != jpegKey {
		t.Fatalf("the removal recorded %v, want key %q", d, jpegKey)
	}

	// A row that names what the upload route never wrote is no logo to
	// serve: a key outside the organization's prefix, an object that is
	// gone, and an object larger than any re-encode could have produced
	// (served in part it would not match the digest in its URL).
	digest := strings.Repeat("ab", 32)
	for _, c := range []struct {
		name, key string
		object    []byte
		want      int
	}{
		{"a key outside orgs/", "elsewhere/" + orgID + "/logo/" + digest + ".png", servedPNG, http.StatusNotFound},
		{"an object that is gone", "orgs/" + orgID + "/logo/" + digest + ".png", nil, http.StatusNotFound},
		{"an object over the served bound", "orgs/" + orgID + "/logo/" + digest + ".png", make([]byte, 4*(256<<10)+1), http.StatusInternalServerError},
	} {
		if c.object != nil {
			if err := blobs.Put(ctx, c.key, bytes.NewReader(c.object)); err != nil {
				t.Fatal(err)
			}
		}
		setLogoKey(t, env, orgH, c.key)
		if res, _ := getLogo(t, env, orgH); res.StatusCode != c.want {
			t.Errorf("%s: got %d want %d", c.name, res.StatusCode, c.want)
		}
		_ = blobs.Delete(ctx, c.key)
	}
	setLogoKey(t, env, orgH, "")
}

// A search hit for an organization's agent carries the organization's
// logo, versioned as the resource carries it; a person's namespace and an
// organization without one carry nothing.
func TestSearchHitCarriesTheOrganizationsLogo(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("lgs-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "lgsorg" + env.sfx
	env.createOrg(admin, orgH)
	// Search lists published agents only, so each goes through the
	// pipeline; the term is the name, which is unique to this test.
	name := "logo-hit-" + env.sfx
	env.publishSearchable(t, admin, orgH, name, "an agent with a logo beside it", "# "+name)
	env.publishSearchable(t, admin, adminH, name, "an agent with no logo beside it", "# "+name)

	type hit struct {
		Namespace string  `json:"namespace"`
		LogoUrl   *string `json:"logoUrl"`
	}
	find := func(ns string) *hit {
		t.Helper()
		var out struct {
			Results []hit `json:"results"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/search?q="+name+"&limit=100", nil, &out, http.StatusOK)
		for i := range out.Results {
			if out.Results[i].Namespace == ns {
				return &out.Results[i]
			}
		}
		t.Fatalf("no hit in %s for %q: %+v", ns, name, out.Results)
		return nil
	}

	if h := find(orgH); h.LogoUrl != nil {
		t.Fatalf("an organization without a logo carries one on a hit: %q", *h.LogoUrl)
	}
	if code, _ := putLogo(t, env, admin, orgH, tinyPNG(t), "logo.png"); code != http.StatusOK {
		t.Fatalf("upload: %d", code)
	}
	var o struct {
		LogoUrl *string `json:"logoUrl"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &o, http.StatusOK)
	h := find(orgH)
	if h.LogoUrl == nil || o.LogoUrl == nil || *h.LogoUrl != *o.LogoUrl {
		t.Fatalf("the hit's logoUrl = %v, the resource's = %v; want the same versioned URL", h.LogoUrl, o.LogoUrl)
	}
	if h := find(adminH); h.LogoUrl != nil {
		t.Fatalf("a person's namespace carries a logo on a hit: %q", *h.LogoUrl)
	}
}

func TestOrgLogoRefusesWhatItCannotMakeSafe(t *testing.T) {
	env := newTestEnv(t)
	adminH := env.register("lgr-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "lgrorg" + env.sfx
	orgID := env.createOrg(admin, orgH)

	// SVG, however it is named: 415, and nothing stored.
	for _, name := range []string{"logo.svg", "logo.png"} {
		code, body := putLogo(t, env, admin, orgH, []byte(tinySVG), name)
		if code != http.StatusUnsupportedMediaType || !strings.Contains(body, "unsupported-image") {
			t.Fatalf("SVG as %s: %d %s", name, code, body)
		}
	}
	// A GIF is a raster the proxy serves and a logo does not: 415.
	if code, _ := putLogo(t, env, admin, orgH, tinyGIF(t), "logo.gif"); code != http.StatusUnsupportedMediaType {
		t.Fatalf("GIF: %d", code)
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusNotFound {
		t.Fatalf("a refused upload left a logo: %d", res.StatusCode)
	}

	// Over the size cap: 413 before a byte is decoded.
	big := append(tinyPNG(t), bytes.Repeat([]byte{0}, 300<<10)...)
	if code, body := putLogo(t, env, admin, orgH, big, "big.png"); code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "upload-too-large") {
		t.Fatalf("300 KB: %d %s", code, body)
	}
	// The cap is exact: 256 KB is taken and one byte more is not. The
	// request's own framing is allowed for, so a full-size file is not
	// refused for its boundary lines; a file name long enough to eat the
	// allowance is refused as a whole.
	atCap := tinyPNG(t)
	atCap = append(atCap, bytes.Repeat([]byte{0}, 256<<10-len(atCap))...)
	if code, body := putLogo(t, env, admin, orgH, atCap, "cap.png"); code != http.StatusOK {
		t.Fatalf("exactly 256 KB: %d %s", code, body)
	}
	if code, body := putLogo(t, env, admin, orgH, append(atCap, 0), "cap.png"); code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "upload-too-large") {
		t.Fatalf("256 KB and a byte: %d %s", code, body)
	}
	if code, body := putLogo(t, env, admin, orgH, atCap, strings.Repeat("n", 2048)+".png"); code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "upload-too-large") {
		t.Fatalf("256 KB under a 2 KB file name: %d %s", code, body)
	}

	// The decoder's pixel cap is exact too: 4096 by 4096 is taken, a column
	// more is 413 on the header alone.
	var full bytes.Buffer
	if err := png.Encode(&full, image.NewGray(image.Rect(0, 0, 4096, 4096))); err != nil {
		t.Fatal(err)
	}
	if code, body := putLogo(t, env, admin, orgH, full.Bytes(), "full.png"); code != http.StatusOK {
		t.Fatalf("4096 by 4096: %d %s", code, body)
	}
	if code, body := putLogo(t, env, admin, orgH, pngClaiming(4097, 4096), "wide.png"); code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "upload-too-large") {
		t.Fatalf("4097 by 4096: %d %s", code, body)
	}

	// An image that names a format and cannot be decoded as it is not a
	// logo: 415, never a server error.
	jpegBytes := tinyJPEG(t)
	for name, cut := range map[string][]byte{"PNG": tinyPNG(t)[:40], "JPEG": jpegBytes[:len(jpegBytes)-5]} {
		if code, body := putLogo(t, env, admin, orgH, cut, "cut.img"); code != http.StatusUnsupportedMediaType || !strings.Contains(body, "unsupported-image") {
			t.Fatalf("a %s cut short: %d %s", name, code, body)
		}
	}

	// What is not one multipart part named file is a 400: an empty file,
	// a part under another name, a body that is not multipart at all.
	for _, c := range []struct {
		name, field string
		body        []byte
	}{
		{"an empty file", "file", nil},
		{"a part named logo", "logo", tinyPNG(t)},
	} {
		if code, body := putLogoPart(t, env, admin, orgH, c.field, "logo.png", c.body); code != http.StatusBadRequest || !strings.Contains(body, "bad-request") {
			t.Fatalf("%s: %d %s", c.name, code, body)
		}
	}
	notMultipart := env.do(admin, http.MethodPut, "/api/v1/orgs/"+orgH+"/logo", map[string]any{"file": "logo"})
	_ = notMultipart.Body.Close()
	if notMultipart.StatusCode != http.StatusBadRequest {
		t.Fatalf("a body that is not multipart: %d", notMultipart.StatusCode)
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

	// Removing it is the admins' too: a logo is in place (the 256 KB one),
	// and a member, an outsider and anonymous leave it there.
	for _, c := range []struct {
		who  caller
		want int
	}{{env.login(memberH), http.StatusForbidden}, {env.login(outsiderH), http.StatusForbidden}, {anonymous, http.StatusUnauthorized}} {
		res := env.do(c.who, http.MethodDelete, "/api/v1/orgs/"+orgH+"/logo", nil)
		_ = res.Body.Close()
		if res.StatusCode != c.want {
			t.Fatalf("%s removed the logo: %d, want %d", c.who.name, res.StatusCode, c.want)
		}
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusOK {
		t.Fatalf("a refused removal took the logo: %d", res.StatusCode)
	}

	// A token needs the organization-admin scope for either: the admin's
	// token without it is refused, with it the admin sets the logo.
	_, noScope := env.mintPAT(admin, "no-org-scope", "agent:read")
	_, withScope := env.mintPAT(admin, "org-scope", "org:admin")
	if code, _ := putLogo(t, env, caller{name: "pat-no-scope", pat: noScope}, orgH, tinyPNG(t), "logo.png"); code != http.StatusForbidden {
		t.Fatalf("a token without org:admin set the logo: %d", code)
	}
	res := env.do(caller{name: "pat-no-scope", pat: noScope}, http.MethodDelete, "/api/v1/orgs/"+orgH+"/logo", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a token without org:admin removed the logo: %d", res.StatusCode)
	}
	if code, _ := putLogo(t, env, caller{name: "pat-org-admin", pat: withScope}, orgH, tinyPNG(t), "logo.png"); code != http.StatusOK {
		t.Fatalf("a token with org:admin set the logo: %d", code)
	}

	// In the decommission hold the logo is read and nothing changes it.
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/decommission", map[string]any{"confirm": orgH, "reason": "closing"}, nil, http.StatusOK)
	if code, body := putLogo(t, env, admin, orgH, tinyPNG(t), "logo.png"); code != http.StatusConflict || !strings.Contains(body, "org-decommissioning") {
		t.Fatalf("a set during the hold: %d %s", code, body)
	}
	res = env.do(admin, http.MethodDelete, "/api/v1/orgs/"+orgH+"/logo", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("a removal during the hold: %d", res.StatusCode)
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusOK {
		t.Fatalf("the logo during the hold: %d", res.StatusCode)
	}

	// A suspended organization answers as absent, its logo included, to
	// everyone.
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE orgs SET state = 'suspended' WHERE id = $1::uuid`, orgID); err != nil {
		t.Fatal(err)
	}
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusNotFound {
		t.Fatalf("the logo of a suspended organization: %d, want 404", res.StatusCode)
	}
	if code, _ := putLogo(t, env, admin, orgH, tinyPNG(t), "logo.png"); code != http.StatusNotFound {
		t.Fatalf("a set on a suspended organization: %d, want 404", code)
	}
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
	if res, _ := getLogo(t, env, orgH); res.StatusCode != http.StatusNotFound {
		t.Fatalf("a refused upload left a logo: %d", res.StatusCode)
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
	if code, _ := putLogo(t, env, admin, orgH, tinyPNG(t), "logo.png"); code != http.StatusInternalServerError {
		t.Fatalf("an unknown entitlement: %d, want the 500 every unknown entitlement answers", code)
	}
}

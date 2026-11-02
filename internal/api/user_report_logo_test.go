package api_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"math/rand/v2"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/pkg/reportdesign"
)

// putReportLogo uploads body as the one multipart part to the caller's
// report logo and returns the status and the body.
func putReportLogo(t *testing.T, env *testEnv, who caller, body []byte) (int, []byte) {
	t.Helper()
	return putReportLogoParts(t, env, who, formPart{"file", body})
}

// formPart is one part of a multipart upload, named by its form field.
type formPart struct {
	field string
	body  []byte
}

// putReportLogoParts uploads the parts, in order, to the caller's report
// logo and returns the status and the body.
func putReportLogoParts(t *testing.T, env *testEnv, who caller, parts ...formPart) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		part, _ := mw.CreateFormFile(p.field, "logo.png")
		_, _ = part.Write(p.body)
	}
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPut, env.srv.URL+"/api/v1/user/report-settings/logo", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	env.authenticate(req, who)
	res, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// logoPNG is a w×h PNG of one colour.
func logoPNG(t *testing.T, w, h int, c color.Color) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The report design's logo: uploaded as a file, kept only as the core's own PNG of its
// pixels, scaled down to fit, answered only to a client that asks for it,
// kept when a client that does not know logos saves the design, the account's
// own and gone with the design.
func TestReportLogo(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("logo-user")
	env.verifyEmail(u)
	sess := env.login(u)
	other := env.register("logo-other")
	env.verifyEmail(other)
	otherSess := env.login(other)

	type settings struct {
		Design json.RawMessage `json:"design"`
	}
	const path = "/api/v1/user/report-settings"
	read := func(who caller, query string) (reportdesign.Design, json.RawMessage) {
		t.Helper()
		var got settings
		env.doJSON(who, http.MethodGet, path+query, nil, &got, http.StatusOK)
		if got.Design == nil {
			return reportdesign.Design{}, nil
		}
		d, err := reportdesign.Parse(got.Design)
		if err != nil {
			t.Fatalf("the server answered a design that does not parse: %v", err)
		}
		return d, got.Design
	}

	// A logo travels with a design: none saved is 409.
	if st, body := putReportLogo(t, env, sess, logoPNG(t, 8, 8, color.Black)); st != http.StatusConflict || !bytes.Contains(body, []byte("Save a report design first")) {
		t.Fatalf("a logo with no design: %d %s", st, body)
	}

	modern, _ := reportdesign.Builtin("modern")
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(modern.Canonical())}, nil, http.StatusOK)

	// The upload carries a text chunk and bytes after IEND; neither is kept.
	crafted := tinyPNG(t)
	st, body := putReportLogo(t, env, sess, crafted)
	if st != http.StatusOK {
		t.Fatalf("upload: %d %s", st, body)
	}
	var answered settings
	_ = json.Unmarshal(body, &answered)
	withLogo, err := reportdesign.Parse(answered.Design)
	if err != nil || withLogo.Logo == (reportdesign.Logo{}) {
		t.Fatalf("the upload answered %.200s (%v)", answered.Design, err)
	}
	stored, _ := withLogo.Logo.Decode()
	if bytes.Contains(stored, []byte("SMUGGLED")) || bytes.Equal(stored, crafted) {
		t.Fatal("the upload's own bytes were kept")
	}
	if img, err := png.Decode(bytes.NewReader(stored)); err != nil || img.Bounds().Dx() != 4 {
		t.Fatalf("the stored logo: %v %v", err, img)
	}
	if withLogo.Logo.PNG == base64.StdEncoding.EncodeToString(crafted) {
		t.Fatal("the logo is the upload")
	}

	// Without include=logo the design comes as a client before logos reads
	// it; with it, the logo too, and a user:profile token reads both, as
	// the CLI does.
	if d, raw := read(sess, ""); d != modern || bytes.Contains(raw, []byte(`"logo"`)) {
		t.Fatalf("GET without include: %s", raw)
	}
	_, profilePAT := env.mintPAT(sess, "logo-profile", "user:profile")
	if d, _ := read(caller{name: "pat", pat: profilePAT}, "?include=logo"); d != withLogo {
		t.Fatal("GET include=logo did not answer the logo")
	}
	env.doJSON(sess, http.MethodGet, path+"?include=watermark", nil, nil, http.StatusBadRequest)
	env.doJSON(sess, http.MethodPut, path+"?include=watermark", map[string]any{"design": json.RawMessage(modern.Canonical())}, nil, http.StatusBadRequest)

	// Saving the design without a logo, as the site, the desktop and the CLI
	// of before logos do, keeps the logo.
	classic, _ := reportdesign.Builtin("classic")
	var kept settings
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic.Canonical())}, &kept, http.StatusOK)
	if bytes.Contains(kept.Design, []byte(`"logo"`)) {
		t.Fatalf("a PUT without include=logo answered the logo: %.200s", kept.Design)
	}
	keep := classic
	keep.Logo = withLogo.Logo
	if d, _ := read(sess, "?include=logo"); d != keep {
		t.Fatal("a save without a logo dropped it")
	}

	// A design that carries a logo replaces it, with the core's own
	// encoding, and PUT answers it with include=logo.
	red := modern
	red.Logo = reportdesign.Logo{PNG: base64.StdEncoding.EncodeToString(logoPNG(t, 20, 10, color.NRGBA{R: 255, A: 255}))}
	var put settings
	env.doJSON(sess, http.MethodPut, path+"?include=logo", map[string]any{"design": json.RawMessage(red.Canonical())}, &put, http.StatusOK)
	gotRed, err := reportdesign.Parse(put.Design)
	if err != nil || gotRed.Logo == withLogo.Logo || gotRed.Logo == (reportdesign.Logo{}) {
		t.Fatalf("a design with a logo answered %.200s (%v)", put.Design, err)
	}
	if d, _ := read(sess, "?include=logo"); d != gotRed {
		t.Fatal("a design with a logo did not read back")
	}
	if without := gotRed; func() bool { without.Logo = reportdesign.Logo{}; return without != modern }() {
		t.Fatalf("a design with a logo did not replace the saved design: %.200s", put.Design)
	}
	if d, raw := read(sess, ""); d != modern || bytes.Contains(raw, []byte(`"logo"`)) {
		t.Fatalf("GET without include after a design with a logo: %s", raw)
	}

	// A design's logo field is held to a PNG within the bounds, in standard
	// base64 on one line, that decodes whole.
	logoDoc := func(png string) map[string]any {
		m := map[string]any{}
		_ = json.Unmarshal(modern.Canonical(), &m)
		m["logo"] = map[string]any{"png": png}
		return m
	}
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	small := logoPNG(t, 6, 6, color.NRGBA{B: 200, A: 255})
	for len(small)%3 == 0 {
		small = append(small, 0)
	}
	// The last base64 character carries bits the data does not use; setting
	// one gives a second spelling of the same bytes.
	clean := b64(small)
	spare := clean
	trimmed := strings.TrimRight(spare, "=")
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", trimmed[len(trimmed)-1])
	spare = trimmed[:len(trimmed)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[last|1]) + spare[len(trimmed):]
	const notAPNG = "must be a PNG in standard base64"
	keyedGray := keyedGrayPNG(t, 700, 700)
	if len(keyedGray) > reportdesign.MaxLogoBytes {
		t.Fatalf("the grayscale PNG is %d bytes, over the bound it should be under", len(keyedGray))
	}
	whole := logoPNG(t, 6, 6, color.Black)
	for _, c := range []struct {
		name string
		png  string
		msg  string
		// field is the refused field, "design.logo.png" unless set.
		field string
	}{
		{"not base64", "not base64!", notAPNG, ""},
		{"a JPEG", b64(tinyJPEG(t)), notAPNG, ""},
		{"a GIF", b64(tinyGIF(t)), notAPNG, ""},
		{"a line break in the base64", clean[:8] + "\n" + clean[8:], notAPNG, ""},
		{"base64 with padding bits set", spare, notAPNG, ""},
		{"a PNG cut short", b64(whole[:len(whole)-30]), "the PNG does not decode", ""},
		{"1025 pixels wide", b64(logoPNG(t, 1025, 2, color.Black)), "a logo is at most 1024 pixels each way", ""},
		{"1025 pixels tall", b64(logoPNG(t, 2, 1025, color.Black)), "a logo is at most 1024 pixels each way", ""},
		{"an empty logo", "", "must not be empty; a design without a logo has no logo key", "design.logo.png"},
		{"a logo field over 512 KB", strings.Repeat("A", base64.StdEncoding.EncodedLen(reportdesign.MaxLogoBytes)+4), "a logo is at most 512 KB", ""},
		{"a PNG that is over 512 KB when written again", b64(keyedGray), "this image is over 512 KB as a PNG; a simpler or smaller one is needed", ""},
	} {
		var p struct {
			Errors []struct {
				Field   string `json:"field"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": logoDoc(c.png)}, &p, http.StatusUnprocessableEntity)
		want := c.field
		if want == "" {
			want = "design.logo.png"
		}
		if len(p.Errors) != 1 || p.Errors[0].Field != want || p.Errors[0].Message != c.msg {
			t.Errorf("a design logo that is %s: refused with %+v, want %s %q", c.name, p.Errors, want, c.msg)
		}
	}
	var noKey struct {
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	noPNG := logoDoc("")
	noPNG["logo"] = map[string]any{}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": noPNG}, &noKey, http.StatusUnprocessableEntity)
	if len(noKey.Errors) != 1 || noKey.Errors[0].Field != "design.logo.png" || noKey.Errors[0].Message != "is required" {
		t.Errorf("a logo with no png: refused with %+v", noKey.Errors)
	}
	// The logo field does not count to the document's 16 KB, and the rest of
	// the document still does.
	if d, _ := read(sess, "?include=logo"); d != gotRed {
		t.Fatal("a refused design changed the logo")
	}

	// Refusals: SVG and GIF are not logos; over 512 KB, a header claiming
	// 20 million pixels, and no file part are refused; the logo stands.
	huge := logoPNG(t, 4, 4, color.Black)
	huge = append(huge, make([]byte, reportdesign.MaxLogoUploadBytes)...)
	const notRaster = "A logo is a PNG or a JPEG. SVG is not accepted"
	cutShort := logoPNG(t, 8, 8, color.NRGBA{R: 7, G: 9, A: 255})
	cutShort = cutShort[:len(cutShort)-20]
	for _, c := range []struct {
		name   string
		body   []byte
		want   int
		detail string
	}{
		{"svg", []byte(tinySVG), http.StatusUnsupportedMediaType, notRaster},
		{"gif", tinyGIF(t), http.StatusUnsupportedMediaType, notRaster},
		{"not an image", []byte("plain text"), http.StatusUnsupportedMediaType, notRaster},
		{"a PNG cut short", cutShort, http.StatusUnsupportedMediaType, notRaster},
		{"over 512 KB", huge, http.StatusRequestEntityTooLarge, "A logo is at most 512 KB."},
		{"one byte over 512 KB", padPNG(t, reportdesign.MaxLogoUploadBytes+1), http.StatusRequestEntityTooLarge, "A logo is at most 512 KB."},
		{"20 million pixels", claimSize(logoPNG(t, 4, 4, color.Black), 5000, 4000), http.StatusRequestEntityTooLarge, "a logo has at most 16 million pixels"},
		{"one pixel row over 16 million", claimSize(logoPNG(t, 4, 4, color.Black), 4097, 4096), http.StatusRequestEntityTooLarge, "a logo has at most 16 million pixels"},
		{"over 512 KB as a PNG", noisyJPEG(t), http.StatusRequestEntityTooLarge, "over 512 KB as a PNG"},
	} {
		if st, body := putReportLogo(t, env, sess, c.body); st != c.want || !bytes.Contains(body, []byte(c.detail)) {
			t.Errorf("%s: %d %s, want %d and %q", c.name, st, body, c.want, c.detail)
		}
	}
	// A part ahead of the file that runs past the request's bound is too
	// large too; a part under another name, or an empty file, is no file.
	if st, body := putReportLogoParts(t, env, sess, formPart{"note", make([]byte, reportdesign.MaxLogoUploadBytes+4096)}, formPart{"file", logoPNG(t, 4, 4, color.Black)}); st != http.StatusRequestEntityTooLarge {
		t.Errorf("a part past the request bound: %d %s", st, body)
	}
	if st, body := putReportLogoParts(t, env, sess, formPart{"logo", logoPNG(t, 4, 4, color.Black)}); st != http.StatusBadRequest {
		t.Errorf("a part not named file: %d %s", st, body)
	}
	if st, body := putReportLogoParts(t, env, sess, formPart{"file", nil}); st != http.StatusBadRequest {
		t.Errorf("an empty file: %d %s", st, body)
	}
	req, _ := http.NewRequest(http.MethodPut, env.srv.URL+path+"/logo", bytes.NewReader(logoPNG(t, 4, 4, color.Black)))
	req.Header.Set("Content-Type", "image/png")
	env.authenticate(req, sess)
	if res, err := env.srv.Client().Do(req); err != nil || res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a raw body: %v %v", res, err)
	}
	if d, _ := read(sess, "?include=logo"); d != gotRed {
		t.Fatal("a refused upload changed the logo")
	}

	// A JPEG is taken, and stored as PNG.
	if st, body := putReportLogo(t, env, sess, tinyJPEG(t)); st != http.StatusOK {
		t.Fatalf("a JPEG: %d %s", st, body)
	}
	if d, _ := read(sess, "?include=logo"); d.Logo == gotRed.Logo {
		t.Fatal("the JPEG did not replace the logo")
	} else if raw, _ := d.Logo.Decode(); !bytes.HasPrefix(raw, []byte("\x89PNG")) {
		t.Fatal("the JPEG was not stored as PNG")
	}

	// Uploads at their bounds are taken: 512 KB to the byte and 4096x4096
	// pixels; a file found after another part is the logo.
	if st, body := putReportLogo(t, env, sess, padPNG(t, reportdesign.MaxLogoUploadBytes)); st != http.StatusOK {
		t.Fatalf("a %d-byte upload: %d %s", reportdesign.MaxLogoUploadBytes, st, body)
	}
	if st, body := putReportLogo(t, env, sess, logoPNG(t, 4096, 4096, color.NRGBA{R: 9, A: 255})); st != http.StatusOK {
		t.Fatalf("a 4096x4096 upload: %d %s", st, body)
	}
	if st, body := putReportLogoParts(t, env, sess, formPart{"note", []byte("x")}, formPart{"file", logoPNG(t, 5, 5, color.Black)}); st != http.StatusOK {
		t.Fatalf("a file after another part: %d %s", st, body)
	} else if d, _ := read(sess, "?include=logo"); func() bool { w, h := logoSize(t, d.Logo); return w != 5 || h != 5 }() {
		t.Fatal("the file after another part is not the logo")
	}

	// A larger image is scaled down to fit 1024 pixels each way, its aspect
	// kept; one that fits is left as it is.
	for _, c := range []struct{ w, h, wantW, wantH int }{
		{2048, 1024, 1024, 512},
		{512, 2048, 256, 1024},
		{1024, 1024, 1024, 1024},
		{3000, 1, 1024, 1},
	} {
		if st, body := putReportLogo(t, env, sess, logoPNG(t, c.w, c.h, color.NRGBA{G: 90, A: 255})); st != http.StatusOK {
			t.Fatalf("a %dx%d upload: %d %s", c.w, c.h, st, body)
		}
		d, _ := read(sess, "?include=logo")
		if w, h := logoSize(t, d.Logo); w != c.wantW || h != c.wantH {
			t.Errorf("a %dx%d upload is stored as %dx%d, want %dx%d", c.w, c.h, w, h, c.wantW, c.wantH)
		}
	}

	// A design's own logo is held to the same side bound and taken at it.
	for _, c := range []struct {
		name string
		png  []byte
	}{
		{"1024 pixels wide", logoPNG(t, 1024, 2, color.Black)},
		{"1024 pixels tall", logoPNG(t, 2, 1024, color.Black)},
	} {
		var ok settings
		env.doJSON(sess, http.MethodPut, path+"?include=logo", map[string]any{"design": logoDoc(b64(c.png))}, &ok, http.StatusOK)
		if d, err := reportdesign.Parse(ok.Design); err != nil || d.Logo == (reportdesign.Logo{}) {
			t.Errorf("a design logo %s: answered %.100s (%v)", c.name, ok.Design, err)
		}
	}
	// ...and stored as the core's own encoding of its pixels, whatever
	// chunks and trailing bytes it came with.
	var viaDesign settings
	env.doJSON(sess, http.MethodPut, path+"?include=logo", map[string]any{"design": logoDoc(b64(tinyPNG(t)))}, &viaDesign, http.StatusOK)
	if d, err := reportdesign.Parse(viaDesign.Design); err != nil {
		t.Fatal(err)
	} else if stored, _ := d.Logo.Decode(); bytes.Contains(stored, []byte("SMUGGLED")) || bytes.Equal(stored, tinyPNG(t)) {
		t.Fatal("a design's logo was stored as it was sent")
	}

	// Each account reaches only its own; a token without user:profile, and
	// nobody without a credential, reach none.
	if d, raw := read(otherSess, "?include=logo"); raw != nil {
		t.Fatalf("another account reads %v", d)
	}
	if st, _ := putReportLogo(t, env, otherSess, logoPNG(t, 4, 4, color.Black)); st != http.StatusConflict {
		t.Fatalf("another account's upload: %d", st)
	}
	_, agentPAT := env.mintPAT(sess, "logo-agent", "agent:read")
	if st, _ := putReportLogo(t, env, caller{name: "pat", pat: agentPAT}, logoPNG(t, 4, 4, color.Black)); st != http.StatusForbidden {
		t.Fatalf("an agent:read token's upload: %d", st)
	}
	if st, _ := putReportLogo(t, env, anonymous, logoPNG(t, 4, 4, color.Black)); st != http.StatusUnauthorized {
		t.Fatalf("an anonymous upload: %d", st)
	}
	env.doJSON(anonymous, http.MethodDelete, path+"/logo", nil, nil, http.StatusUnauthorized)
	env.doJSON(caller{name: "pat", pat: agentPAT}, http.MethodDelete, path+"/logo", nil, nil, http.StatusForbidden)

	// The other account now has a design and a logo of its own, which
	// nothing the first account does reaches.
	env.doJSON(otherSess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic.Canonical())}, nil, http.StatusOK)
	if st, body := putReportLogo(t, env, otherSess, logoPNG(t, 6, 3, color.NRGBA{R: 200, A: 255})); st != http.StatusOK {
		t.Fatalf("another account's upload: %d %s", st, body)
	}
	theirs, _ := read(otherSess, "?include=logo")
	if theirs.Logo == (reportdesign.Logo{}) {
		t.Fatal("another account's logo was not stored")
	}
	otherStill := func(after string) {
		t.Helper()
		if d, _ := read(otherSess, "?include=logo"); d != theirs {
			t.Fatalf("%s changed another account's design or logo", after)
		}
	}
	otherStill("the first account's uploads")

	// A stored logo that no longer validates is left out; the design stands.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE user_report_settings SET logo = $2 WHERE user_id = $1`, uuid.MustParse(env.userID(u)), []byte("not a png")); err != nil {
		t.Fatal(err)
	}
	if d, raw := read(sess, "?include=logo"); d != modern || bytes.Contains(raw, []byte(`"logo"`)) {
		t.Fatalf("a stored logo that no longer validates read back %.200s", raw)
	}
	if st, body := putReportLogo(t, env, sess, logoPNG(t, 4, 4, color.Black)); st != http.StatusOK {
		t.Fatalf("a logo uploaded over one that no longer validates: %d %s", st, body)
	}

	// DELETE removes the logo and keeps the design; again is still done.
	for range 2 {
		var del settings
		env.doJSON(sess, http.MethodDelete, path+"/logo", nil, &del, http.StatusOK)
		if d, err := reportdesign.Parse(del.Design); err != nil || d != modern {
			t.Fatalf("DELETE answered %s (%v)", del.Design, err)
		}
		otherStill("deleting the logo")
	}

	// Clearing the design clears the logo with it.
	if st, _ := putReportLogo(t, env, sess, logoPNG(t, 4, 4, color.Black)); st != http.StatusOK {
		t.Fatal("upload again")
	}
	env.doJSON(sess, http.MethodPut, path, map[string]any{}, nil, http.StatusOK)
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(modern.Canonical())}, nil, http.StatusOK)
	if d, _ := read(sess, "?include=logo"); d != modern {
		t.Fatal("a cleared design's logo came back")
	}
	otherStill("clearing the design")

	// The account's erasure deletes the design and its logo.
	if st, _ := putReportLogo(t, env, sess, logoPNG(t, 4, 4, color.Black)); st != http.StatusOK {
		t.Fatal("upload before erasure")
	}
	id := env.userID(u)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete?publishedContent=yank", nil, nil, http.StatusNoContent)
	if _, err := env.st.Queries().GetUserReportSettings(context.Background(), uuid.MustParse(id)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("the erased account's report settings: %v", err)
	}
	otherStill("erasing the account")
}

// padPNG is a PNG followed by zero bytes to exactly n bytes: the bytes after
// IEND are ignored by a decoder, so the file is still the same image.
func padPNG(t *testing.T, n int) []byte {
	t.Helper()
	img := logoPNG(t, 4, 4, color.Black)
	if len(img) > n {
		t.Fatalf("a PNG of %d bytes does not fit %d", len(img), n)
	}
	return append(img, make([]byte, n-len(img))...)
}

// noiseImage is a w×h opaque image of random pixels, the same every time.
func noiseImage(w, h int) *image.NRGBA {
	rng := rand.New(rand.NewPCG(1, 2))
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = byte(rng.UintN(256))
	}
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 255
	}
	return img
}

// noisePNG is noiseImage as a PNG, which does not compress.
func noisePNG(t *testing.T, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, noiseImage(w, h)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// keyedGrayPNG is a w×h grayscale PNG of random pixels with a transparent
// colour key. It decodes to an image with an alpha channel, so a PNG written
// again from its pixels takes four bytes a pixel where this one takes one.
func keyedGrayPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	rng := rand.New(rand.NewPCG(3, 4))
	var raw bytes.Buffer
	for range h {
		raw.WriteByte(0) // filter: none
		for range w {
			raw.WriteByte(byte(rng.UintN(256)))
		}
	}
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	chunk := func(kind string, data []byte) []byte {
		out := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
		out = append(out, kind...)
		out = append(out, data...)
		return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out[4:]))
	}
	ihdr := binary.BigEndian.AppendUint32(nil, uint32(w))
	ihdr = binary.BigEndian.AppendUint32(ihdr, uint32(h))
	ihdr = append(ihdr, 8, 0, 0, 0, 0) // 8 bits, grayscale, deflate, filtered, not interlaced
	out := []byte("\x89PNG\r\n\x1a\n")
	out = append(out, chunk("IHDR", ihdr)...)
	out = append(out, chunk("tRNS", []byte{0, 0})...)
	out = append(out, chunk("IDAT", z.Bytes())...)
	return append(out, chunk("IEND", nil)...)
}

// noisyJPEG is a JPEG of random pixels that fits the upload bound while
// its pixels, as a PNG, do not fit the stored bound.
func noisyJPEG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, noiseImage(600, 600), &jpeg.Options{Quality: 40}); err != nil {
		t.Fatal(err)
	}
	if b.Len() > reportdesign.MaxLogoUploadBytes {
		t.Fatalf("the noisy JPEG is %d bytes, over the upload bound", b.Len())
	}
	return b.Bytes()
}

// logoSize is the pixel size of a design's stored logo.
func logoSize(t *testing.T, l reportdesign.Logo) (int, int) {
	t.Helper()
	raw, err := l.Decode()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Width, cfg.Height
}

// claimSize rewrites a PNG's IHDR to claim w×h, its CRC made right, so the
// header lies about pixels the file does not hold.
func claimSize(data []byte, w, h uint32) []byte {
	out := append([]byte{}, data...)
	put := func(at int, v uint32) {
		out[at], out[at+1], out[at+2], out[at+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	}
	put(16, w)
	put(20, h)
	put(29, crc32.ChecksumIEEE(out[12:29]))
	return out
}

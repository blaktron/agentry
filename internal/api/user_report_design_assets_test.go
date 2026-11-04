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
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/pkg/reportdesign"
)

// putDesignFile uploads body as the one multipart part to an image route of
// the caller's design (route is "logo" or "cover-image") and returns the
// status and the body.
func putDesignFile(t *testing.T, env *testEnv, who caller, id uuid.UUID, route string, body []byte) (int, []byte) {
	t.Helper()
	return putDesignFileParts(t, env, who, id, route, formPart{"file", body})
}

// formPart is one part of a multipart upload, named by its form field.
type formPart struct {
	field string
	body  []byte
}

// putDesignFileParts uploads the parts, in order, to an image route of the
// caller's design and returns the status and the body.
func putDesignFileParts(t *testing.T, env *testEnv, who caller, id uuid.UUID, route string, parts ...formPart) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		part, _ := mw.CreateFormFile(p.field, "image.png")
		_, _ = part.Write(p.body)
	}
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPut, env.srv.URL+designsPath+"/"+id.String()+"/"+route, &buf)
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

// A design's images: each uploaded as a file or carried in the document,
// kept only as the core's own encoding of its pixels, scaled down to fit,
// answered only to a client that asks for them, kept when a client that
// does not know them saves the document, the account's own, and gone with
// the design, the cleared account and the erased account.
func TestReportDesignAssets(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("logo-user")
	env.verifyEmail(u)
	sess := env.login(u)
	other := env.register("logo-other")
	env.verifyEmail(other)
	otherSess := env.login(other)

	read := func(who caller, id uuid.UUID, query string) (reportdesign.Design, designRecord, int) {
		t.Helper()
		res := env.do(who, http.MethodGet, designsPath+"/"+id.String()+query, nil)
		defer func() { _ = res.Body.Close() }()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			return reportdesign.Design{}, designRecord{}, res.StatusCode
		}
		var rec designRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		return parseDesign(t, rec.Design), rec, res.StatusCode
	}
	same := func(a, b reportdesign.Design) bool { return reflect.DeepEqual(a, b) }

	// An image travels with a design: a design the caller does not have is
	// 404, on each image route.
	for _, route := range []string{"logo", "cover-image"} {
		if st, body := putDesignFile(t, env, sess, uuid.New(), route, logoPNG(t, 8, 8, color.Black)); st != http.StatusNotFound {
			t.Fatalf("a %s with no design: %d %s", route, st, body)
		}
		env.doJSON(sess, http.MethodDelete, designsPath+"/"+uuid.New().String()+"/"+route, nil, nil, http.StatusNotFound)
	}
	env.doJSON(sess, http.MethodPut, designsPath+"/"+uuid.New().String()+"/custom-cover", map[string]any{"source": "#page[]", "images": []any{}}, nil, http.StatusNotFound)
	env.doJSON(sess, http.MethodDelete, designsPath+"/"+uuid.New().String()+"/custom-cover", nil, nil, http.StatusNotFound)

	modern, _ := reportdesign.Builtin("modern")
	var created designRecord
	env.doJSON(sess, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(modern.Canonical()), "default": true}, &created, http.StatusCreated)
	id := created.ID
	path := designsPath + "/" + id.String()

	// The logo upload carries a text chunk and bytes after IEND; neither
	// is kept.
	crafted := tinyPNG(t)
	st, body := putDesignFile(t, env, sess, id, "logo", crafted)
	if st != http.StatusOK {
		t.Fatalf("upload: %d %s", st, body)
	}
	var answered designRecord
	_ = json.Unmarshal(body, &answered)
	withLogo := parseDesign(t, answered.Design)
	if withLogo.Logo == (reportdesign.Logo{}) || !answered.HasLogo {
		t.Fatalf("the upload answered %+v", answered)
	}
	stored, _ := withLogo.Logo.Decode()
	if bytes.Contains(stored, []byte("SMUGGLED")) || bytes.Equal(stored, crafted) {
		t.Fatal("the upload's own bytes were kept")
	}
	if img, err := png.Decode(bytes.NewReader(stored)); err != nil || img.Bounds().Dx() != 4 {
		t.Fatalf("the stored logo: %v %v", err, img)
	}

	// Without include=assets the design comes without its images and the
	// record says it has one; with it, the images too, and a user:profile
	// token reads both, as the CLI does.
	if d, rec, _ := read(sess, id, ""); !same(d, modern) || bytes.Contains(rec.Design, []byte(`"logo"`)) || !rec.HasLogo {
		t.Fatalf("GET without include: %+v", rec)
	}
	_, profilePAT := env.mintPAT(sess, "logo-profile", "user:profile")
	if d, _, _ := read(caller{name: "pat", pat: profilePAT}, id, "?include=assets"); !same(d, withLogo) {
		t.Fatal("GET include=assets did not answer the logo")
	}
	env.doJSON(sess, http.MethodGet, path+"?include=logo", nil, nil, http.StatusBadRequest)
	env.doJSON(sess, http.MethodPut, path+"?include=logo", map[string]any{"design": json.RawMessage(modern.Canonical())}, nil, http.StatusBadRequest)
	env.doJSON(sess, http.MethodPost, designsPath+"?include=logo", map[string]any{"design": json.RawMessage(modern.Canonical())}, nil, http.StatusBadRequest)

	// Saving the document without its images keeps them.
	classic, _ := reportdesign.Builtin("classic")
	var kept designRecord
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic.Canonical())}, &kept, http.StatusOK)
	if bytes.Contains(kept.Design, []byte(`"logo"`)) || !kept.HasLogo {
		t.Fatalf("a PUT without include=assets answered %+v", kept)
	}
	keep := classic
	keep.Logo = withLogo.Logo
	if d, _, _ := read(sess, id, "?include=assets"); !same(d, keep) {
		t.Fatal("a save without a logo dropped it")
	}

	// A document that carries a logo replaces it, with the core's own
	// encoding, and PUT answers it with include=assets; a create with one
	// stores it the same way.
	red := modern
	red.Logo = reportdesign.Logo{PNG: base64.StdEncoding.EncodeToString(logoPNG(t, 20, 10, color.NRGBA{R: 255, A: 255}))}
	var put designRecord
	env.doJSON(sess, http.MethodPut, path+"?include=assets", map[string]any{"design": json.RawMessage(red.Canonical())}, &put, http.StatusOK)
	gotRed := parseDesign(t, put.Design)
	if gotRed.Logo == withLogo.Logo || gotRed.Logo == (reportdesign.Logo{}) {
		t.Fatalf("a design with a logo answered %.200s", put.Design)
	}
	if d, _, _ := read(sess, id, "?include=assets"); !same(d, gotRed) {
		t.Fatal("a design with a logo did not read back")
	}
	if !same(gotRed.WithoutAssets(), modern) {
		t.Fatalf("a design with a logo did not replace the saved design: %.200s", put.Design)
	}
	if d, rec, _ := read(sess, id, ""); !same(d, modern) || bytes.Contains(rec.Design, []byte(`"logo"`)) {
		t.Fatalf("GET without include after a design with a logo: %s", rec.Design)
	}
	var viaCreate designRecord
	env.doJSON(sess, http.MethodPost, designsPath+"?include=assets", map[string]any{"design": json.RawMessage(red.Canonical())}, &viaCreate, http.StatusCreated)
	if d := parseDesign(t, viaCreate.Design); !same(d, gotRed) || !viaCreate.HasLogo {
		t.Fatalf("a create with a logo answered %+v", viaCreate)
	}
	env.doJSON(sess, http.MethodDelete, designsPath+"/"+viaCreate.ID.String(), nil, nil, http.StatusNoContent)

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
		var p designProblem
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": logoDoc(c.png)}, &p, http.StatusUnprocessableEntity)
		want := c.field
		if want == "" {
			want = "design.logo.png"
		}
		if len(p.Errors) != 1 || p.Errors[0].Field != want || p.Errors[0].Message != c.msg {
			t.Errorf("a design logo that is %s: refused with %+v, want %s %q", c.name, p.Errors, want, c.msg)
		}
	}
	var noKey designProblem
	noPNG := logoDoc("")
	noPNG["logo"] = map[string]any{}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": noPNG}, &noKey, http.StatusUnprocessableEntity)
	if len(noKey.Errors) != 1 || noKey.Errors[0].Field != "design.logo.png" || noKey.Errors[0].Message != "is required" {
		t.Errorf("a logo with no png: refused with %+v", noKey.Errors)
	}
	if d, _, _ := read(sess, id, "?include=assets"); !same(d, gotRed) {
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
		if st, body := putDesignFile(t, env, sess, id, "logo", c.body); st != c.want || !bytes.Contains(body, []byte(c.detail)) {
			t.Errorf("%s: %d %s, want %d and %q", c.name, st, body, c.want, c.detail)
		}
	}
	// A part ahead of the file that runs past the request's bound is too
	// large too; a part under another name, or an empty file, is no file.
	if st, body := putDesignFileParts(t, env, sess, id, "logo", formPart{"note", make([]byte, reportdesign.MaxLogoUploadBytes+4096)}, formPart{"file", logoPNG(t, 4, 4, color.Black)}); st != http.StatusRequestEntityTooLarge {
		t.Errorf("a part past the request bound: %d %s", st, body)
	}
	if st, body := putDesignFileParts(t, env, sess, id, "logo", formPart{"logo", logoPNG(t, 4, 4, color.Black)}); st != http.StatusBadRequest {
		t.Errorf("a part not named file: %d %s", st, body)
	}
	if st, body := putDesignFileParts(t, env, sess, id, "logo", formPart{"file", nil}); st != http.StatusBadRequest {
		t.Errorf("an empty file: %d %s", st, body)
	}
	req, _ := http.NewRequest(http.MethodPut, env.srv.URL+path+"/logo", bytes.NewReader(logoPNG(t, 4, 4, color.Black)))
	req.Header.Set("Content-Type", "image/png")
	env.authenticate(req, sess)
	if res, err := env.srv.Client().Do(req); err != nil || res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a raw body: %v %v", res, err)
	}
	if d, _, _ := read(sess, id, "?include=assets"); !same(d, gotRed) {
		t.Fatal("a refused upload changed the logo")
	}

	// A JPEG is taken, and stored as PNG.
	if st, body := putDesignFile(t, env, sess, id, "logo", tinyJPEG(t)); st != http.StatusOK {
		t.Fatalf("a JPEG: %d %s", st, body)
	}
	if d, _, _ := read(sess, id, "?include=assets"); d.Logo == gotRed.Logo {
		t.Fatal("the JPEG did not replace the logo")
	} else if raw, _ := d.Logo.Decode(); !bytes.HasPrefix(raw, []byte("\x89PNG")) {
		t.Fatal("the JPEG was not stored as PNG")
	}

	// Uploads at their bounds are taken: 512 KB to the byte and 4096x4096
	// pixels; a file found after another part is the logo.
	if st, body := putDesignFile(t, env, sess, id, "logo", padPNG(t, reportdesign.MaxLogoUploadBytes)); st != http.StatusOK {
		t.Fatalf("a %d-byte upload: %d %s", reportdesign.MaxLogoUploadBytes, st, body)
	}
	if st, body := putDesignFile(t, env, sess, id, "logo", logoPNG(t, 4096, 4096, color.NRGBA{R: 9, A: 255})); st != http.StatusOK {
		t.Fatalf("a 4096x4096 upload: %d %s", st, body)
	}
	if st, body := putDesignFileParts(t, env, sess, id, "logo", formPart{"note", []byte("x")}, formPart{"file", logoPNG(t, 5, 5, color.Black)}); st != http.StatusOK {
		t.Fatalf("a file after another part: %d %s", st, body)
	} else if d, _, _ := read(sess, id, "?include=assets"); func() bool { w, h := logoSize(t, d.Logo); return w != 5 || h != 5 }() {
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
		if st, body := putDesignFile(t, env, sess, id, "logo", logoPNG(t, c.w, c.h, color.NRGBA{G: 90, A: 255})); st != http.StatusOK {
			t.Fatalf("a %dx%d upload: %d %s", c.w, c.h, st, body)
		}
		d, _, _ := read(sess, id, "?include=assets")
		if w, h := logoSize(t, d.Logo); w != c.wantW || h != c.wantH {
			t.Errorf("a %dx%d upload is stored as %dx%d, want %dx%d", c.w, c.h, w, h, c.wantW, c.wantH)
		}
	}
	// ...and a document's own logo is stored as the core's own encoding of
	// its pixels, whatever chunks and trailing bytes it came with.
	var viaDesign designRecord
	env.doJSON(sess, http.MethodPut, path+"?include=assets", map[string]any{"design": logoDoc(b64(tinyPNG(t)))}, &viaDesign, http.StatusOK)
	if stored, _ := parseDesign(t, viaDesign.Design).Logo.Decode(); bytes.Contains(stored, []byte("SMUGGLED")) || bytes.Equal(stored, tinyPNG(t)) {
		t.Fatal("a design's logo was stored as it was sent")
	}

	// The cover image: a PNG stays a PNG and a JPEG a JPEG, each encoded
	// again from its pixels, scaled to fit 2048; refused in no other
	// format, over 2 MB, or over 16 million pixels; answered only with
	// include=assets; kept by a document saved without it; replaced by a
	// document that carries one.
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, noiseImage(300, 200), &jpeg.Options{Quality: 60}); err != nil {
		t.Fatal(err)
	}
	st, body = putDesignFile(t, env, sess, id, "cover-image", jb.Bytes())
	if st != http.StatusOK {
		t.Fatalf("a JPEG cover image: %d %s", st, body)
	}
	_ = json.Unmarshal(body, &answered)
	withCover := parseDesign(t, answered.Design)
	if withCover.CoverImage.Format() != "jpeg" || !answered.HasCoverImage {
		t.Fatalf("the JPEG cover image answered %+v (%s)", answered, withCover.CoverImage.Format())
	}
	if raw, _, _ := withCover.CoverImage.Decode(); bytes.Equal(raw, jb.Bytes()) {
		t.Fatal("the JPEG was stored as sent")
	}
	if d, rec, _ := read(sess, id, ""); bytes.Contains(rec.Design, []byte(`"coverImage"`)) || !rec.HasCoverImage || d.CoverImage != (reportdesign.Image{}) {
		t.Fatalf("GET without include answered the cover image: %+v", rec)
	}
	if st, body := putDesignFile(t, env, sess, id, "cover-image", logoPNG(t, 4000, 1000, color.NRGBA{R: 200, A: 255})); st != http.StatusOK {
		t.Fatalf("a 4000x1000 PNG cover image: %d %s", st, body)
	}
	d, _, _ := read(sess, id, "?include=assets")
	if raw, format, _ := d.CoverImage.Decode(); format != "png" {
		t.Fatalf("a PNG cover image came back as %s", format)
	} else if cfg, _ := png.DecodeConfig(bytes.NewReader(raw)); cfg.Width != 2048 || cfg.Height != 512 {
		t.Fatalf("a 4000x1000 cover image is stored as %dx%d", cfg.Width, cfg.Height)
	}
	coverPNG := d.CoverImage
	for _, c := range []struct {
		name   string
		body   []byte
		want   int
		detail string
	}{
		{"svg", []byte(tinySVG), http.StatusUnsupportedMediaType, "A cover image is a PNG or a JPEG"},
		{"gif", tinyGIF(t), http.StatusUnsupportedMediaType, "A cover image is a PNG or a JPEG"},
		{"over 2 MB", padPNG(t, reportdesign.MaxCoverImageUploadBytes+1), http.StatusRequestEntityTooLarge, "A cover image is at most 2 MB."},
		{"20 million pixels", claimSize(logoPNG(t, 4, 4, color.Black), 5000, 4000), http.StatusRequestEntityTooLarge, "an image has at most 16 million pixels"},
	} {
		if st, body := putDesignFile(t, env, sess, id, "cover-image", c.body); st != c.want || !bytes.Contains(body, []byte(c.detail)) {
			t.Errorf("cover image %s: %d %s, want %d and %q", c.name, st, body, c.want, c.detail)
		}
	}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic.Canonical())}, nil, http.StatusOK)
	if d, _, _ := read(sess, id, "?include=assets"); d.CoverImage != coverPNG {
		t.Fatal("a save without a cover image dropped it")
	}
	withJPEG := classic
	withJPEG.CoverImage = reportdesign.ImageOf(jb.Bytes(), "jpeg")
	env.doJSON(sess, http.MethodPut, path+"?include=assets", map[string]any{"design": json.RawMessage(withJPEG.Canonical())}, &put, http.StatusOK)
	if d := parseDesign(t, put.Design); d.CoverImage.Format() != "jpeg" || d.CoverImage == withJPEG.CoverImage {
		t.Fatalf("a document with a cover image answered %.200s", put.Design)
	}
	// A cover image in the document under the wrong key, or over its
	// bounds, is refused naming the field.
	for _, c := range []struct {
		name  string
		image map[string]any
		field string
		msg   string
	}{
		{"a JPEG under png", map[string]any{"png": b64(jb.Bytes())}, "design.coverImage", "must be a PNG under its key"},
		{"a URL", map[string]any{"jpeg": "https://x.example/c.jpg"}, "design.coverImage", "must be a PNG or a JPEG in standard base64"},
		{"too wide", map[string]any{"png": b64(logoPNG(t, reportdesign.MaxCoverImageSide+1, 1, color.Black))}, "design.coverImage", "over its pixel limit"},
		{"both keys", map[string]any{"png": b64(whole), "jpeg": b64(jb.Bytes())}, "design.coverImage", "not both"},
	} {
		m := map[string]any{}
		_ = json.Unmarshal(classic.Canonical(), &m)
		m["coverImage"] = c.image
		var p designProblem
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": m}, &p, http.StatusUnprocessableEntity)
		if len(p.Errors) != 1 || p.Errors[0].Field != c.field || !strings.Contains(p.Errors[0].Message, c.msg) {
			t.Errorf("a cover image that is %s: %+v", c.name, p.Errors)
		}
	}
	var del designRecord
	env.doJSON(sess, http.MethodDelete, path+"/cover-image", nil, &del, http.StatusOK)
	if d := parseDesign(t, del.Design); d.CoverImage != (reportdesign.Image{}) || del.HasCoverImage || d.Logo == (reportdesign.Logo{}) {
		t.Fatalf("DELETE cover-image answered %+v", del)
	}
	env.doJSON(sess, http.MethodDelete, path+"/cover-image", nil, nil, http.StatusOK)

	// The custom cover: PUT as JSON whole, its source held to its bounds and
	// kept as text, each image and the thumbnail encoded again; answered
	// only with include=assets; kept by a document saved without it;
	// replaced by a document that carries one; removed by DELETE.
	source := "#let cover(meta, design) = [\n  #set page(fill: design.accent)\n  #align(center + horizon)[#text(size: 48pt, fill: white)[#meta.title]]\n]\n"
	cc := map[string]any{
		"source":    source,
		"images":    []any{map[string]any{"png": b64(tinyPNG(t))}, map[string]any{"jpeg": b64(jb.Bytes())}},
		"thumbnail": map[string]any{"png": b64(logoPNG(t, 200, 283, color.White))},
	}
	var withCustom designRecord
	env.doJSON(sess, http.MethodPut, path+"/custom-cover", cc, &withCustom, http.StatusOK)
	custom := parseDesign(t, withCustom.Design)
	if !withCustom.HasCustomCover || custom.CustomCover.Source != source || len(custom.CustomCover.Images) != 2 || custom.CustomCover.Thumbnail == (reportdesign.Image{}) {
		t.Fatalf("the custom cover answered %+v", withCustom)
	}
	if raw, format, _ := custom.CustomCover.Images[0].Decode(); format != "png" || bytes.Contains(raw, []byte("SMUGGLED")) {
		t.Fatalf("the first image: %s, kept as sent %v", format, bytes.Contains(raw, []byte("SMUGGLED")))
	}
	if _, format, _ := custom.CustomCover.Images[1].Decode(); format != "jpeg" {
		t.Fatalf("the second image came back as %s", format)
	}
	if d, rec, _ := read(sess, id, ""); bytes.Contains(rec.Design, []byte(`"customCover"`)) || !rec.HasCustomCover || !d.CustomCover.IsZero() {
		t.Fatalf("GET without include answered the custom cover: %+v", rec)
	}
	if d, _, _ := read(sess, id, "?include=assets"); !same(d, custom) {
		t.Fatal("the custom cover did not read back")
	}
	// Refusals name the field; an image in no format the core reads is 415.
	third := b64(padPNG(t, reportdesign.MaxCoverImagesBytes/3+1))
	for _, c := range []struct {
		name  string
		body  map[string]any
		want  int
		field string
		msg   string
	}{
		{"no source", map[string]any{"images": []any{}}, http.StatusUnprocessableEntity, "customCover.source", "must not be empty"},
		{"a source over 32 KiB", map[string]any{"source": strings.Repeat("x", reportdesign.MaxCoverSourceBytes+1), "images": []any{}}, http.StatusUnprocessableEntity, "customCover.source", "is 32769 bytes, over the limit of 32768"},
		{"a source with a NUL", map[string]any{"source": "a\x00b", "images": []any{}}, http.StatusUnprocessableEntity, "customCover.source", "no control character"},
		{"seven images", map[string]any{"source": "x", "images": []any{map[string]any{"png": b64(whole)}, map[string]any{"png": b64(whole)}, map[string]any{"png": b64(whole)}, map[string]any{"png": b64(whole)}, map[string]any{"png": b64(whole)}, map[string]any{"png": b64(whole)}, map[string]any{"png": b64(whole)}}}, http.StatusUnprocessableEntity, "customCover.images", "is 7 images, over the limit of 6"},
		{"images over 2 MB in all", map[string]any{"source": "x", "images": []any{map[string]any{"png": third}, map[string]any{"png": third}, map[string]any{"png": third}}}, http.StatusUnprocessableEntity, "customCover.images", "over 2 MB in all"},
		{"an image that is a GIF", map[string]any{"source": "x", "images": []any{map[string]any{"png": b64(tinyGIF(t))}}}, http.StatusUnsupportedMediaType, "", "customCover.images.0"},
		{"a thumbnail that is a JPEG", map[string]any{"source": "x", "images": []any{}, "thumbnail": map[string]any{"jpeg": b64(jb.Bytes())}}, http.StatusUnsupportedMediaType, "", "customCover.thumbnail"},
		{"an unknown key", map[string]any{"source": "x", "images": []any{}, "fonts": []any{}}, http.StatusBadRequest, "", ""},
	} {
		res := env.do(sess, http.MethodPut, path+"/custom-cover", c.body)
		raw, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != c.want {
			t.Errorf("a custom cover with %s: %d %s, want %d", c.name, res.StatusCode, raw, c.want)
			continue
		}
		var p designProblem
		_ = json.Unmarshal(raw, &p)
		if c.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != c.field || !strings.Contains(p.Errors[0].Message, c.msg)) {
			t.Errorf("a custom cover with %s: %+v, want %s %q", c.name, p.Errors, c.field, c.msg)
		}
		if c.field == "" && c.msg != "" && !strings.Contains(p.Detail, c.msg) {
			t.Errorf("a custom cover with %s: %q does not name %s", c.name, p.Detail, c.msg)
		}
	}
	if d, _, _ := read(sess, id, "?include=assets"); !same(d, custom) {
		t.Fatal("a refused custom cover changed the stored one")
	}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic.Canonical())}, nil, http.StatusOK)
	if d, _, _ := read(sess, id, "?include=assets"); !reflect.DeepEqual(d.CustomCover, custom.CustomCover) {
		t.Fatal("a save without a custom cover dropped it")
	}
	replaced := classic
	replaced.Cover.Style = "custom"
	replaced.CustomCover = reportdesign.CustomCover{Source: "#let cover(meta, design) = []\n", Images: []reportdesign.Image{}}
	env.doJSON(sess, http.MethodPut, path+"?include=assets", map[string]any{"design": json.RawMessage(replaced.Canonical())}, &put, http.StatusOK)
	if d := parseDesign(t, put.Design); !reflect.DeepEqual(d.CustomCover, replaced.CustomCover) || d.Cover.Style != "custom" {
		t.Fatalf("a document with a custom cover answered %.300s", put.Design)
	}
	env.doJSON(sess, http.MethodDelete, path+"/custom-cover", nil, &del, http.StatusOK)
	if d := parseDesign(t, del.Design); !d.CustomCover.IsZero() || del.HasCustomCover || d.Cover.Style != "custom" || d.Logo == (reportdesign.Logo{}) {
		t.Fatalf("DELETE custom-cover answered %+v", del)
	}
	env.doJSON(sess, http.MethodDelete, path+"/custom-cover", nil, nil, http.StatusOK)
	// The document as it now stands: the custom style, no images.
	plainNow := replaced.WithoutAssets()

	// Each account reaches only its own; a token without user:profile, and
	// nobody without a credential, reach none.
	if _, _, st := read(otherSess, id, "?include=assets"); st != http.StatusNotFound {
		t.Fatalf("another account reads: %d", st)
	}
	if st, _ := putDesignFile(t, env, otherSess, id, "logo", logoPNG(t, 4, 4, color.Black)); st != http.StatusNotFound {
		t.Fatalf("another account's upload: %d", st)
	}
	if st, _ := putDesignFile(t, env, otherSess, id, "cover-image", logoPNG(t, 4, 4, color.Black)); st != http.StatusNotFound {
		t.Fatalf("another account's cover image: %d", st)
	}
	env.doJSON(otherSess, http.MethodPut, path+"/custom-cover", map[string]any{"source": "x", "images": []any{}}, nil, http.StatusNotFound)
	for _, route := range []string{"logo", "cover-image", "custom-cover"} {
		env.doJSON(otherSess, http.MethodDelete, path+"/"+route, nil, nil, http.StatusNotFound)
	}
	_, agentPAT := env.mintPAT(sess, "logo-agent", "agent:read")
	if st, _ := putDesignFile(t, env, caller{name: "pat", pat: agentPAT}, id, "logo", logoPNG(t, 4, 4, color.Black)); st != http.StatusForbidden {
		t.Fatalf("an agent:read token's upload: %d", st)
	}
	if st, _ := putDesignFile(t, env, anonymous, id, "logo", logoPNG(t, 4, 4, color.Black)); st != http.StatusUnauthorized {
		t.Fatalf("an anonymous upload: %d", st)
	}
	for _, route := range []string{"logo", "cover-image", "custom-cover"} {
		env.doJSON(anonymous, http.MethodDelete, path+"/"+route, nil, nil, http.StatusUnauthorized)
		env.doJSON(caller{name: "pat", pat: agentPAT}, http.MethodDelete, path+"/"+route, nil, nil, http.StatusForbidden)
	}

	// The other account now has a design and a logo of its own, which
	// nothing the first account does reaches.
	var theirRec designRecord
	env.doJSON(otherSess, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(classic.Canonical())}, &theirRec, http.StatusCreated)
	if st, body := putDesignFile(t, env, otherSess, theirRec.ID, "logo", logoPNG(t, 6, 3, color.NRGBA{R: 200, A: 255})); st != http.StatusOK {
		t.Fatalf("another account's upload: %d %s", st, body)
	}
	theirs, _, _ := read(otherSess, theirRec.ID, "?include=assets")
	if theirs.Logo == (reportdesign.Logo{}) {
		t.Fatal("another account's logo was not stored")
	}
	otherStill := func(after string) {
		t.Helper()
		if d, _, _ := read(otherSess, theirRec.ID, "?include=assets"); !same(d, theirs) {
			t.Fatalf("%s changed another account's design or logo", after)
		}
	}
	otherStill("the first account's uploads")

	// A stored image that no longer validates is left out; the design
	// stands.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE user_report_designs SET logo = $2, cover_image = $2, cover_image_format = 'png', custom_cover = '{"source":"x","images":"no"}' WHERE id = $1`, id, []byte("not a png")); err != nil {
		t.Fatal(err)
	}
	if d, rec, _ := read(sess, id, "?include=assets"); !same(d, plainNow) || bytes.Contains(rec.Design, []byte(`"logo"`)) {
		t.Fatalf("stored images that no longer validate read back %.300s", rec.Design)
	}
	if st, body := putDesignFile(t, env, sess, id, "logo", logoPNG(t, 4, 4, color.Black)); st != http.StatusOK {
		t.Fatalf("a logo uploaded over one that no longer validates: %d %s", st, body)
	}
	env.doJSON(sess, http.MethodDelete, path+"/cover-image", nil, nil, http.StatusOK)
	env.doJSON(sess, http.MethodDelete, path+"/custom-cover", nil, nil, http.StatusOK)

	// DELETE removes the logo and keeps the design; again is still done.
	for range 2 {
		env.doJSON(sess, http.MethodDelete, path+"/logo", nil, &del, http.StatusOK)
		if d := parseDesign(t, del.Design); !same(d, plainNow) || del.HasLogo {
			t.Fatalf("DELETE answered %s", del.Design)
		}
		otherStill("deleting the logo")
	}

	// Deleting the design deletes its images with it.
	if st, _ := putDesignFile(t, env, sess, id, "logo", logoPNG(t, 4, 4, color.Black)); st != http.StatusOK {
		t.Fatal("upload again")
	}
	env.doJSON(sess, http.MethodDelete, path, nil, nil, http.StatusNoContent)
	if _, _, st := read(sess, id, "?include=assets"); st != http.StatusNotFound {
		t.Fatalf("a deleted design reads %d", st)
	}
	otherStill("deleting the design")

	// The account's erasure deletes every design and image.
	env.doJSON(sess, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(modern.Canonical())}, &created, http.StatusCreated)
	if st, _ := putDesignFile(t, env, sess, created.ID, "logo", logoPNG(t, 4, 4, color.Black)); st != http.StatusOK {
		t.Fatal("upload before erasure")
	}
	uid := env.userID(u)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete?publishedContent=yank", nil, nil, http.StatusNoContent)
	if rows, err := env.st.Queries().ListUserReportDesigns(context.Background(), uuid.MustParse(uid)); err != nil || len(rows) != 0 {
		t.Fatalf("the erased account's report designs: %d, %v", len(rows), err)
	}
	if _, err := env.st.Queries().GetUserReportDesignDefault(context.Background(), uuid.MustParse(uid)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("the erased account's default design: %v", err)
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

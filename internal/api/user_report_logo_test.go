package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/pkg/reportdesign"
)

// putReportLogo uploads body as the one multipart part to the caller's
// report logo and returns the status and the body.
func putReportLogo(t *testing.T, env *testEnv, who caller, body []byte) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, _ := mw.CreateFormFile("file", "logo.png")
	_, _ = part.Write(body)
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
// pixels, answered only to a client that asks for it, kept when a client
// that does not know logos saves the design, and gone with the design.
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
	if st, body := putReportLogo(t, env, sess, logoPNG(t, 8, 8, color.Black)); st != http.StatusConflict {
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

	// Saving the design without a logo, as the site, the desktop and the CLI
	// of before logos do, keeps the logo.
	classic, _ := reportdesign.Builtin("classic")
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic.Canonical())}, nil, http.StatusOK)
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

	// Refusals: SVG and GIF are not logos; over 512 KB, a header claiming
	// 20 million pixels, and no file part are refused; the logo stands.
	huge := logoPNG(t, 4, 4, color.Black)
	huge = append(huge, make([]byte, reportdesign.MaxLogoUploadBytes)...)
	for _, c := range []struct {
		name string
		body []byte
		want int
	}{
		{"svg", []byte(tinySVG), http.StatusUnsupportedMediaType},
		{"gif", tinyGIF(t), http.StatusUnsupportedMediaType},
		{"over 512 KB", huge, http.StatusRequestEntityTooLarge},
		{"20 million pixels", claimSize(logoPNG(t, 4, 4, color.Black), 5000, 4000), http.StatusRequestEntityTooLarge},
	} {
		if st, body := putReportLogo(t, env, sess, c.body); st != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, st, body, c.want)
		}
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

	// DELETE removes the logo and keeps the design; again is still done.
	for range 2 {
		var del settings
		env.doJSON(sess, http.MethodDelete, path+"/logo", nil, &del, http.StatusOK)
		if d, err := reportdesign.Parse(del.Design); err != nil || d != modern {
			t.Fatalf("DELETE answered %s (%v)", del.Design, err)
		}
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

	// The account's erasure deletes the design and its logo.
	if st, _ := putReportLogo(t, env, sess, logoPNG(t, 4, 4, color.Black)); st != http.StatusOK {
		t.Fatal("upload before erasure")
	}
	id := env.userID(u)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete?publishedContent=yank", nil, nil, http.StatusNoContent)
	if _, err := env.st.Queries().GetUserReportSettings(context.Background(), uuid.MustParse(id)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("the erased account's report settings: %v", err)
	}
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

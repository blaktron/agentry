package reportdesign

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func solid(w, h int, c color.Color) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, c)
		}
	}
	return img
}

// chunks lists a PNG's chunk types, in order.
func chunks(t *testing.T, data []byte) []string {
	t.Helper()
	if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("not a PNG")
	}
	var out []string
	for p := 8; p < len(data); {
		n := int(binary.BigEndian.Uint32(data[p:]))
		out = append(out, string(data[p+4:p+8]))
		p += 12 + n
	}
	return out
}

// withChunk inserts a chunk after IHDR, its CRC correct.
func withChunk(data []byte, typ string, body []byte) []byte {
	c := make([]byte, 0, 12+len(body))
	c = binary.BigEndian.AppendUint32(c, uint32(len(body)))
	c = append(c, typ...)
	c = append(c, body...)
	c = binary.BigEndian.AppendUint32(c, crc32.ChecksumIEEE(c[4:]))
	at := 8 + 12 + 13
	return append(append(append([]byte{}, data[:at]...), c...), data[at:]...)
}

// withSize rewrites IHDR's width and height, its CRC correct: a header that
// claims what the pixels are not.
func withSize(data []byte, w, h uint32) []byte {
	out := append([]byte{}, data...)
	binary.BigEndian.PutUint32(out[16:], w)
	binary.BigEndian.PutUint32(out[20:], h)
	binary.BigEndian.PutUint32(out[29:], crc32.ChecksumIEEE(out[12:29]))
	return out
}

func decodeLogo(t *testing.T, l Logo) image.Image {
	t.Helper()
	data, err := l.Decode()
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// An upload is decoded and encoded again from its pixels: what a
// crafted file carries beside them (a text chunk, bytes after IEND) is
// gone, and the pixels are kept. A JPEG becomes a PNG.
func TestNormalizeLogoKeepsOnlyThePixels(t *testing.T) {
	src := solid(40, 20, color.NRGBA{R: 0x1f, G: 0x6f, B: 0xeb, A: 0xff})
	crafted := withChunk(encodePNG(t, src), "tEXt", []byte("Comment\x00<script>alert(1)</script>"))
	crafted = append(crafted, []byte("trailing bytes after IEND")...)
	if !bytes.Contains(crafted, []byte("<script>")) {
		t.Fatal("the crafted file lost its payload")
	}
	l, err := NormalizeLogo(crafted)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := l.Decode()
	if bytes.Contains(data, []byte("<script>")) || bytes.Contains(data, []byte("trailing")) {
		t.Fatal("the re-encode kept the upload's own bytes")
	}
	for _, c := range chunks(t, data) {
		if c != "IHDR" && c != "IDAT" && c != "IEND" && c != "PLTE" && c != "tRNS" {
			t.Fatalf("the logo carries a %s chunk", c)
		}
	}
	got := decodeLogo(t, l)
	if got.Bounds().Dx() != 40 || got.Bounds().Dy() != 20 {
		t.Fatalf("a logo inside the bound was resized to %v", got.Bounds())
	}
	if r, g, b, _ := got.At(5, 5).RGBA(); r>>8 != 0x1f || g>>8 != 0x6f || b>>8 != 0xeb {
		t.Fatalf("the pixels changed: %v", got.At(5, 5))
	}

	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, solid(30, 30, color.White), nil); err != nil {
		t.Fatal(err)
	}
	l, err = NormalizeLogo(jb.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := l.Decode(); !bytes.HasPrefix(data, []byte("\x89PNG")) {
		t.Fatal("a JPEG was not encoded again as PNG")
	}
}

// What is not a PNG or a JPEG is refused as a format; what is over a bound
// is refused as too large, before the pixels are decoded.
func TestNormalizeLogoRefuses(t *testing.T) {
	var gb bytes.Buffer
	if err := gif.Encode(&gb, solid(4, 4, color.Black), nil); err != nil {
		t.Fatal(err)
	}
	small := encodePNG(t, solid(4, 4, color.Black))
	for _, c := range []struct {
		name string
		data []byte
		kind error
	}{
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), ErrLogoFormat},
		{"gif", gb.Bytes(), ErrLogoFormat},
		{"empty", nil, ErrLogoFormat},
		{"truncated png", small[:len(small)-20], ErrLogoFormat},
		{"over 512 KB", append(append([]byte{}, small...), make([]byte, MaxLogoUploadBytes)...), ErrLogoTooLarge},
		{"a header claiming 20 million pixels", withSize(small, 5000, 4000), ErrLogoTooLarge},
	} {
		_, err := NormalizeLogo(c.data)
		var fe *FieldError
		if !errors.Is(err, c.kind) || !errors.As(err, &fe) || fe.Field != "logo" {
			t.Errorf("%s: %v, want %v on logo", c.name, err, c.kind)
		}
	}
}

// A large upload is scaled down to fit MaxLogoSide, its aspect kept, each
// pixel the average of those it covers, and a transparent edge does not
// darken (premultiplied alpha).
func TestNormalizeLogoScalesDown(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 2048, 1024))
	for y := range 1024 {
		for x := range 2048 {
			switch {
			case x < 1024:
				img.Set(x, y, color.NRGBA{R: 255, A: 255})
			case x < 1536:
				img.Set(x, y, color.NRGBA{B: 255, A: 255})
			case x%2 == 0:
				img.Set(x, y, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
			default:
				img.Set(x, y, color.NRGBA{}) // transparent black
			}
		}
	}
	l, err := NormalizeLogo(encodePNG(t, img))
	if err != nil {
		t.Fatal(err)
	}
	got := decodeLogo(t, l)
	if got.Bounds().Dx() != 1024 || got.Bounds().Dy() != 512 {
		t.Fatalf("scaled to %v, want 1024×512", got.Bounds())
	}
	at := func(x, y int) color.NRGBA { return color.NRGBAModel.Convert(got.At(x, y)).(color.NRGBA) }
	if c := at(10, 10); c != (color.NRGBA{R: 255, A: 255}) {
		t.Errorf("red half reads %v", c)
	}
	if c := at(600, 10); c != (color.NRGBA{B: 255, A: 255}) {
		t.Errorf("blue quarter reads %v", c)
	}
	if c := at(900, 10); c.R != 255 || c.G != 255 || c.B != 255 || c.A < 120 || c.A > 135 {
		t.Errorf("white over transparent reads %v, want white at half alpha", c)
	}

	l, err = NormalizeLogo(encodePNG(t, solid(300, 1800, color.Black)))
	if err != nil {
		t.Fatal(err)
	}
	if b := decodeLogo(t, l).Bounds(); b.Dx() != 171 || b.Dy() != 1024 {
		t.Fatalf("a tall logo scaled to %v, want 171×1024", b)
	}
}

// A design carries its logo as the last key, and only when it has one: a
// built-in's document and SHA-256 are what they were, a design with a logo
// round-trips byte for byte, and the receipt's hash covers the logo.
func TestDesignWithLogoRoundTrips(t *testing.T) {
	plain := Default()
	if bytes.Contains(plain.Canonical(), []byte(`"logo"`)) {
		t.Fatal("a design without a logo writes a logo key")
	}
	l, err := NormalizeLogo(encodePNG(t, solid(64, 32, color.NRGBA{R: 200, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	mine := plain
	mine.Logo = l
	doc := mine.Canonical()
	if !bytes.HasSuffix(doc, []byte("  \"logo\": {\n    \"png\": \""+l.PNG+"\"\n  }\n}\n")) {
		t.Fatalf("the logo is not the last key:\n%s", doc)
	}
	got, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got != mine || !bytes.Equal(got.Canonical(), doc) {
		t.Fatal("a design with a logo did not round-trip")
	}
	if mine.SHA256() == plain.SHA256() {
		t.Fatal("the hash does not cover the logo")
	}
	// The 16 KB does not count the logo, but counts everything else.
	big, err := NormalizeLogo(noise(t, 300, 300))
	if err != nil {
		t.Fatal(err)
	}
	if len(big.PNG) < MaxDocumentBytes {
		t.Fatalf("the noisy logo is only %d bytes of base64", len(big.PNG))
	}
	mine.Logo = big
	if _, err := Parse(mine.Canonical()); err != nil {
		t.Fatalf("a design with a %d-byte logo field: %v", len(big.PNG), err)
	}
	padded := append([]byte("{"+strings.Repeat(" ", MaxDocumentBytes)), mine.Canonical()[1:]...)
	var fe *FieldError
	if _, err := Parse(padded); !errors.As(err, &fe) || fe.Field != "" || !strings.Contains(fe.Message, "without its logo") {
		t.Fatalf("16 KB besides the logo: %v", err)
	}
}

// noise is a PNG of random-looking pixels, which compresses badly.
func noise(t *testing.T, w, h int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	x := uint32(2463534242)
	for i := range img.Pix {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		img.Pix[i] = byte(x)
	}
	return encodePNG(t, img)
}

// A design's logo field is held to what NormalizeLogo writes: a PNG in
// standard base64 within the bounds. Each refusal names logo or logo.png.
func TestDesignLogoRefusals(t *testing.T) {
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, solid(8, 8, color.White), nil); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	wide := encodePNG(t, solid(MaxLogoSide+1, 2, color.Black))
	for _, c := range []struct {
		name  string
		logo  any
		field string
		kind  error
	}{
		{"a URL", "https://x.example/logo.png", "logo", nil},
		{"no png", map[string]any{}, "logo.png", nil},
		{"empty png", map[string]any{"png": ""}, "logo.png", nil},
		{"another key", map[string]any{"png": b64(encodePNG(t, solid(2, 2, color.Black))), "url": "https://x.example"}, "", nil},
		{"not base64", map[string]any{"png": "not base64!"}, "logo.png", ErrLogoFormat},
		{"base64 in lines", map[string]any{"png": func() string {
			b := b64(encodePNG(t, solid(2, 2, color.Black)))
			return b[:8] + "\r\n" + b[8:]
		}()}, "logo.png", ErrLogoFormat},
		{"a JPEG", map[string]any{"png": b64(jb.Bytes())}, "logo.png", ErrLogoFormat},
		{"wider than the bound", map[string]any{"png": b64(wide)}, "logo.png", ErrLogoTooLarge},
		{"a header that lies", map[string]any{"png": b64(withSize(encodePNG(t, solid(4, 4, color.Black)), 8, 8))}, "logo.png", ErrLogoFormat},
	} {
		var m map[string]any
		_ = json.Unmarshal(Default().Canonical(), &m)
		m["logo"] = c.logo
		doc, _ := json.Marshal(m)
		_, err := Parse(doc)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != c.field || (c.kind != nil && !errors.Is(err, c.kind)) {
			t.Errorf("%s: %v, want a refusal on %q", c.name, err, c.field)
		}
	}
}

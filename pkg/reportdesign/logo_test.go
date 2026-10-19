package reportdesign

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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

// paddedPNG is a small valid PNG followed by zero bytes up to n bytes in all:
// a decoder stops at IEND, so only the length is the file's own.
func paddedPNG(t *testing.T, n int) []byte {
	t.Helper()
	small := encodePNG(t, solid(4, 4, color.Black))
	if n < len(small) {
		t.Fatalf("a PNG is %d bytes, not %d", len(small), n)
	}
	return append(small, make([]byte, n-len(small))...)
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

		// Each bound at its own edge, and each refusal its own kind.
		{"a PNG cut inside its header", small[:20], ErrLogoFormat},
		{"one byte over 512 KB", paddedPNG(t, MaxLogoUploadBytes+1), ErrLogoTooLarge},
		{"a header one pixel row over 4096 squared", withSize(small, 4096, 4097), ErrLogoTooLarge},
		{"a header claiming four billion pixels", withSize(small, 65536, 65536), ErrLogoTooLarge},
		{"a header one pixel over 4096 squared", withSize(small, 257, 65281), ErrLogoTooLarge},
		{"a header with no width", withSize(small, 0, 4), ErrLogoFormat},
		{"a header with no height", withSize(small, 4, 0), ErrLogoFormat},
		{"a header at the pixel limit that the pixels do not fill", withSize(small, 4096, 4096), ErrLogoFormat},
		{"a JPEG too detailed for 512 KB as a PNG", noiseJPEG(t, 800, 800, 10), ErrLogoTooLarge},
	} {
		_, err := NormalizeLogo(c.data)
		var fe *FieldError
		if !errors.Is(err, c.kind) || !errors.As(err, &fe) || fe.Field != "logo" {
			t.Errorf("%s: %v, want %v on logo", c.name, err, c.kind)
			continue
		}
		if other := map[error]error{ErrLogoFormat: ErrLogoTooLarge, ErrLogoTooLarge: ErrLogoFormat}[c.kind]; errors.Is(err, other) {
			t.Errorf("%s: %v is also %v", c.name, err, other)
		}
		if want := map[string]string{
			"svg":                         "a logo is a PNG or a JPEG",
			"gif":                         "a logo is a PNG or a JPEG",
			"empty":                       "a logo is a PNG or a JPEG",
			"a PNG cut inside its header": "a logo is a PNG or a JPEG",
			"truncated png":               "does not decode",
			"a header at the pixel limit that the pixels do not fill": "does not decode",
			"over 512 KB":                              "a logo is at most 512 KB",
			"one byte over 512 KB":                     "a logo is at most 512 KB",
			"a header claiming 20 million pixels":      "at most 16 million pixels",
			"a header one pixel row over 4096 squared": "at most 16 million pixels",
			"a header claiming four billion pixels":    "at most 16 million pixels",
			"a header one pixel over 4096 squared":     "at most 16 million pixels",
			"a header with no width":                   "a logo is a PNG or a JPEG",
			"a header with no height":                  "a logo is a PNG or a JPEG",
			"a JPEG too detailed for 512 KB as a PNG":  "over 512 KB as a PNG",
		}[c.name]; !strings.Contains(fe.Message, want) {
			t.Errorf("%s: refused with %q, want it to say %q", c.name, fe.Message, want)
		}
	}

	// An upload of exactly 512 KB is read; a decoder stops at IEND.
	if l, err := NormalizeLogo(paddedPNG(t, MaxLogoUploadBytes)); err != nil || l.PNG == "" {
		t.Errorf("an upload of exactly %d bytes: %v", MaxLogoUploadBytes, err)
	}
}

// noiseJPEG is a JPEG of random-looking pixels: small as a JPEG at a low
// quality, large once decoded and written as a PNG.
func noiseJPEG(t *testing.T, w, h, quality int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	x := uint32(2463534242)
	for i := range img.Pix {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		img.Pix[i] = byte(x)
		if i%4 == 3 {
			img.Pix[i] = 255
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatal(err)
	}
	if b.Len() > MaxLogoUploadBytes {
		t.Fatalf("the noisy JPEG is %d bytes, over the upload limit", b.Len())
	}
	return b.Bytes()
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

	// A partly transparent colour is read as premultiplied alpha and written
	// back the same: scaling a uniform image changes nothing.
	l, err = NormalizeLogo(encodePNG(t, solid(1025, 2, color.NRGBA{R: 200, G: 100, B: 50, A: 128})))
	if err != nil {
		t.Fatal(err)
	}
	if c := color.NRGBAModel.Convert(decodeLogo(t, l).At(7, 1)).(color.NRGBA); c.A != 128 || c.R < 198 || c.R > 202 || c.G < 98 || c.G > 102 || c.B < 48 || c.B > 52 {
		t.Errorf("a uniform half-transparent image reads %v after scaling, want (200,100,50,128)", c)
	}

	// The new size is rounded, never below one pixel, and a logo inside the
	// bound keeps its size.
	for _, c := range []struct{ w, h, wantW, wantH int }{
		{1025, 3, 1024, 3},
		{3, 1025, 3, 1024},
		{4000, 2, 1024, 1},
		{2, 4000, 1, 1024},
		{4000, 1, 1024, 1},
		{1, 4000, 1, 1024},
		{1025, 531, 1024, 530},
		{531, 1025, 530, 1024},
		{1024, 1024, 1024, 1024},
		{1024, 7, 1024, 7},
	} {
		l, err := NormalizeLogo(encodePNG(t, solid(c.w, c.h, color.NRGBA{R: 10, G: 20, B: 30, A: 255})))
		if err != nil {
			t.Errorf("%d×%d: %v", c.w, c.h, err)
			continue
		}
		if b := decodeLogo(t, l).Bounds(); b.Dx() != c.wantW || b.Dy() != c.wantH {
			t.Errorf("%d×%d scaled to %v, want %d×%d", c.w, c.h, b, c.wantW, c.wantH)
		}
	}

	// A ratio that is not a whole number weighs each source pixel by the
	// area it covers: 1536×3 becomes 1024×2, each new pixel 1.5 source pixels
	// across, and the red channel runs with the column, the green with the row
	// (0, 92 and 241 in the first three).
	ramp := func(i int) uint8 { return [3]uint8{0, 92, 241}[min(i, 2)] }
	weighted := image.NewNRGBA(image.Rect(0, 0, 1536, 3))
	for y := range 3 {
		for x := range 1536 {
			r := uint8(0)
			if x < 3 {
				r = ramp(x)
			}
			weighted.Set(x, y, color.NRGBA{R: r, G: ramp(y), A: 255})
		}
	}
	l, err = NormalizeLogo(encodePNG(t, weighted))
	if err != nil {
		t.Fatal(err)
	}
	got = decodeLogo(t, l)
	if b := got.Bounds(); b.Dx() != 1024 || b.Dy() != 2 {
		t.Fatalf("1536×3 scaled to %v, want 1024×2", b)
	}
	for _, c := range []struct {
		x, y int
		want color.NRGBA
	}{
		{0, 0, color.NRGBA{R: 31, G: 31, A: 255}},  // (0·1 + 92·0.5) / 1.5 = 30.67
		{1, 0, color.NRGBA{R: 191, G: 31, A: 255}}, // (92·0.5 + 241·1) / 1.5 = 191.33
		{0, 1, color.NRGBA{R: 31, G: 191, A: 255}},
		{1, 1, color.NRGBA{R: 191, G: 191, A: 255}},
	} {
		if c2 := color.NRGBAModel.Convert(got.At(c.x, c.y)).(color.NRGBA); c2 != c.want {
			t.Errorf("pixel (%d,%d) reads %v, want %v", c.x, c.y, c2, c.want)
		}
	}

	// The last source column and row are read when the size rounds so that
	// the new pixels cover slightly more than one source pixel each.
	edge := image.NewNRGBA(image.Rect(0, 0, 1025, 2))
	edge.Set(1024, 0, color.NRGBA{R: 255, A: 255})
	edge.Set(1024, 1, color.NRGBA{R: 255, A: 255})
	l, err = NormalizeLogo(encodePNG(t, edge))
	if err != nil {
		t.Fatal(err)
	}
	got = decodeLogo(t, l)
	if b := got.Bounds(); b.Dx() != 1024 || b.Dy() != 2 {
		t.Fatalf("1025×2 scaled to %v, want 1024×2", b)
	}
	if r, _, _, a := got.At(1023, 0).RGBA(); a == 0 || r*0xff/a < 0xf8 {
		t.Errorf("the last column of 1025×2 is lost: %v", got.At(1023, 0))
	}
	edge = image.NewNRGBA(image.Rect(0, 0, 2, 1025))
	edge.Set(0, 1024, color.NRGBA{G: 255, A: 255})
	edge.Set(1, 1024, color.NRGBA{G: 255, A: 255})
	l, err = NormalizeLogo(encodePNG(t, edge))
	if err != nil {
		t.Fatal(err)
	}
	got = decodeLogo(t, l)
	if b := got.Bounds(); b.Dx() != 2 || b.Dy() != 1024 {
		t.Fatalf("2×1025 scaled to %v, want 2×1024", b)
	}
	if _, g, _, a := got.At(0, 1023).RGBA(); a == 0 || g*0xff/a < 0xf8 {
		t.Errorf("the last row of 2×1025 is lost: %v", got.At(0, 1023))
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

	// The 16 KB to the byte, with a logo and without one: leading blanks make
	// up the difference, and the document is read at the limit and refused
	// one byte past it.
	withBlanks := func(doc []byte, n int) []byte { return append(bytes.Repeat([]byte(" "), n), doc...) }
	mine.Logo = l
	withLogo := mine.Canonical()
	for _, c := range []struct {
		name    string
		doc     []byte
		counted int // the bytes the limit counts
	}{
		{"without a logo", plain.Canonical(), len(plain.Canonical())},
		{"with a logo", withLogo, len(withLogo) - len(l.PNG)},
	} {
		if _, err := Parse(withBlanks(c.doc, MaxDocumentBytes-c.counted)); err != nil {
			t.Errorf("%s: a document of exactly %d bytes besides the logo: %v", c.name, MaxDocumentBytes, err)
		}
		_, err := Parse(withBlanks(c.doc, MaxDocumentBytes-c.counted+1))
		if !errors.As(err, &fe) || fe.Field != "" || !strings.Contains(fe.Message, "without its logo") {
			t.Errorf("%s: a document one byte over %d: %v", c.name, MaxDocumentBytes, err)
		}
	}

	// Past the most a document may be with a logo field of the largest size,
	// it is refused as a whole before it is read; at that size it is read, and
	// the logo field is the refusal.
	limit := MaxDocumentBytes + maxLogoField + len(`"logo":{"png":""}`)
	asSent := func(fieldLen int) []byte {
		return []byte(strings.TrimSuffix(string(plain.Canonical()), "\n}\n") + `,"logo":{"png":"` + strings.Repeat("A", fieldLen) + `"}}`)
	}
	fieldLen := limit - len(asSent(0))
	if doc := asSent(fieldLen); len(doc) != limit {
		t.Fatalf("the test document is %d bytes, want %d", len(doc), limit)
	}
	if _, err := Parse(asSent(fieldLen)); !errors.As(err, &fe) || fe.Field != "logo.png" || !errors.Is(err, ErrLogoTooLarge) {
		t.Errorf("a document at the size limit with a logo field of %d: %v, want the logo refused as too large", fieldLen, err)
	}
	// The early refusal counts the whole document, the logo field included,
	// and says so; it does not call that count "without its logo".
	over := asSent(fieldLen + 1)
	want := fmt.Sprintf("the document is %d bytes, over the %d bytes a document may be with its logo", len(over), limit)
	if _, err := Parse(over); !errors.As(err, &fe) || fe.Field != "" || fe.Message != want {
		t.Errorf("a document one byte over the size limit: %v, want the document refused as a whole saying %q", err, want)
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
	tall := encodePNG(t, solid(2, MaxLogoSide+1, color.Black))
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

		// The base64 has one form: no bare CR or LF, no spare bits in the
		// last character.
		{"base64 with a bare CR", map[string]any{"png": func() string {
			b := b64(encodePNG(t, solid(2, 2, color.Black)))
			return b[:8] + "\r" + b[8:]
		}()}, "logo.png", ErrLogoFormat},
		{"base64 with a bare LF", map[string]any{"png": func() string {
			b := b64(encodePNG(t, solid(2, 2, color.Black)))
			return b[:8] + "\n" + b[8:]
		}()}, "logo.png", ErrLogoFormat},
		{"base64 with spare bits in the last character", map[string]any{"png": func() string {
			data := encodePNG(t, solid(2, 2, color.Black))
			for len(data)%3 == 0 {
				data = append(data, 0)
			}
			b := b64(data)
			i := strings.IndexByte(b, '=')
			const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			return b[:i-1] + string(alphabet[strings.IndexByte(alphabet, b[i-1])^1]) + b[i:]
		}()}, "logo.png", ErrLogoFormat},
		{"taller than the bound", map[string]any{"png": b64(tall)}, "logo.png", ErrLogoTooLarge},
		{"one byte over 512 KB", map[string]any{"png": b64(paddedPNG(t, MaxLogoBytes+1))}, "logo.png", ErrLogoTooLarge},
		{"a field over the largest base64", map[string]any{"png": b64(paddedPNG(t, MaxLogoBytes+3))}, "logo.png", ErrLogoTooLarge},
	} {
		var m map[string]any
		_ = json.Unmarshal(Default().Canonical(), &m)
		m["logo"] = c.logo
		doc, _ := json.Marshal(m)
		_, err := Parse(doc)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != c.field || (c.kind != nil && !errors.Is(err, c.kind)) {
			t.Errorf("%s: %v, want a refusal on %q", c.name, err, c.field)
			continue
		}
		if other := map[error]error{ErrLogoFormat: ErrLogoTooLarge, ErrLogoTooLarge: ErrLogoFormat}[c.kind]; other != nil && errors.Is(err, other) {
			t.Errorf("%s: %v is also %v", c.name, err, other)
		}
		if want := map[string]string{
			"no png":                "is required",
			"empty png":             "must not be empty",
			"not base64":            "must be a PNG in standard base64",
			"base64 in lines":       "must be a PNG in standard base64",
			"a JPEG":                "must be a PNG in standard base64",
			"base64 with a bare CR": "must be a PNG in standard base64",
			"base64 with a bare LF": "must be a PNG in standard base64",
			"base64 with spare bits in the last character": "must be a PNG in standard base64",
			"wider than the bound":                         "at most 1024 pixels each way",
			"taller than the bound":                        "at most 1024 pixels each way",
			"a header that lies":                           "the PNG does not decode",
			"one byte over 512 KB":                         "a logo is at most 512 KB",
			"a field over the largest base64":              "a logo is at most 512 KB",
		}[c.name]; !strings.Contains(fe.Message, want) {
			t.Errorf("%s: refused with %q, want it to say %q", c.name, fe.Message, want)
		}
	}

	// What sits exactly on a bound is a logo: 1024 pixels each way, and
	// 512 KB of PNG (which is the largest base64 field too).
	for name, png := range map[string][]byte{
		"1024 pixels wide": encodePNG(t, solid(MaxLogoSide, 1, color.Black)),
		"1024 pixels tall": encodePNG(t, solid(1, MaxLogoSide, color.Black)),
		"512 KB":           paddedPNG(t, MaxLogoBytes),
	} {
		var m map[string]any
		_ = json.Unmarshal(Default().Canonical(), &m)
		m["logo"] = map[string]any{"png": b64(png)}
		doc, _ := json.Marshal(m)
		if _, err := Parse(doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// "logo": null is the same as no logo key: the design is read without a
// logo and its canonical form has no logo key, whichever way it was written.
func TestLogoNullIsNoLogo(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(Default().Canonical(), &m); err != nil {
		t.Fatal(err)
	}
	m["logo"] = nil
	doc, _ := json.Marshal(m)
	d, err := Parse(doc)
	if err != nil {
		t.Fatalf(`"logo": null: %v`, err)
	}
	if d.Logo != (Logo{}) || !bytes.Equal(d.Canonical(), Default().Canonical()) {
		t.Errorf(`"logo": null did not read as no logo: %s`, d.Canonical())
	}
}

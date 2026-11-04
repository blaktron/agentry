package reportdesign

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"reflect"
	"strings"
	"testing"
)

// jpegWithComment is a JPEG of a solid colour with a COM segment after its
// SOI marker: a piece of the upload that is not pixels.
func jpegWithComment(t *testing.T, w, h int, c color.Color, comment string) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, solid(w, h, c), &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	seg := []byte{0xff, 0xfe, byte((len(comment) + 2) >> 8), byte(len(comment) + 2)}
	seg = append(seg, comment...)
	return append(append(append([]byte{}, data[:2]...), seg...), data[2:]...)
}

// NormalizeCoverImage keeps only the pixels: a PNG stays a PNG with its text
// chunks gone, a JPEG stays a JPEG with its comment gone, each is scaled to
// fit the bound, and a refusal names its kind.
func TestNormalizeCoverImageKeepsOnlyThePixels(t *testing.T) {
	// A PNG with a text chunk.
	src := encodePNG(t, solid(300, 200, color.NRGBA{R: 30, G: 90, B: 200, A: 255}))
	tagged := withChunk(src, "tEXt", append(append([]byte("Comment"), 0), "secret note"...))
	img, err := NormalizeCoverImage(tagged)
	if err != nil {
		t.Fatal(err)
	}
	data, format, err := img.Decode()
	if err != nil || format != "png" || img.JPEG != "" {
		t.Fatalf("a PNG came back as %s (%v)", format, err)
	}
	if bytes.Contains(data, []byte("secret note")) || bytes.Contains(data, []byte("tEXt")) {
		t.Fatal("the PNG's text chunk survived")
	}
	cfg, _, _ := image.DecodeConfig(bytes.NewReader(data))
	if cfg.Width != 300 || cfg.Height != 200 {
		t.Fatalf("a PNG within the bound was resized to %dx%d", cfg.Width, cfg.Height)
	}

	// A JPEG with a comment.
	jsrc := jpegWithComment(t, 400, 300, color.NRGBA{R: 200, G: 40, B: 40, A: 255}, "camera make and place")
	img, err = NormalizeCoverImage(jsrc)
	if err != nil {
		t.Fatal(err)
	}
	data, format, err = img.Decode()
	if err != nil || format != "jpeg" || img.PNG != "" {
		t.Fatalf("a JPEG came back as %s (%v)", format, err)
	}
	if bytes.Contains(data, []byte("camera make")) {
		t.Fatal("the JPEG's comment survived")
	}
	if decoded, _, err := image.Decode(bytes.NewReader(data)); err != nil || decoded.Bounds().Dx() != 400 {
		t.Fatalf("the JPEG does not decode: %v", err)
	}

	// Scaled down to fit 2048, the aspect kept.
	big := encodePNG(t, solid(4096, 1024, color.Black))
	img, err = NormalizeCoverImage(big)
	if err != nil {
		t.Fatal(err)
	}
	data, _, _ = img.Decode()
	cfg, _, _ = image.DecodeConfig(bytes.NewReader(data))
	if cfg.Width != MaxCoverImageSide || cfg.Height != 512 {
		t.Fatalf("4096x1024 became %dx%d", cfg.Width, cfg.Height)
	}
	// A JPEG scaled down stays a JPEG.
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, solid(1000, 3000, color.White), nil); err != nil {
		t.Fatal(err)
	}
	img, err = NormalizeCoverImage(jb.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	data, format, _ = img.Decode()
	cfg, _, _ = image.DecodeConfig(bytes.NewReader(data))
	if format != "jpeg" || cfg.Height != MaxCoverImageSide || cfg.Width != 683 {
		t.Fatalf("1000x3000 JPEG became %s %dx%d", format, cfg.Width, cfg.Height)
	}

	// Refusals: over the upload cap, not an image, a GIF, too many
	// pixels, a header that lies, and a PNG too detailed for the cap.
	for _, c := range []struct {
		name   string
		upload []byte
		kind   error
		msg    string
	}{
		{"over 2 MB", append(src, bytes.Repeat([]byte{0}, MaxCoverImageUploadBytes)...), ErrImageTooLarge, "at most 2 MB"},
		{"not an image", []byte("<svg xmlns='http://www.w3.org/2000/svg'/>"), ErrImageFormat, "a PNG or a JPEG"},
		{"a GIF", []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00;"), ErrImageFormat, "a PNG or a JPEG"},
		{"too many pixels", withSize(src, 5000, 5000), ErrImageTooLarge, "at most 16 million pixels"},
		{"a header that lies", withSize(src, 301, 200), ErrImageFormat, "does not decode"},
		{"empty", nil, ErrImageFormat, "a PNG or a JPEG"},
	} {
		_, err := NormalizeCoverImage(c.upload)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "coverImage" || !errors.Is(err, c.kind) || !strings.Contains(fe.Message, c.msg) {
			t.Errorf("%s: %v, want %v on coverImage saying %q", c.name, err, c.kind, c.msg)
		}
	}
	// The logo's kinds are the image's.
	if !errors.Is(ErrLogoTooLarge, ErrImageTooLarge) || !errors.Is(ErrLogoFormat, ErrImageFormat) {
		t.Fatal("the logo's refusal kinds differ from the image's")
	}
}

// A design carries its cover image and its custom cover after the logo, only
// when it has them, and round-trips byte for byte with them; the hash
// covers them; WithoutAssets drops all three.
func TestDesignWithImagesRoundTrips(t *testing.T) {
	plain := Default()
	for _, key := range []string{`"coverImage"`, `"customCover"`} {
		if bytes.Contains(plain.Canonical(), []byte(key)) {
			t.Fatalf("a design without one writes %s", key)
		}
	}
	logo, err := NormalizeLogo(encodePNG(t, solid(64, 32, color.NRGBA{R: 200, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, solid(640, 480, color.NRGBA{G: 120, A: 255}), nil); err != nil {
		t.Fatal(err)
	}
	coverImage, err := NormalizeCoverImage(jb.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	img1, _ := NormalizeCustomCoverImage(encodePNG(t, solid(10, 10, color.Black)))
	img2, _ := NormalizeCustomCoverImage(jb.Bytes())
	thumb, err := NormalizeThumbnail(encodePNG(t, solid(200, 280, color.White)))
	if err != nil {
		t.Fatal(err)
	}
	mine := plain
	mine.Cover.Style = "custom"
	mine.Logo = logo
	mine.CoverImage = coverImage
	mine.CustomCover = CustomCover{Source: "#let cover(meta, design) = [\n  #align(center)[#text(size: 40pt)[#meta.title]]\n]\n", Images: []Image{img1, img2}, Thumbnail: thumb}
	doc := mine.Canonical()
	for _, want := range []string{`  "logo": {`, `  "coverImage": {`, `    "jpeg": "`, `  "customCover": {`, `    "source": "#let cover(meta, design) = [\n`, `    "images": [`, `    "thumbnail": {`} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Fatalf("the document lacks %q:\n%.600s", want, doc)
		}
	}
	if i, j, k := bytes.Index(doc, []byte(`"logo"`)), bytes.Index(doc, []byte(`"coverImage"`)), bytes.Index(doc, []byte(`"customCover"`)); !(i < j && j < k) {
		t.Fatal("the assets are not the last keys in order")
	}
	got, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, mine) || !bytes.Equal(got.Canonical(), doc) {
		t.Fatal("a design with images did not round-trip")
	}
	if mine.SHA256() == plain.SHA256() {
		t.Fatal("the hash does not cover the images")
	}
	without := got.WithoutAssets()
	without.Cover.Style = plain.Cover.Style
	if !reflect.DeepEqual(without, plain) {
		t.Fatalf("WithoutAssets left something: %s", without.Canonical())
	}
	// The projection carries the logo and drops the rest.
	v2 := got.Version2()
	if !bytes.Contains(v2, []byte(`"logo"`)) || bytes.Contains(v2, []byte(`"coverImage"`)) || bytes.Contains(v2, []byte(`"customCover"`)) {
		t.Fatalf("the projection: %.300s", v2)
	}
	// The document's cap does not count the assets: a custom cover at its
	// source bound, with 2 MB of images, is a design.
	mine.CustomCover.Source = strings.Repeat("/", MaxCoverSourceBytes)
	mine.CustomCover.Images = nil
	if _, err := Parse(mine.Canonical()); err != nil {
		t.Fatalf("a source at the bound: %v", err)
	}
	// A custom cover with no images writes an empty list, and null for one
	// reads as none.
	if !bytes.Contains(mine.Canonical(), []byte(`"images": []`)) {
		t.Fatalf("no images did not write []: %.300s", mine.Canonical())
	}
	var m map[string]any
	_ = json.Unmarshal(plain.Canonical(), &m)
	m["coverImage"], m["customCover"], m["logo"] = nil, nil, nil
	d, err := Parse(mustJSON(t, m))
	if err != nil || !bytes.Equal(d.Canonical(), plain.Canonical()) {
		t.Fatalf("null assets: %v", err)
	}
}

// The custom cover and the cover image are held to their bounds, each
// refusal naming the field and its kind.
func TestCustomCoverAndCoverImageRefusals(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	small := b64(encodePNG(t, solid(4, 4, color.Black)))
	var jb bytes.Buffer
	_ = jpeg.Encode(&jb, solid(4, 4, color.White), nil)
	smallJPEG := b64(jb.Bytes())
	wide := b64(encodePNG(t, solid(MaxCoverImageSide+1, 1, color.Black)))
	bigPNG := b64(paddedPNG(t, MaxThumbnailBytes+1))
	sixImages := func() []any {
		out := make([]any, 0, MaxCoverImages+1)
		for range MaxCoverImages + 1 {
			out = append(out, map[string]any{"png": small})
		}
		return out
	}
	// 2 MB in all: three images of just over a third each.
	third := b64(paddedPNG(t, MaxCoverImagesBytes/3+1))
	cover := func(source string, images []any, thumb any) map[string]any {
		c := map[string]any{"source": source, "images": images}
		if thumb != nil {
			c["thumbnail"] = thumb
		}
		return c
	}
	for _, c := range []struct {
		name  string
		path  string
		value any
		field string
		kind  error
		msg   string
	}{
		{"cover image by URL", "coverImage", map[string]any{"png": "https://x.example/a.png"}, "coverImage", ErrImageFormat, "must be a PNG or a JPEG in standard base64"},
		{"cover image with both", "coverImage", map[string]any{"png": small, "jpeg": smallJPEG}, "coverImage", nil, "not both"},
		{"cover image with neither", "coverImage", map[string]any{}, "coverImage", nil, "must hold a png or a jpeg"},
		{"cover image empty png", "coverImage", map[string]any{"png": ""}, "coverImage.png", nil, "must not be empty"},
		{"cover image empty jpeg", "coverImage", map[string]any{"jpeg": ""}, "coverImage.jpeg", nil, "must not be empty"},
		{"cover image another key", "coverImage", map[string]any{"png": small, "url": "x"}, "", nil, `unknown key "url"`},
		{"a JPEG under png", "coverImage", map[string]any{"png": smallJPEG}, "coverImage", ErrImageFormat, "must be a PNG under its key"},
		{"a PNG under jpeg", "coverImage", map[string]any{"jpeg": small}, "coverImage", ErrImageFormat, "must be a JPEG under its key"},
		{"cover image too wide", "coverImage", map[string]any{"png": wide}, "coverImage", ErrImageTooLarge, "over its pixel limit"},
		{"cover image over 2 MB", "coverImage", map[string]any{"png": b64(paddedPNG(t, MaxCoverImageBytes+1))}, "coverImage", ErrImageTooLarge, "over its byte limit"},
		{"custom cover no source", "customCover", map[string]any{"images": []any{}}, "customCover.source", nil, "is required"},
		{"custom cover no images", "customCover", map[string]any{"source": "x"}, "customCover.images", nil, "is required"},
		{"custom cover empty source", "customCover", cover("  \n", []any{}, nil), "customCover.source", nil, "must not be empty"},
		{"custom cover source over 32 KiB", "customCover", cover(strings.Repeat("x", MaxCoverSourceBytes+1), []any{}, nil), "customCover.source", nil, "is 32769 bytes, over the limit of 32768"},
		{"custom cover source with NUL", "customCover", cover("#let x = 1\x00", []any{}, nil), "customCover.source", nil, "no control character but a tab or a line break"},
		{"custom cover source with an escape", "customCover", cover("\x1b[31m", []any{}, nil), "customCover.source", nil, "no control character"},
		{"custom cover seven images", "customCover", cover("x", sixImages(), nil), "customCover.images", nil, "is 7 images, over the limit of 6"},
		{"custom cover image by URL", "customCover", cover("x", []any{map[string]any{"png": "https://x.example/a.png"}}, nil), "customCover.images.0", ErrImageFormat, "standard base64"},
		{"custom cover second image too wide", "customCover", cover("x", []any{map[string]any{"png": small}, map[string]any{"png": wide}}, nil), "customCover.images.1", ErrImageTooLarge, "over its pixel limit"},
		{"custom cover image with neither", "customCover", cover("x", []any{map[string]any{}}, nil), "customCover.images.0", nil, "must hold a png or a jpeg"},
		{"custom cover images over 2 MB in all", "customCover", cover("x", []any{map[string]any{"png": third}, map[string]any{"png": third}, map[string]any{"png": third}}, nil), "customCover.images", ErrImageTooLarge, "over 2 MB in all"},
		{"custom cover thumbnail a JPEG", "customCover", cover("x", []any{}, map[string]any{"jpeg": smallJPEG}), "customCover.thumbnail", ErrImageFormat, "must be a PNG"},
		{"custom cover thumbnail over 300 KB", "customCover", cover("x", []any{}, map[string]any{"png": bigPNG}), "customCover.thumbnail", ErrImageTooLarge, "over its byte limit"},
		{"custom cover thumbnail by URL", "customCover", cover("x", []any{}, map[string]any{"png": "https://x.example/t.png"}), "customCover.thumbnail", ErrImageFormat, "standard base64"},
		{"custom cover another key", "customCover", map[string]any{"source": "x", "images": []any{}, "fonts": []any{}}, "", nil, `unknown key "fonts"`},
		{"custom cover as a string", "customCover", "#page[]", "customCover", nil, "must be an object"},
		{"images as a string", "customCover", map[string]any{"source": "x", "images": "a.png"}, "customCover.images", nil, "must be an array"},
	} {
		var m map[string]any
		_ = json.Unmarshal(Default().Canonical(), &m)
		m[c.path] = c.value
		_, err := Parse(mustJSON(t, m))
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != c.field || (c.kind != nil && !errors.Is(err, c.kind)) {
			t.Errorf("%s: %v, want a refusal on %q", c.name, err, c.field)
			continue
		}
		if !strings.Contains(fe.Message, c.msg) {
			t.Errorf("%s: refused with %q, want it to say %q", c.name, fe.Message, c.msg)
		}
		if c.kind == nil && (errors.Is(err, ErrImageFormat) || errors.Is(err, ErrImageTooLarge)) {
			t.Errorf("%s: %v wraps an image kind", c.name, err)
		}
	}
	// On the bounds: six images of 2 MB in all, a 32 KiB source, a 300 KB
	// thumbnail, a 2048-pixel cover image.
	var m map[string]any
	_ = json.Unmarshal(Default().Canonical(), &m)
	sixth := b64(paddedPNG(t, MaxCoverImagesBytes/6))
	images := make([]any, 0, MaxCoverImages)
	for range MaxCoverImages {
		images = append(images, map[string]any{"png": sixth})
	}
	m["customCover"] = cover(strings.Repeat("x", MaxCoverSourceBytes), images, map[string]any{"png": b64(paddedPNG(t, MaxThumbnailBytes))})
	m["coverImage"] = map[string]any{"png": b64(encodePNG(t, solid(MaxCoverImageSide, MaxCoverImageSide, color.Black)))}
	if _, err := Parse(mustJSON(t, m)); err != nil {
		t.Fatalf("on the bounds: %v", err)
	}
	// The normalizers for a custom cover's images and its thumbnail.
	if _, err := NormalizeThumbnail(jb.Bytes()); !errors.Is(err, ErrImageFormat) {
		t.Errorf("a JPEG thumbnail: %v", err)
	}
	if _, err := NormalizeThumbnail(noise(t, 400, 400)); !errors.Is(err, ErrImageTooLarge) {
		t.Errorf("a 400x400 noise thumbnail (over 300 KB): %v", err)
	}
	img, err := NormalizeCustomCoverImage(jb.Bytes())
	if err != nil || img.Format() != "jpeg" {
		t.Errorf("a JPEG custom cover image: %v, %s", err, img.Format())
	}
	if _, err := NormalizeCustomCoverImage([]byte("no")); err == nil {
		t.Error("a non-image custom cover image")
	}
}

// SuggestColours reads a logo's two dominant colours, ignoring its white
// and transparent background, and offers passing shades of each; a logo of
// one colour has no secondary, and one with no colour none at all.
func TestSuggestColours(t *testing.T) {
	// A logo: a red mark over a blue one on a white ground, with a
	// transparent corner.
	img := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	for y := range 100 {
		for x := range 100 {
			switch {
			case x < 20 && y < 20:
				img.Set(x, y, color.NRGBA{R: 1, G: 2, B: 3, A: 0}) // transparent
			case y < 60:
				img.Set(x, y, color.NRGBA{R: 220, G: 40, B: 40, A: 255}) // red, most
			case y < 85:
				img.Set(x, y, color.NRGBA{R: 30, G: 60, B: 200, A: 255}) // blue, next
			default:
				img.Set(x, y, color.White)
			}
		}
	}
	s, err := SuggestColours(encodePNG(t, img))
	if err != nil {
		t.Fatal(err)
	}
	if s.FromAccent != "#dc2828" || s.FromSecondary != "#1e3cc8" {
		t.Fatalf("read %s and %s, want the red and the blue", s.FromAccent, s.FromSecondary)
	}
	for _, c := range []string{s.Accent, s.Secondary} {
		if onWhite(c) < TextContrast {
			t.Errorf("%s does not pass for text", c)
		}
	}
	if near, _ := NearestPassing("#dc2828", TextContrast); s.Accent != near {
		t.Errorf("the accent %s is not the nearest passing shade %s", s.Accent, near)
	}
	// One colour: no secondary. A near shade of it is the same colour.
	one := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	for y := range 10 {
		for x := range 10 {
			c := color.NRGBA{R: 20, G: 20, B: 20, A: 255}
			if x%2 == 0 {
				c = color.NRGBA{R: 24, G: 22, B: 20, A: 255}
			}
			one.Set(x, y, c)
		}
	}
	s, err = SuggestColours(encodePNG(t, one))
	if err != nil || s.Secondary != "" || s.FromSecondary != "" || s.Accent == "" {
		t.Fatalf("one colour: %+v, %v", s, err)
	}
	// A colour a twentieth as common as the first is not a secondary.
	rare := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	for y := range 100 {
		for x := range 100 {
			c := color.NRGBA{R: 0, G: 100, B: 0, A: 255}
			if x == 0 && y < 4 {
				c = color.NRGBA{R: 250, G: 0, B: 0, A: 255}
			}
			rare.Set(x, y, c)
		}
	}
	if s, _ := SuggestColours(encodePNG(t, rare)); s.Secondary != "" {
		t.Errorf("a rare colour became the secondary: %+v", s)
	}
	// White and transparent alone: nothing to suggest.
	blank := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	for y := range 10 {
		for x := range 10 {
			if x < 5 {
				blank.Set(x, y, color.White)
			}
		}
	}
	if _, err := SuggestColours(encodePNG(t, blank)); !errors.Is(err, ErrNoColour) {
		t.Errorf("a blank logo: %v", err)
	}
	if _, err := SuggestColours([]byte("not an image")); err == nil {
		t.Error("not an image suggested colours")
	}
	// A JPEG logo reads too.
	var jb bytes.Buffer
	_ = jpeg.Encode(&jb, solid(20, 20, color.NRGBA{R: 10, G: 80, B: 10, A: 255}), nil)
	if s, err := SuggestColours(jb.Bytes()); err != nil || s.Accent == "" {
		t.Errorf("a JPEG logo: %+v, %v", s, err)
	}
}

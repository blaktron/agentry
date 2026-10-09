package reportdesign

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
)

// Every built-in validates, its embedded document is exactly its Canonical,
// and parsing that document gives the same design back (invariant 8, D14).
func TestBuiltinsRoundTripByteForByte(t *testing.T) {
	if got := BuiltinIDs(); !slices.Equal(got, []string{"plain", "classic", "modern", "editorial", "technical"}) {
		t.Fatalf("built-ins %v", got)
	}
	for _, id := range BuiltinIDs() {
		doc, ok := BuiltinDocument(id)
		if !ok {
			t.Fatalf("%s: no document", id)
		}
		d, err := Parse(doc)
		if err != nil {
			t.Fatalf("%s does not validate: %v", id, err)
		}
		if !bytes.Equal(d.Canonical(), doc) {
			t.Errorf("%s: its document is not its canonical form:\n%s\nwant\n%s", id, doc, d.Canonical())
		}
		again, err := Parse(d.Canonical())
		if err != nil || again != d {
			t.Errorf("%s: canonical round trip changed it (%v)", id, err)
		}
		b, _ := Builtin(id)
		if b != d || b.BasedOn != id || b.AgentryTheme != DocumentVersion {
			t.Errorf("%s: Builtin answers %+v", id, b)
		}
		if len(d.SHA256()) != 64 {
			t.Errorf("%s: SHA256 %q", id, d.SHA256())
		}
	}
	if Default().BasedOn != "plain" {
		t.Fatalf("the default is %s", Default().BasedOn)
	}
}

// Plain stays near-monochrome (D4): its accent is a near-black grey, so
// nobody's PDFs change colour unless they choose a design.
func TestPlainIsNearMonochrome(t *testing.T) {
	c, _ := parseHex(Default().Accent)
	_, s, l := c.hsl()
	if s > 0.15 || l > 0.25 {
		t.Fatalf("Plain's accent %s has saturation %.2f and lightness %.2f", Default().Accent, s, l)
	}
}

// The five differ as design languages: no two share faces, accent, title
// block and heading treatment all at once (plan §4's table).
func TestBuiltinsDiffer(t *testing.T) {
	seen := map[string]string{}
	for _, d := range Builtins() {
		key := strings.Join([]string{d.Fonts.Headings, d.Fonts.Body, d.Accent, d.TitleBlock, d.Headings}, "|")
		if other, ok := seen[key]; ok {
			t.Fatalf("%s looks like %s", d.BasedOn, other)
		}
		seen[key] = d.BasedOn
	}
}

func modern(t *testing.T) map[string]any {
	t.Helper()
	doc, _ := BuiltinDocument("modern")
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func set(m map[string]any, path string, v any) {
	keys := strings.Split(path, ".")
	for _, k := range keys[:len(keys)-1] {
		m = m[k].(map[string]any)
	}
	if v == deleteKey {
		delete(m, keys[len(keys)-1])
		return
	}
	m[keys[len(keys)-1]] = v
}

type marker struct{}

var deleteKey = marker{}

// The validation table: bad colours, unknown fonts and styles, a font in a
// role it cannot take, an over-long or multi-line footer, unknown keys, a
// missing field, an earlier document version and an over-size document are
// each refused with the field named (invariant 2; agentry#1024).
func TestValidationTable(t *testing.T) {
	cases := []struct {
		name, path string
		value      any
		field      string
	}{
		{"short colour", "accent", "#fff", "accent"},
		{"upper-case colour", "accent", "#1F6FEB", "accent"},
		{"colour name", "accent", "red", "accent"},
		{"css function", "accent", "url(https://x.example/a.png)", "accent"},
		{"colour with alpha", "accent", "#1f6feb80", "accent"},
		{"unknown font", "fonts.body", "Comic Sans MS", "fonts.body"},
		{"font path", "fonts.headings", "../../etc/passwd", "fonts.headings"},
		{"Noto is not on the list", "fonts.body", "Noto Sans", "fonts.body"},
		{"mono body", "fonts.body", "JetBrains Mono", "fonts.body"},
		{"display body", "fonts.body", "Playfair Display", "fonts.body"},
		{"sans code", "fonts.code", "Inter", "fonts.code"},
		{"unknown title block", "titleBlock", "banner", "titleBlock"},
		{"unknown heading", "headings", "underline", "headings"},
		{"unknown quotes", "quotes", "boxed", "quotes"},
		{"unknown paper", "paper", "legal", "paper"},
		{"capitalised paper", "paper", "A4", "paper"},
		{"unknown page numbers", "footer.pageNumbers", "n of N", "footer.pageNumbers"},
		{"footer over 120", "footer.text", strings.Repeat("x", 121), "footer.text"},
		{"footer two lines", "footer.text", "one\ntwo", "footer.text"},
		{"footer tab", "footer.text", "a\tb", "footer.text"},
		{"footer bidi override", "footer.text", "Invoice \u202eexe.pdf", "footer.text"},
		{"footer line separator", "footer.text", "a\u2028b", "footer.text"},
		{"footer only spaces", "footer.text", "   ", "footer.text"},
		{"empty name", "name", "", "name"},
		{"blank name", "name", "  ", "name"},
		{"long name", "name", strings.Repeat("n", 61), "name"},
		{"unknown basedOn", "basedOn", "formal", "basedOn"},
		{"version zero", "version", 0, "version"},
		{"version too high", "version", MaxVersion + 1, "version"},
		{"theme document 1", "agentryTheme", 1, "agentryTheme"},
		{"missing accent", "accent", deleteKey, "accent"},
		{"missing nested", "tables.banded", deleteKey, "tables.banded"},
		{"null field", "footer.text", nil, "footer.text"},
		{"wrong type", "version", "1", "version"},
		{"wrong nested type", "tables.tinted", "yes", "tables.tinted"},
		{"unknown key", "logo", "x.png", ""},
		{"unknown nested key", "fonts.math", "Noto Sans Math", ""},
		{"v1 key", "cover", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := modern(t)
			set(m, c.path, c.value)
			doc, _ := json.Marshal(m)
			_, err := Parse(doc)
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("accepted, or not a FieldError: %v", err)
			}
			if fe.Field != c.field {
				t.Fatalf("refused on %q (%s), want %q", fe.Field, fe.Message, c.field)
			}
		})
	}

	// Whole-document refusals.
	doc, _ := BuiltinDocument("plain")
	for name, data := range map[string][]byte{
		"over-size":     append(bytes.Repeat([]byte(" "), MaxDocumentBytes), doc...),
		"two values":    append(append([]byte{}, doc...), []byte("{}")...),
		"an array":      []byte("[]"),
		"not json":      []byte("agentryTheme: 2"),
		"empty":         nil,
		"invalid utf-8": append(append([]byte{}, doc[:len(doc)-2]...), 0xff, '}'),
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// What a design may hold as text is accepted as text: Typst markup in the
// footer is data, which the runner's template sets literally (invariant 2),
// and characters JSON would escape for HTML are written as they are.
func TestTextIsData(t *testing.T) {
	m := modern(t)
	set(m, "footer.text", `#import "@preview/x:0.1.0" & <b>Acme</b> — 第1页`)
	set(m, "name", "Acme & Co")
	doc, _ := json.Marshal(m)
	d, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(d.Canonical(), []byte(`"Acme & Co"`)) {
		t.Fatalf("canonical escapes the text: %s", d.Canonical())
	}
}

// The contrast table (invariant 7, D17).
func TestContrast(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want float64
	}{
		{"#000000", "#ffffff", 21},
		{"#ffffff", "#ffffff", 1},
		{"#767676", "#ffffff", 4.54}, // the classic AA grey
		{"#777777", "#ffffff", 4.48},
		{"#949494", "#ffffff", 3.03},
		{"#1f6feb", "#ffffff", 4.63},
	} {
		got, err := Contrast(c.a, c.b)
		if err != nil || math.Abs(got-c.want) > 0.01 {
			t.Errorf("Contrast(%s, %s) = %.3f (%v), want %.2f", c.a, c.b, got, err, c.want)
		}
	}
	if _, err := Contrast("#fff", White); err == nil {
		t.Error("a short colour has a contrast")
	}

	// An accent on graphics only needs 3:1; the same accent on text 4.5:1.
	m := modern(t)
	set(m, "titleBlock", "bar")
	set(m, "headings", "rule")
	set(m, "accent", "#3d8bfd") // 3.4:1
	doc, _ := json.Marshal(m)
	d, err := Parse(doc)
	if err != nil {
		t.Fatalf("a 3.4:1 accent on graphics only is refused: %v", err)
	}
	if d.AccentOnText() || d.MinContrast() != GraphicsContrast {
		t.Fatalf("bar and rule put the accent on text")
	}
	for _, onText := range []struct{ path, value string }{
		{"titleBlock", "band"}, {"headings", "smallcaps"}, {"headings", "numbered"},
	} {
		m := modern(t)
		set(m, "titleBlock", "bar")
		set(m, "headings", "rule")
		set(m, "accent", "#3d8bfd")
		set(m, onText.path, onText.value)
		doc, _ := json.Marshal(m)
		_, err := Parse(doc)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "accent" || !strings.Contains(fe.Message, "the nearest shade that does is #") {
			t.Errorf("%s %s with a 3.4:1 accent: %v", onText.path, onText.value, err)
		}
	}
	// Below 3:1 is refused even on graphics.
	set(m, "accent", "#a8c7fa")
	doc, _ = json.Marshal(m)
	if _, err := Parse(doc); err == nil {
		t.Error("a 1.8:1 accent on graphics is accepted")
	}
}

// The nearest passing shade passes, keeps the hue, and is the lightest one
// that does: one step lighter fails (D17).
func TestNearestPassing(t *testing.T) {
	if got, _ := NearestPassing("#1f6feb", TextContrast); got != "#1f6feb" {
		t.Fatalf("a passing colour moved to %s", got)
	}
	for _, colour := range []string{"#3d8bfd", "#ffcc00", "#00ff00", "#ff6b6b", "#aaaaaa", "#ffffff", "#e8f0fe"} {
		for _, min := range []float64{GraphicsContrast, TextContrast} {
			got, err := NearestPassing(colour, min)
			if err != nil {
				t.Fatal(err)
			}
			if r := onWhite(got); r < min {
				t.Errorf("NearestPassing(%s, %.1f) = %s at %.2f:1", colour, min, got, r)
			}
			in, _ := parseHex(colour)
			out, _ := parseHex(got)
			h1, s1, l1 := in.hsl()
			h2, _, l2 := out.hsl()
			if l2 > l1 {
				t.Errorf("NearestPassing(%s) = %s is lighter", colour, got)
			}
			if s1 > 0.1 && math.Abs(h1-h2) > 0.02 && math.Abs(h1-h2) < 0.98 {
				t.Errorf("NearestPassing(%s) = %s moved the hue from %.3f to %.3f", colour, got, h1, h2)
			}
			// The next lighter shade (a step of lightness) fails, so it is
			// the nearest.
			h, s, l := out.hsl()
			if lighter := fromHSL(h, s, l+0.01).hex(); lighter != got && l+0.01 <= l1 && onWhite(lighter) >= min {
				t.Errorf("NearestPassing(%s, %.1f) = %s, but %s also passes", colour, min, got, lighter)
			}
		}
	}
}

func TestTint(t *testing.T) {
	got, err := Tint("#1f6feb")
	if err != nil || got != "#e4eefd" {
		t.Fatalf("Tint = %s (%v)", got, err)
	}
	if got, _ := Tint("#000000"); got != "#e0e0e0" {
		t.Fatalf("black's tint %s", got)
	}
}

// The families are D13's fourteen, each role takes the right ones, and the
// built-ins use only those.
func TestFamilies(t *testing.T) {
	if n := len(Families()); n != 14 {
		t.Fatalf("%d families", n)
	}
	if got := FontsFor("code"); !slices.Equal(got, []string{"IBM Plex Mono", "JetBrains Mono", "Source Code Pro"}) {
		t.Fatalf("code fonts %v", got)
	}
	body := FontsFor("body")
	if slices.Contains(body, "Montserrat") || slices.Contains(body, "Playfair Display") || slices.Contains(body, "IBM Plex Mono") {
		t.Fatalf("body fonts %v", body)
	}
	if len(FontsFor("headings")) != 14 || FontsFor("logo") != nil {
		t.Fatal("headings take every family; an unknown role none")
	}
}

// schema.json is Schema's committed copy. REPORTDESIGN_UPDATE_SCHEMA=1
// rewrites it.
func TestSchemaFileIsCurrent(t *testing.T) {
	if os.Getenv("REPORTDESIGN_UPDATE_SCHEMA") == "1" {
		if err := os.WriteFile("schema.json", Schema(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, Schema()) {
		t.Fatal("schema.json is stale: run with REPORTDESIGN_UPDATE_SCHEMA=1")
	}
	var s struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(got, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Required) != len(s.Properties) || len(s.Properties) != 12 {
		t.Fatalf("the schema has %d properties, %d required", len(s.Properties), len(s.Required))
	}
}

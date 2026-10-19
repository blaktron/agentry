package reportdesign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every built-in validates, its embedded document is exactly its Canonical,
// and parsing that document gives the same design back.
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
		sum := sha256.Sum256(doc)
		if d.SHA256() != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: SHA256 %s is not the lower-case hex SHA-256 of its document", id, d.SHA256())
		}
	}
	if Default().BasedOn != "plain" {
		t.Fatalf("the default is %s", Default().BasedOn)
	}
	if p, _ := Builtin("plain"); Default() != p {
		t.Fatal("the default is not the Plain built-in")
	}

	// The list is a copy, Builtins follows its order, and an id that is not
	// a built-in has neither a design nor a document.
	ids := BuiltinIDs()
	ids[0] = "edited"
	if BuiltinIDs()[0] != "plain" {
		t.Fatal("editing the returned id list changed the built-ins")
	}
	for i, b := range Builtins() {
		if b.BasedOn != BuiltinIDs()[i] {
			t.Errorf("Builtins()[%d] is %s, want %s", i, b.BasedOn, BuiltinIDs()[i])
		}
	}
	if _, ok := Builtin("formal"); ok {
		t.Error("Builtin answers an id that is not a built-in")
	}
	if doc, ok := BuiltinDocument("formal"); ok || doc != nil {
		t.Errorf("BuiltinDocument answers an id that is not a built-in: %q, %v", doc, ok)
	}
}

// Plain stays near-monochrome: its accent is a near-black grey, so
// nobody's PDFs change colour unless they choose a design.
func TestPlainIsNearMonochrome(t *testing.T) {
	c, _ := parseHex(Default().Accent)
	_, s, l := c.hsl()
	if s > 0.15 || l > 0.25 {
		t.Fatalf("Plain's accent %s has saturation %.2f and lightness %.2f", Default().Accent, s, l)
	}
}

// The five differ as design languages: no two share faces, accent, title
// block and heading treatment all at once.
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
// each refused with the field named.
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
		{"unknown key", "watermark", "x.png", ""},
		{"a logo by file name", "logo", "x.png", "logo"},
		{"unknown nested key", "fonts.math", "Noto Sans Math", ""},
		{"v1 key", "cover", true, ""},

		// Each part of the colour form refused on its own.
		{"five-digit colour", "accent", "#1f6fe", "accent"},
		{"colour without a hash", "accent", "1f6feb", "accent"},
		{"colour with a prefix", "accent", "x#1f6feb", "accent"},
		{"colour with a non-hex letter", "accent", "#1f6feg", "accent"},
		// A family is named exactly, and a role takes only its kinds.
		{"lower-case family name", "fonts.body", "inter", "fonts.body"},
		{"family name with a space", "fonts.body", "Inter ", "fonts.body"},
		{"serif code", "fonts.code", "Lora", "fonts.code"},
		{"unknown code font", "fonts.code", "Courier", "fonts.code"},
		// Every control, line-break and bidirectional formatting character
		// is refused in a free text, not only the first of each kind.
		{"footer delete character", "footer.text", "a" + string(rune(0x7f)) + "b", "footer.text"},
		{"footer next-line control", "footer.text", "a" + string(rune(0x85)) + "b", "footer.text"},
		{"footer paragraph separator", "footer.text", "a" + string(rune(0x2029)) + "b", "footer.text"},
		{"footer left-to-right embedding", "footer.text", "a" + string(rune(0x202a)) + "b", "footer.text"},
		{"footer left-to-right override", "footer.text", "a" + string(rune(0x202d)) + "b", "footer.text"},
		{"footer left-to-right isolate", "footer.text", "a" + string(rune(0x2066)) + "b", "footer.text"},
		{"footer pop directional isolate", "footer.text", "a" + string(rune(0x2069)) + "b", "footer.text"},
		{"footer left-to-right mark", "footer.text", "a" + string(rune(0x200e)) + "b", "footer.text"},
		{"footer right-to-left mark", "footer.text", "a" + string(rune(0x200f)) + "b", "footer.text"},
		{"footer arabic letter mark", "footer.text", "a" + string(rune(0x061c)) + "b", "footer.text"},
		{"footer only no-break spaces", "footer.text", strings.Repeat(string(rune(0xa0)), 3), "footer.text"},
		{"name with a line break", "name", "a\nb", "name"},
		{"name with a bidi override", "name", "a" + string(rune(0x202e)) + "b", "name"},
		// Every other format character (Unicode Cf) is refused too: it draws
		// nothing, so a footer or a name could carry hidden or look-alike text.
		{"footer zero-width space", "footer.text", "a" + string(rune(0x200b)) + "b", "footer.text"},
		{"footer zero-width non-joiner", "footer.text", "a" + string(rune(0x200c)) + "b", "footer.text"},
		{"footer zero-width joiner", "footer.text", "a" + string(rune(0x200d)) + "b", "footer.text"},
		{"footer byte order mark", "footer.text", string(rune(0xfeff)) + "Acme", "footer.text"},
		{"footer word joiner", "footer.text", "a" + string(rune(0x2060)) + "b", "footer.text"},
		{"footer soft hyphen", "footer.text", "a" + string(rune(0xad)) + "b", "footer.text"},
		{"footer tag character", "footer.text", "a" + string(rune(0xe0041)) + "b", "footer.text"},
		{"footer language tag", "footer.text", "a" + string(rune(0xe0001)) + "b", "footer.text"},
		{"footer interlinear annotation", "footer.text", "a" + string(rune(0xfff9)) + "b", "footer.text"},
		{"name zero-width space", "name", "a" + string(rune(0x200b)) + "b", "name"},
		{"name byte order mark", "name", string(rune(0xfeff)) + "Acme", "name"},
		{"name word joiner", "name", "a" + string(rune(0x2060)) + "b", "name"},
		{"name soft hyphen", "name", "a" + string(rune(0xad)) + "b", "name"},
		{"name tag character", "name", "a" + string(rune(0xe0041)) + "b", "name"},
		{"theme document 3", "agentryTheme", 3, "agentryTheme"},
		{"name as a number", "name", 5, "name"},
		{"fonts as a string", "fonts", "Inter", "fonts"},
		{"null nested field", "fonts.code", nil, "fonts.code"},
		// Every required field is named when it is missing.
		{"missing agentryTheme", "agentryTheme", deleteKey, "agentryTheme"},
		{"missing name", "name", deleteKey, "name"},
		{"missing basedOn", "basedOn", deleteKey, "basedOn"},
		{"missing version", "version", deleteKey, "version"},
		{"missing paper", "paper", deleteKey, "paper"},
		{"missing fonts", "fonts", deleteKey, "fonts"},
		{"missing fonts.headings", "fonts.headings", deleteKey, "fonts.headings"},
		{"missing fonts.body", "fonts.body", deleteKey, "fonts.body"},
		{"missing fonts.code", "fonts.code", deleteKey, "fonts.code"},
		{"missing titleBlock", "titleBlock", deleteKey, "titleBlock"},
		{"missing headings", "headings", deleteKey, "headings"},
		{"missing tables", "tables", deleteKey, "tables"},
		{"missing tables.tinted", "tables.tinted", deleteKey, "tables.tinted"},
		{"missing quotes", "quotes", deleteKey, "quotes"},
		{"missing footer", "footer", deleteKey, "footer"},
		{"missing footer.pageNumbers", "footer.pageNumbers", deleteKey, "footer.pageNumbers"},
		{"missing footer.text", "footer.text", deleteKey, "footer.text"},
	}

	// What each refusal says, where it is a different refusal of the same
	// field: the colour form is not the contrast rule, a family that is
	// unknown is not one in the wrong role, an unknown key is not a syntax
	// error.
	const (
		colourMsg = "must be a colour #rrggbb in lower-case hex"
		oneLine   = "must be one line of plain text (no control, line-break, bidirectional formatting or other invisible format characters)"
		blank     = "must not be empty or only spaces"
		required  = "is required"
	)
	wantMsg := map[string]string{
		"unknown font":                "must name a family of the report designs' list",
		"font path":                   "must name a family of the report designs' list",
		"Noto is not on the list":     "must name a family of the report designs' list",
		"lower-case family name":      "must name a family of the report designs' list",
		"family name with a space":    "must name a family of the report designs' list",
		"unknown code font":           "must name a family of the report designs' list",
		"mono body":                   "JetBrains Mono cannot set body text (it is a mono or a headings-only face); choose one of Inter, IBM Plex Sans, Source Sans 3, Work Sans, Source Serif 4, Lora, Merriweather, IBM Plex Serif, EB Garamond",
		"display body":                "Playfair Display cannot set body text (it is a mono or a headings-only face)",
		"sans code":                   "Inter cannot set code (it is not a mono face); choose one of IBM Plex Mono, JetBrains Mono, Source Code Pro",
		"serif code":                  "Lora cannot set code (it is not a mono face)",
		"unknown title block":         "must be one of band, bar, ruled, none",
		"unknown heading":             "must be one of rule, bar, smallcaps, numbered, plain",
		"unknown quotes":              "must be one of callout, plain",
		"unknown paper":               "must be one of a4, letter",
		"capitalised paper":           "must be one of a4, letter",
		"unknown page numbers":        "must be one of none, n, nOfN",
		"unknown basedOn":             "must be one of plain, classic, modern, editorial, technical",
		"footer over 120":             "is 121 characters, over the limit of 120",
		"long name":                   "is 61 characters, over the limit of 60",
		"footer two lines":            oneLine,
		"footer tab":                  oneLine,
		"footer bidi override":        oneLine,
		"footer line separator":       oneLine,
		"footer delete character":     oneLine,
		"footer next-line control":    oneLine,
		"footer paragraph separator":  oneLine,
		"name with a line break":      oneLine,
		"name with a bidi override":   oneLine,
		"footer only spaces":          blank,
		"footer only no-break spaces": blank,
		"empty name":                  blank,
		"blank name":                  blank,
		"version zero":                "must be a whole number from 1 to 1000000",
		"version too high":            "must be a whole number from 1 to 1000000",
		"theme document 1":            "must be 2",
		"theme document 3":            "must be 2",
		"missing accent":              required,
		"missing nested":              required,
		"null field":                  required,
		"null nested field":           required,
		"wrong type":                  "must be a number",
		"wrong nested type":           "must be a boolean",
		"a logo by file name":         "must be an object",
		"fonts as a string":           "must be an object",
		"name as a number":            "must be a string",
		"unknown key":                 `unknown key "watermark"`,
		"unknown nested key":          `unknown key "math"`,
		"v1 key":                      `unknown key "cover"`,
	}
	for _, name := range []string{"short colour", "upper-case colour", "colour name", "css function", "colour with alpha",
		"five-digit colour", "colour without a hash", "colour with a prefix", "colour with a non-hex letter"} {
		wantMsg[name] = colourMsg
	}
	for _, c := range cases {
		if strings.HasPrefix(c.name, "missing ") {
			wantMsg[c.name] = required
		}
		// A format character in either free text is the one-line refusal.
		if (strings.HasPrefix(c.name, "footer ") || strings.HasPrefix(c.name, "name ")) && wantMsg[c.name] == "" {
			wantMsg[c.name] = oneLine
		}
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
			if want := wantMsg[c.name]; want != "" && !strings.Contains(fe.Message, want) {
				t.Errorf("refused with %q, want it to say %q", fe.Message, want)
			}
			// The message never quotes the value back, a colour and a
			// family the list knows excepted.
			if s, ok := c.value.(string); ok && len(s) >= 4 && c.field != "accent" {
				if _, known := FamilyByName(s); !known && strings.Contains(fe.Message, s) {
					t.Errorf("the message quotes the value back: %q", fe.Message)
				}
			}
			wantErr := "report design: " + fe.Field + ": " + fe.Message
			if fe.Field == "" {
				wantErr = "report design: " + fe.Message
			}
			if err.Error() != wantErr {
				t.Errorf("Error() = %q, want %q", err.Error(), wantErr)
			}
			if errors.Is(err, ErrLogoFormat) || errors.Is(err, ErrLogoTooLarge) {
				t.Errorf("a refusal outside the logo wraps a logo kind: %v", err)
			}
		})
	}
	if got := (&FieldError{Field: "fonts.body", Message: "m"}).Error(); got != "report design: fonts.body: m" {
		t.Errorf("a field's refusal reads %q", got)
	}
	if got := (&FieldError{Message: "m"}).Error(); got != "report design: m" {
		t.Errorf("the document's refusal reads %q", got)
	}

	// What sits exactly on a limit is accepted: the names and the footer are
	// counted in characters, not bytes, a version may be 1 or the largest, and
	// headings take any family.
	for _, c := range []struct {
		name, path string
		value      any
	}{
		{"name of 60 characters", "name", strings.Repeat("n", MaxNameRunes)},
		{"name of 60 multi-byte characters", "name", strings.Repeat(string(rune(0xe9)), MaxNameRunes)},
		{"footer of 120 characters", "footer.text", strings.Repeat("x", MaxFooterTextRunes)},
		{"footer of 120 multi-byte characters", "footer.text", strings.Repeat(string(rune(0xe9)), MaxFooterTextRunes)},
		{"no footer text", "footer.text", ""},
		{"no-break space inside the footer", "footer.text", "a" + string(rune(0xa0)) + "b"},
		{"version 1", "version", 1},
		{"the largest version", "version", MaxVersion},
		{"headings in a mono face", "fonts.headings", "JetBrains Mono"},
		{"headings in a display face", "fonts.headings", "Playfair Display"},
	} {
		m := modern(t)
		set(m, c.path, c.value)
		doc, _ := json.Marshal(m)
		if _, err := Parse(doc); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
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

		// A stray byte inside a string would be read as U+FFFD by a JSON
		// decoder that was left to it.
		"invalid utf-8 in a string": bytes.Replace(doc, []byte(`"name": "`+Default().Name+`"`), []byte("\"name\": \"Acme\xff\""), 1),
	} {
		_, err := Parse(data)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "" {
			t.Errorf("%s: %v, want a refusal of the document as a whole", name, err)
		}
		if want := map[string]string{
			"over-size":                 "without its logo, over the 16384-byte limit",
			"two values":                "more than one JSON value",
			"an array":                  "not a JSON object",
			"not json":                  "not a JSON object",
			"empty":                     "not a JSON object",
			"invalid utf-8":             "not UTF-8",
			"invalid utf-8 in a string": "not UTF-8",
		}[name]; fe != nil && !strings.Contains(fe.Message, want) {
			t.Errorf("%s: refused with %q, want it to say %q", name, fe.Message, want)
		}
	}
}

// What a design may hold as text is accepted as text: Typst markup in the
// footer is data, which the runner's template sets literally,
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

// A refusal for an accent just under a line never prints a ratio that reaches
// it, for any colour: the shade a design is told it has is not a pass.
func TestContrastRefusalNeverPrintsAPass(t *testing.T) {
	for _, tb := range []string{"bar", "band"} {
		d := Default()
		d.TitleBlock = tb
		need := d.MinContrast()
		for v := 0; v < 256; v++ {
			for _, hex := range []string{
				fmt.Sprintf("#%02x%02x%02x", v, v, v),
				fmt.Sprintf("#%02x%02x%02x", v, 0x80, 0xff-v),
				fmt.Sprintf("#%02x%02x%02x", 0xe0-v/2, v, 0x40),
			} {
				d.Accent = hex
				err := d.Validate()
				var fe *FieldError
				if !errors.As(err, &fe) || fe.Field != "accent" {
					continue
				}
				m := reachesRatio.FindStringSubmatch(fe.Message)
				if m == nil {
					t.Fatalf("%s: %q prints no ratio", hex, fe.Message)
				}
				if shown, _ := strconv.ParseFloat(m[1], 64); shown >= need {
					t.Fatalf("%s: %q prints %s, which reaches %v", hex, fe.Message, m[1], need)
				}
			}
		}
	}
}

var reachesRatio = regexp.MustCompile(` reaches ([0-9.]+):1 on white`)

// The contrast table.
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
	if _, err := Contrast(White, "#fff"); err == nil {
		t.Error("a short second colour has a contrast")
	}
	if got, err := Contrast(White, "#000000"); err != nil || math.Abs(got-21) > 1e-9 {
		t.Errorf("Contrast(white, black) = %v (%v), want 21 whichever colour is named first", got, err)
	}
	if got := onWhite("red"); got != 1 {
		t.Errorf("a colour that is not #rrggbb reads %v on white, want no contrast (1)", got)
	}
	// Each weight and each bend of the luminance curve, against black, whose
	// contrast is (luminance + 0.05) / 0.05.
	for _, c := range []struct {
		colour string
		want   float64
	}{
		{"#ff0000", 5.252},    // the red weight, 0.2126
		{"#00ff00", 15.304},   // the green weight, 0.7152
		{"#0000ff", 2.444},    // the blue weight, 0.0722
		{"#808080", 5.317210}, // the power curve
		{"#080808", 1.048564}, // the linear segment
		{"#0a0a0a", 1.060705}, // the last linear step
		{"#0b0b0b", 1.066931}, // the first power step
		{"#0c0c0c", 1.073530},
		{"#1f6feb", 4.531669},
		{"#c04080", 4.286354},
	} {
		got, err := Contrast(c.colour, "#000000")
		if err != nil || math.Abs(got-c.want) > 1e-5 {
			t.Errorf("Contrast(%s, black) = %.6f (%v), want %.6f", c.colour, got, err, c.want)
		}
	}

	// The two lines sit between neighbouring greys: 3:1 for an accent that
	// colours only graphics, 4.5:1 where it touches text. The message says
	// which, what the accent reaches, and a shade that does pass.
	shadeOf := func(msg string) string {
		const marker = "the nearest shade that does is "
		i := strings.Index(msg, marker)
		if i < 0 || len(msg) < i+len(marker)+7 {
			return ""
		}
		return msg[i+len(marker) : i+len(marker)+7]
	}
	for _, c := range []struct {
		accent, titleBlock, headings string
		ok                           bool
		min                          float64
		need, use, reaches           string
	}{
		{"#949494", "bar", "rule", true, GraphicsContrast, "", "", ""},
		{"#959595", "bar", "rule", false, GraphicsContrast, "needs 3.0:1", "colours only graphics", "#959595 reaches 2.99:1 on white"},
		{"#767676", "band", "rule", true, TextContrast, "", "", ""},
		{"#777777", "band", "rule", false, TextContrast, "needs 4.5:1", "colours text", "#777777 reaches 4.48:1 on white"},
		{"#767676", "bar", "smallcaps", true, TextContrast, "", "", ""},
		{"#777777", "bar", "smallcaps", false, TextContrast, "needs 4.5:1", "colours text", "#777777 reaches 4.48:1 on white"},
		{"#767676", "bar", "numbered", true, TextContrast, "", "", ""},
		{"#777777", "bar", "numbered", false, TextContrast, "needs 4.5:1", "colours text", "#777777 reaches 4.48:1 on white"},
		{"#a8c7fa", "bar", "rule", false, GraphicsContrast, "needs 3.0:1", "colours only graphics", "#a8c7fa reaches 1.72:1 on white"},
	} {
		m := modern(t)
		set(m, "titleBlock", c.titleBlock)
		set(m, "headings", c.headings)
		set(m, "accent", c.accent)
		doc, _ := json.Marshal(m)
		d, err := Parse(doc)
		if c.ok {
			if err != nil || d.MinContrast() != c.min {
				t.Errorf("%s with %s and %s: %v (needs %v), want accepted at %v", c.accent, c.titleBlock, c.headings, err, d.MinContrast(), c.min)
			}
			continue
		}
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "accent" {
			t.Errorf("%s with %s and %s: %v, want a refusal on accent", c.accent, c.titleBlock, c.headings, err)
			continue
		}
		for _, want := range []string{c.need, c.use, c.reaches} {
			if !strings.Contains(fe.Message, want) {
				t.Errorf("%s with %s and %s: %q does not say %q", c.accent, c.titleBlock, c.headings, fe.Message, want)
			}
		}
		// The ratio the refusal prints is never one that reaches the line.
		rm := reachesRatio.FindStringSubmatch(fe.Message)
		if rm == nil {
			t.Errorf("%s with %s and %s: %q prints no ratio", c.accent, c.titleBlock, c.headings, fe.Message)
		} else if shown, _ := strconv.ParseFloat(rm[1], 64); shown >= c.min {
			t.Errorf("%s with %s and %s: %q prints %s, which reaches %v", c.accent, c.titleBlock, c.headings, fe.Message, rm[1], c.min)
		}
		if r, err := Contrast(shadeOf(fe.Message), White); err != nil || r < c.min {
			t.Errorf("%s with %s and %s: the suggested shade %q reaches %.2f:1 (%v), want %v", c.accent, c.titleBlock, c.headings, shadeOf(fe.Message), r, err, c.min)
		}
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
// that does: one step lighter fails.
func TestNearestPassing(t *testing.T) {
	if _, err := NearestPassing("red", TextContrast); err == nil {
		t.Error("a colour that is not #rrggbb has a nearest passing shade")
	}

	// It is the lightest darkening that passes: walking down from the
	// colour's own lightness in steps far finer than a channel value, the first
	// shade to pass is the one answered.
	for _, colour := range []string{"#3d8bfd", "#ffcc00", "#00ff00", "#ff6b6b", "#aaaaaa", "#ffffff", "#e8f0fe", "#a8c7fa", "#ff8800", "#7fdbca", "#c0c0ff"} {
		for _, min := range []float64{GraphicsContrast, TextContrast} {
			got, _ := NearestPassing(colour, min)
			if onWhite(colour) >= min {
				if got != colour {
					t.Errorf("NearestPassing(%s, %.1f) moved a passing colour to %s", colour, min, got)
				}
				continue
			}
			c, _ := parseHex(colour)
			h, s, l := c.hsl()
			want := ""
			for x := l; x >= 0; x -= 0.00002 {
				if out := fromHSL(h, s, x).hex(); onWhite(out) >= min {
					want = out
					break
				}
			}
			if got != want {
				t.Errorf("NearestPassing(%s, %.1f) = %s, want %s, the lightest shade that passes", colour, min, got, want)
			}
		}
	}

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
	if got, _ := Tint(White); got != White {
		t.Fatalf("white's tint %s", got)
	}
	if _, err := Tint("red"); err == nil {
		t.Fatal("a colour that is not #rrggbb has a tint")
	}

	// A channel is rounded to the nearest value and held to 0..255.
	if got := (rgb{-5, 300, 12.5}).hex(); got != "#00ff0d" {
		t.Fatalf("hex of out-of-range channels %s, want #00ff0d", got)
	}

	// hsl and fromHSL are inverses across every sector of the hue circle, the
	// grey axis and both halves of lightness.
	for _, colour := range []string{
		"#ff0000", "#ffff00", "#00ff00", "#00ffff", "#0000ff", "#ff00ff", "#ff0080",
		"#800000", "#808000", "#008000", "#008080", "#000080", "#800080",
		"#e8f0fe", "#ffcc00", "#3d8bfd", "#1f6feb", "#c04080", "#7fdbca",
		"#1f3a5f", "#2b2f36", "#0f766e", "#b3261e", "#402030", "#203040",
		"#aaaaaa", "#000000", "#ffffff",
	} {
		c, _ := parseHex(colour)
		h, s, l := c.hsl()
		if back := fromHSL(h, s, l).hex(); back != colour {
			t.Errorf("%s -> hsl(%.4f, %.4f, %.4f) -> %s", colour, h, s, l, back)
		}
	}
	// fromHSL against the textbook construction (chroma, the sector of the
	// hue, and the offset), over a grid that crosses every sector edge.
	for deg := 0; deg < 360; deg += 3 {
		for _, s := range []float64{0.25, 0.6, 1} {
			for _, l := range []float64{0.2, 0.5, 0.8} {
				h := float64(deg) / 360
				chroma := (1 - math.Abs(2*l-1)) * s
				x := chroma * (1 - math.Abs(math.Mod(h*6, 2)-1))
				var r, g, b float64
				switch sector := int(h * 6); sector {
				case 0:
					r, g, b = chroma, x, 0
				case 1:
					r, g, b = x, chroma, 0
				case 2:
					r, g, b = 0, chroma, x
				case 3:
					r, g, b = 0, x, chroma
				case 4:
					r, g, b = x, 0, chroma
				default:
					r, g, b = chroma, 0, x
				}
				m := l - chroma/2
				got := fromHSL(h, s, l)
				if math.Abs(got.r-(r+m)*255) > 1e-6 || math.Abs(got.g-(g+m)*255) > 1e-6 || math.Abs(got.b-(b+m)*255) > 1e-6 {
					t.Fatalf("fromHSL(%d deg, %.2f, %.2f) = %.3f, %.3f, %.3f, want %.3f, %.3f, %.3f",
						deg, s, l, got.r, got.g, got.b, (r+m)*255, (g+m)*255, (b+m)*255)
				}
			}
		}
	}
	for _, c := range []struct {
		colour  string
		h, s, l float64
	}{
		{"#ff0000", 0, 1, 0.5},
		{"#ff0080", 0.916340, 1, 0.5}, // red-leaning magenta wraps to the end of the circle
		{"#e8f0fe", 0.606061, 0.916667, 0.952941},
		{"#1f6feb", 0.601307, 0.836066, 0.521569},
		{"#800000", 0, 1, 0.250980},
	} {
		parsed, _ := parseHex(c.colour)
		h, s, l := parsed.hsl()
		if math.Abs(h-c.h) > 1e-5 || math.Abs(s-c.s) > 1e-5 || math.Abs(l-c.l) > 1e-5 {
			t.Errorf("hsl(%s) = (%.6f, %.6f, %.6f), want (%.6f, %.6f, %.6f)", c.colour, h, s, l, c.h, c.s, c.l)
		}
	}
}

// There are fourteen families, each role takes the right ones, and the
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

	// The whole list: name, kind and whether a face is for headings only.
	want := []Family{
		{"Inter", Sans, false}, {"IBM Plex Sans", Sans, false}, {"Source Sans 3", Sans, false}, {"Work Sans", Sans, false},
		{"Montserrat", Sans, true},
		{"Source Serif 4", Serif, false}, {"Lora", Serif, false}, {"Merriweather", Serif, false},
		{"IBM Plex Serif", Serif, false}, {"EB Garamond", Serif, false},
		{"Playfair Display", Serif, true},
		{"IBM Plex Mono", Mono, false}, {"JetBrains Mono", Mono, false}, {"Source Code Pro", Mono, false},
	}
	if got := Families(); !slices.Equal(got, want) {
		t.Fatalf("families %+v, want %+v", got, want)
	}
	if got := FontsFor("body"); !slices.Equal(got, []string{"Inter", "IBM Plex Sans", "Source Sans 3", "Work Sans",
		"Source Serif 4", "Lora", "Merriweather", "IBM Plex Serif", "EB Garamond"}) {
		t.Fatalf("body fonts %v", got)
	}

	// The list is a copy, and a family is found by its exact name.
	f := Families()
	f[0].Name = "edited"
	if Families()[0].Name != "Inter" {
		t.Fatal("editing the returned families changed the list")
	}
	if fam, ok := FamilyByName("Playfair Display"); !ok || fam != want[10] {
		t.Fatalf("FamilyByName(Playfair Display) = %+v, %v", fam, ok)
	}
	for _, name := range []string{"inter", "INTER", "Inter ", "", "Noto Sans"} {
		if fam, ok := FamilyByName(name); ok {
			t.Errorf("FamilyByName(%q) found %+v", name, fam)
		}
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
	// Every field is required but the logo.
	if len(s.Required) != 12 || len(s.Properties) != 13 || slices.Contains(s.Required, "logo") {
		t.Fatalf("the schema has %d properties, %d required", len(s.Properties), len(s.Required))
	}
}

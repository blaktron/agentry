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
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var allBuiltins = []string{"plain", "classic", "modern", "editorial", "technical", "boardroom", "studio", "field", "civic", "lumen"}

// Every built-in validates, its embedded document is exactly its Canonical,
// and parsing that document gives the same design back.
func TestBuiltinsRoundTripByteForByte(t *testing.T) {
	if got := BuiltinIDs(); !slices.Equal(got, allBuiltins) {
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
		if err != nil || !reflect.DeepEqual(again, d) {
			t.Errorf("%s: canonical round trip changed it (%v)", id, err)
		}
		b, _ := Builtin(id)
		if !reflect.DeepEqual(b, d) || b.BasedOn != id || b.AgentryTheme != DocumentVersion {
			t.Errorf("%s: Builtin answers %+v", id, b)
		}
		if len(d.SHA256()) != 64 {
			t.Errorf("%s: SHA256 %q", id, d.SHA256())
		}
		sum := sha256.Sum256(doc)
		if d.SHA256() != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: SHA256 %s is not the lower-case hex SHA-256 of its document", id, d.SHA256())
		}
		if !reflect.DeepEqual(d.Brand, Brand{Contact: []string{}}) {
			t.Errorf("%s carries branding: %+v", id, d.Brand)
		}
		if d.Logo != (Logo{}) || d.CoverImage != (Image{}) || !d.CustomCover.IsZero() {
			t.Errorf("%s carries an image or a custom cover", id)
		}
	}
	if Default().BasedOn != "plain" {
		t.Fatalf("the default is %s", Default().BasedOn)
	}
	if p, _ := Builtin("plain"); !reflect.DeepEqual(Default(), p) {
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
	if Default().Secondary != "" {
		t.Fatal("Plain has a secondary")
	}
}

// The ten differ as design languages: no two share faces, accent, title
// block, heading treatment and cover style all at once.
func TestBuiltinsDiffer(t *testing.T) {
	seen := map[string]string{}
	for _, d := range Builtins() {
		key := strings.Join([]string{d.Fonts.Headings, d.Fonts.Body, d.Accent, d.TitleBlock, d.Headings, d.Cover.Style}, "|")
		if other, ok := seen[key]; ok {
			t.Fatalf("%s looks like %s", d.BasedOn, other)
		}
		seen[key] = d.BasedOn
	}
}

// Each built-in is a kit: a cover style, a header style and a footer that
// go with it, and the five themes a version-2 document may name keep that
// look (no
// secondary, the cover drawn only for a long report, and a version-2
// projection that is the version-2 document byte for byte), while the five
// new ones carry a secondary and a cover on every titled report.
func TestBuiltinsAreKits(t *testing.T) {
	kits := map[string]struct{ cover, header, when string }{
		"plain":     {"framed", "none", "long"},
		"classic":   {"framed", "rule", "long"},
		"modern":    {"band", "titleAndPage", "long"},
		"editorial": {"largeType", "brandLine", "long"},
		"technical": {"geometric", "titleAndPage", "long"},
		"boardroom": {"split", "brandLine", "always"},
		"studio":    {"largeType", "logoLeft", "always"},
		"field":     {"plate", "rule", "always"},
		"civic":     {"framed", "brandLine", "always"},
		"lumen":     {"geometric", "titleAndPage", "always"},
	}
	for i, d := range Builtins() {
		want := kits[d.BasedOn]
		if d.Cover.Style != want.cover || d.Header.Style != want.header || d.Cover.When != want.when {
			t.Errorf("%s: cover %s %s, header %s; want %+v", d.BasedOn, d.Cover.Style, d.Cover.When, d.Header.Style, want)
		}
		if i < version2Count {
			if d.Secondary != "" {
				t.Errorf("%s, a version-2 theme, has a secondary", d.BasedOn)
			}
			v2, err := os.ReadFile("testdata/v2/" + d.BasedOn + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(d.Version2(), v2) {
				t.Errorf("%s: its version-2 projection is not the version-2 document:\n%s\nwant\n%s", d.BasedOn, d.Version2(), v2)
			}
			continue
		}
		if d.Secondary == "" {
			t.Errorf("%s has no secondary", d.BasedOn)
		}
		// Each style's declaration holds for the kit's colours: the
		// secondary is checked by Validate already; here, that a kit
		// whose cover puts the accent or the secondary on text has one
		// that reaches the text line, so the editors' previews are right.
		if d.AccentOnText() && onWhite(d.Accent) < TextContrast {
			t.Errorf("%s: the accent carries text at %.2f:1", d.BasedOn, onWhite(d.Accent))
		}
		if d.SecondaryOnText() && onWhite(d.Secondary) < TextContrast {
			t.Errorf("%s: the secondary carries text at %.2f:1", d.BasedOn, onWhite(d.Secondary))
		}
	}
	// A header style's slots name tokens the style draws.
	for _, d := range Builtins() {
		for i, slot := range d.Header.Slots {
			for _, tok := range TokensIn(slot) {
				if !slices.Contains(Tokens, tok) {
					t.Errorf("%s header slot %d names %s", d.BasedOn, i, tok)
				}
			}
		}
	}
	for _, d := range Builtins() {
		for _, fact := range d.Cover.Shows {
			if !slices.Contains(CoverFacts, fact) {
				t.Errorf("%s cover shows %s", d.BasedOn, fact)
			}
		}
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

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The validation table: bad colours, unknown fonts and styles, a font in a
// role it cannot take, an over-long or multi-line text in any of the
// brand's lines or the slots, a slot list of the wrong length, a website
// that is not one, a cover fact twice, unknown keys (version 2's footer
// text among them), a missing field, an earlier document version and an
// over-size document are each refused with the field named.
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
		{"secondary short", "secondary", "#fff", "secondary"},
		{"secondary upper-case", "secondary", "#8A6A00", "secondary"},
		{"secondary name", "secondary", "gold", "secondary"},
		{"secondary spaces", "secondary", "  ", "secondary"},
		{"unknown font", "fonts.body", "Comic Sans MS", "fonts.body"},
		{"font path", "fonts.headings", "../../etc/passwd", "fonts.headings"},
		{"Noto is not on the list", "fonts.body", "Noto Sans", "fonts.body"},
		{"mono body", "fonts.body", "JetBrains Mono", "fonts.body"},
		{"display body", "fonts.body", "Playfair Display", "fonts.body"},
		{"Fraunces body", "fonts.body", "Fraunces", "fonts.body"},
		{"sans code", "fonts.code", "Inter", "fonts.code"},
		{"unknown title block", "titleBlock", "banner", "titleBlock"},
		{"unknown heading", "headings", "underline", "headings"},
		{"unknown heading scale", "headingScale", "huge", "headingScale"},
		{"unknown margins", "margins", "tight", "margins"},
		{"unknown quotes", "quotes", "boxed", "quotes"},
		{"unknown paper", "paper", "legal", "paper"},
		{"capitalised paper", "paper", "A4", "paper"},
		{"unknown page numbers", "footer.pageNumbers", "n of N", "footer.pageNumbers"},
		{"unknown header style", "header.style", "banner", "header.style"},
		{"two header slots", "header.slots", []string{"a", "b"}, "header.slots"},
		{"four footer slots", "footer.slots", []string{"a", "b", "c", "d"}, "footer.slots"},
		{"slots as a string", "header.slots", "{title}", "header.slots"},
		{"slot over 120", "header.slots", []string{strings.Repeat("x", 121), "", ""}, "header.slots.0"},
		{"slot two lines", "footer.slots", []string{"", "one\ntwo", ""}, "footer.slots.1"},
		{"slot tab", "footer.slots", []string{"", "", "a\tb"}, "footer.slots.2"},
		{"slot bidi override", "header.slots", []string{"Invoice \u202eexe.pdf", "", ""}, "header.slots.0"},
		{"slot line separator", "header.slots", []string{"", "a\u2028b", ""}, "header.slots.1"},
		{"slot only spaces", "footer.slots", []string{"   ", "", ""}, "footer.slots.0"},
		{"slot zero-width space", "footer.slots", []string{"a\u200bb", "", ""}, "footer.slots.0"},
		{"empty name", "name", "", "name"},
		{"blank name", "name", "  ", "name"},
		{"long name", "name", strings.Repeat("n", 61), "name"},
		{"long brand name", "brand.name", strings.Repeat("n", 61), "brand.name"},
		{"blank brand name", "brand.name", "  ", "brand.name"},
		{"brand name two lines", "brand.name", "a\nb", "brand.name"},
		{"long strapline", "brand.strapline", strings.Repeat("s", 121), "brand.strapline"},
		{"strapline soft hyphen", "brand.strapline", "a\u00adb", "brand.strapline"},
		{"five contact lines", "brand.contact", []string{"a", "b", "c", "d", "e"}, "brand.contact"},
		{"empty contact line", "brand.contact", []string{"a", ""}, "brand.contact.1"},
		{"long contact line", "brand.contact", []string{strings.Repeat("c", 121)}, "brand.contact.0"},
		{"contact line with a line break", "brand.contact", []string{"1 High St\nTown"}, "brand.contact.0"},
		{"contact as a string", "brand.contact", "1 High St", "brand.contact"},
		{"long website", "brand.website", "https://" + strings.Repeat("a", 110) + ".example", "brand.website"},
		{"http website", "brand.website", "http://example.com", "brand.website"},
		{"website with a space", "brand.website", "example .com", "brand.website"},
		{"website with credentials", "brand.website", "https://user:pw@example.com", "brand.website"},
		{"website with a port", "brand.website", "example.com:8443", "brand.website"},
		{"website with a query", "brand.website", "example.com/?a=b", "brand.website"},
		{"website one label", "brand.website", "localhost", "brand.website"},
		{"website with a scheme in the path", "brand.website", "javascript:alert(1)", "brand.website"},
		{"long confidentiality", "brand.confidentiality", strings.Repeat("c", 121), "brand.confidentiality"},
		{"confidentiality bidi mark", "brand.confidentiality", "a\u200fb", "brand.confidentiality"},
		{"unknown cover style", "cover.style", "hero", "cover.style"},
		{"unknown cover fact", "cover.shows", []string{"title", "price"}, "cover.shows.1"},
		{"cover fact twice", "cover.shows", []string{"title", "date", "title"}, "cover.shows.2"},
		{"shows as a string", "cover.shows", "title", "cover.shows"},
		{"unknown cover when", "cover.when", "sometimes", "cover.when"},
		{"unknown basedOn", "basedOn", "formal", "basedOn"},
		{"version zero", "version", 0, "version"},
		{"version too high", "version", MaxVersion + 1, "version"},
		{"theme document 1", "agentryTheme", 1, "agentryTheme"},
		{"theme document 2", "agentryTheme", 2, "agentryTheme"},
		{"theme document 4", "agentryTheme", 4, "agentryTheme"},
		{"missing accent", "accent", deleteKey, "accent"},
		{"missing nested", "tables.banded", deleteKey, "tables.banded"},
		{"null field", "secondary", nil, "secondary"},
		{"null slots", "header.slots", nil, "header.slots"},
		{"null contact", "brand.contact", nil, "brand.contact"},
		{"wrong type", "version", "1", "version"},
		{"wrong nested type", "tables.tinted", "yes", "tables.tinted"},
		{"unknown key", "watermark", "x.png", ""},
		{"version 2 footer text", "footer.text", "Acme", ""},
		{"a logo by file name", "logo", "x.png", "logo"},
		{"a cover image by file name", "coverImage", "x.png", "coverImage"},
		{"a custom cover by file name", "customCover", "cover.typ", "customCover"},
		{"unknown nested key", "fonts.math", "Noto Sans Math", ""},
		{"unknown brand key", "brand.logo", "x.png", ""},
		{"unknown cover key", "cover.source", "#page[]", ""},

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
		{"slot delete character", "footer.slots", []string{"a" + string(rune(0x7f)) + "b", "", ""}, "footer.slots.0"},
		{"slot next-line control", "footer.slots", []string{"a" + string(rune(0x85)) + "b", "", ""}, "footer.slots.0"},
		{"slot paragraph separator", "footer.slots", []string{"a" + string(rune(0x2029)) + "b", "", ""}, "footer.slots.0"},
		{"slot left-to-right isolate", "footer.slots", []string{"a" + string(rune(0x2066)) + "b", "", ""}, "footer.slots.0"},
		{"slot byte order mark", "footer.slots", []string{string(rune(0xfeff)) + "Acme", "", ""}, "footer.slots.0"},
		{"slot tag character", "footer.slots", []string{"a" + string(rune(0xe0041)) + "b", "", ""}, "footer.slots.0"},
		{"name with a line break", "name", "a\nb", "name"},
		{"name with a bidi override", "name", "a" + string(rune(0x202e)) + "b", "name"},
		{"name zero-width space", "name", "a" + string(rune(0x200b)) + "b", "name"},
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
		{"missing secondary", "secondary", deleteKey, "secondary"},
		{"missing titleBlock", "titleBlock", deleteKey, "titleBlock"},
		{"missing headings", "headings", deleteKey, "headings"},
		{"missing headingScale", "headingScale", deleteKey, "headingScale"},
		{"missing margins", "margins", deleteKey, "margins"},
		{"missing tables", "tables", deleteKey, "tables"},
		{"missing tables.tinted", "tables.tinted", deleteKey, "tables.tinted"},
		{"missing quotes", "quotes", deleteKey, "quotes"},
		{"missing brand", "brand", deleteKey, "brand"},
		{"missing brand.name", "brand.name", deleteKey, "brand.name"},
		{"missing brand.strapline", "brand.strapline", deleteKey, "brand.strapline"},
		{"missing brand.contact", "brand.contact", deleteKey, "brand.contact"},
		{"missing brand.website", "brand.website", deleteKey, "brand.website"},
		{"missing brand.confidentiality", "brand.confidentiality", deleteKey, "brand.confidentiality"},
		{"missing header", "header", deleteKey, "header"},
		{"missing header.style", "header.style", deleteKey, "header.style"},
		{"missing header.slots", "header.slots", deleteKey, "header.slots"},
		{"missing footer", "footer", deleteKey, "footer"},
		{"missing footer.pageNumbers", "footer.pageNumbers", deleteKey, "footer.pageNumbers"},
		{"missing footer.slots", "footer.slots", deleteKey, "footer.slots"},
		{"missing cover", "cover", deleteKey, "cover"},
		{"missing cover.style", "cover.style", deleteKey, "cover.style"},
		{"missing cover.shows", "cover.shows", deleteKey, "cover.shows"},
		{"missing cover.when", "cover.when", deleteKey, "cover.when"},
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
		slotsMsg  = "must be 3 texts: left, centre, right"
		webMsg    = "must be a host name such as example.com, or an https address, with no spaces; it is drawn as text"
	)
	wantMsg := map[string]string{
		"unknown font":                "must name a family of the report designs' list",
		"font path":                   "must name a family of the report designs' list",
		"Noto is not on the list":     "must name a family of the report designs' list",
		"lower-case family name":      "must name a family of the report designs' list",
		"family name with a space":    "must name a family of the report designs' list",
		"unknown code font":           "must name a family of the report designs' list",
		"mono body":                   "JetBrains Mono cannot set body text (it is a mono or a headings-only face); choose one of Inter, IBM Plex Sans, Source Sans 3, Work Sans, DM Sans, Nunito Sans, Raleway, Space Grotesk, Source Serif 4, Lora, Merriweather, IBM Plex Serif, EB Garamond, Libre Baskerville, Crimson Pro",
		"display body":                "Playfair Display cannot set body text (it is a mono or a headings-only face)",
		"Fraunces body":               "Fraunces cannot set body text (it is a mono or a headings-only face)",
		"sans code":                   "Inter cannot set code (it is not a mono face); choose one of IBM Plex Mono, JetBrains Mono, Source Code Pro, Fira Code",
		"serif code":                  "Lora cannot set code (it is not a mono face)",
		"unknown title block":         "must be one of band, bar, ruled, none",
		"unknown heading":             "must be one of rule, bar, smallcaps, numbered, plain",
		"unknown heading scale":       "must be one of compact, regular, generous",
		"unknown margins":             "must be one of narrow, regular, wide",
		"unknown quotes":              "must be one of callout, plain",
		"unknown paper":               "must be one of a4, letter",
		"capitalised paper":           "must be one of a4, letter",
		"unknown page numbers":        "must be one of none, n, nOfN",
		"unknown header style":        "must be one of none, rule, brandLine, titleAndPage, logoLeft",
		"unknown cover style":         "must be one of band, split, geometric, largeType, framed, plate, custom",
		"unknown cover fact":          "must be one of title, subtitle, author, date, brand, logo, confidentiality",
		"cover fact twice":            "names a fact the cover already shows",
		"unknown cover when":          "must be one of long, always, never",
		"unknown basedOn":             "must be one of plain, classic, modern, editorial, technical, boardroom, studio, field, civic, lumen",
		"two header slots":            slotsMsg,
		"four footer slots":           slotsMsg,
		"slots as a string":           "must be an array",
		"shows as a string":           "must be an array",
		"contact as a string":         "must be an array",
		"slot over 120":               "is 121 characters, over the limit of 120",
		"long name":                   "is 61 characters, over the limit of 60",
		"long brand name":             "is 61 characters, over the limit of 60",
		"long strapline":              "is 121 characters, over the limit of 120",
		"long contact line":           "is 121 characters, over the limit of 120",
		"long confidentiality":        "is 121 characters, over the limit of 120",
		"long website":                "is 126 characters, over the limit of 120",
		"five contact lines":          "is 5 lines, over the limit of 4",
		"empty contact line":          blank,
		"blank brand name":            blank,
		"slot only spaces":            blank,
		"empty name":                  blank,
		"blank name":                  blank,
		"secondary spaces":            "must be a colour #rrggbb in lower-case hex, or empty for none",
		"secondary short":             "must be a colour #rrggbb in lower-case hex, or empty for none",
		"secondary upper-case":        "must be a colour #rrggbb in lower-case hex, or empty for none",
		"secondary name":              "must be a colour #rrggbb in lower-case hex, or empty for none",
		"version zero":                "must be a whole number from 1 to 1000000",
		"version too high":            "must be a whole number from 1 to 1000000",
		"theme document 1":            "must be 3",
		"theme document 2":            "must be 3",
		"theme document 4":            "must be 3",
		"missing accent":              required,
		"missing nested":              required,
		"null field":                  required,
		"null slots":                  required,
		"null contact":                required,
		"null nested field":           required,
		"wrong type":                  "must be a number",
		"wrong nested type":           "must be a boolean",
		"a logo by file name":         "must be an object",
		"a cover image by file name":  "must be an object",
		"a custom cover by file name": "must be an object",
		"fonts as a string":           "must be an object",
		"name as a number":            "must be a string",
		"unknown key":                 `unknown key "watermark"`,
		"version 2 footer text":       `unknown key "text"`,
		"unknown nested key":          `unknown key "math"`,
		"unknown brand key":           `unknown key "logo"`,
		"unknown cover key":           `unknown key "source"`,
	}
	for _, name := range []string{"short colour", "upper-case colour", "colour name", "css function", "colour with alpha",
		"five-digit colour", "colour without a hash", "colour with a prefix", "colour with a non-hex letter"} {
		wantMsg[name] = colourMsg
	}
	for _, name := range []string{"http website", "website with a space", "website with credentials", "website with a port",
		"website with a query", "website one label", "website with a scheme in the path"} {
		wantMsg[name] = webMsg
	}
	for _, c := range cases {
		if strings.HasPrefix(c.name, "missing ") {
			wantMsg[c.name] = required
		}
		// A format character in any free text is the one-line refusal.
		if wantMsg[c.name] == "" {
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
			if s, ok := c.value.(string); ok && len(s) >= 4 && c.field != "accent" && c.field != "secondary" {
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
			if errors.Is(err, ErrImageFormat) || errors.Is(err, ErrImageTooLarge) {
				t.Errorf("a refusal outside an image wraps an image kind: %v", err)
			}
		})
	}
	if got := (&FieldError{Field: "fonts.body", Message: "m"}).Error(); got != "report design: fonts.body: m" {
		t.Errorf("a field's refusal reads %q", got)
	}
	if got := (&FieldError{Message: "m"}).Error(); got != "report design: m" {
		t.Errorf("the document's refusal reads %q", got)
	}

	// What sits exactly on a limit is accepted: the names and the lines are
	// counted in characters, not bytes, a version may be 1 or the largest,
	// headings take any family, a website may be a host or an https
	// address with a path, and a slot may hold any token or braces around
	// an unknown word.
	for _, c := range []struct {
		name, path string
		value      any
	}{
		{"name of 60 characters", "name", strings.Repeat("n", MaxNameRunes)},
		{"name of 60 multi-byte characters", "name", strings.Repeat(string(rune(0xe9)), MaxNameRunes)},
		{"brand name of 60 characters", "brand.name", strings.Repeat("n", MaxNameRunes)},
		{"strapline of 120 characters", "brand.strapline", strings.Repeat(string(rune(0xe9)), MaxLineRunes)},
		{"four contact lines", "brand.contact", []string{"1 High Street", "Town", "+44 20 7946 0000", "hello@example.com"}},
		{"a contact line of 120 characters", "brand.contact", []string{strings.Repeat("c", MaxLineRunes)}},
		{"no contact lines", "brand.contact", []string{}},
		{"a host website", "brand.website", "example.com"},
		{"a host with a path", "brand.website", "example.com/reports"},
		{"an https website", "brand.website", "https://www.example.co.uk/about/"},
		{"a capitalised website", "brand.website", "Example.COM"},
		{"no website", "brand.website", ""},
		{"a confidentiality line", "brand.confidentiality", "Confidential — for the addressee only"},
		{"a slot of 120 characters", "header.slots", []string{strings.Repeat(string(rune(0xe9)), MaxLineRunes), "", ""}},
		{"every token in a slot", "footer.slots", []string{"{title} {author} {date} {page} {pages} {brand} {section} {confidentiality}", "", ""}},
		{"braces around an unknown word", "footer.slots", []string{"{price} {Title} {}", "", ""}},
		{"no-break space inside a slot", "footer.slots", []string{"a" + string(rune(0xa0)) + "b", "", ""}},
		{"no secondary", "secondary", ""},
		{"a secondary", "secondary", "#8a6a00"},
		{"version 1", "version", 1},
		{"the largest version", "version", MaxVersion},
		{"headings in a mono face", "fonts.headings", "Fira Code"},
		{"headings in a display face", "fonts.headings", "Fraunces"},
		{"a body in a new family", "fonts.body", "DM Sans"},
		{"every cover fact", "cover.shows", []string{"title", "subtitle", "author", "date", "brand", "logo", "confidentiality"}},
		{"no cover fact", "cover.shows", []string{}},
		{"a custom cover style with no custom cover", "cover.style", "custom"},
		{"a cover never drawn", "cover.when", "never"},
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
	tooBig := modern(t)
	set(tooBig, "brand.contact", []string{strings.Repeat("c", 120), strings.Repeat("c", 120), strings.Repeat("c", 120), strings.Repeat("c", 120)})
	for name, data := range map[string][]byte{
		"over-size":     append(bytes.Repeat([]byte(" "), MaxDocumentWithAssets), doc...),
		"two values":    append(append([]byte{}, doc...), []byte("{}")...),
		"an array":      []byte("[]"),
		"not json":      []byte("agentryTheme: 3"),
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
			"over-size":                 "over the",
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
	// The document's own cap is on its canonical form without its images
	// and custom cover: whitespace as sent does not count, and a design
	// whose texts take it over the cap is refused as a whole.
	padded := append(bytes.Repeat([]byte(" "), MaxDocumentBytes), doc...)
	if _, err := Parse(padded); err != nil {
		t.Errorf("a padded document under the cap with its assets is refused: %v", err)
	}
	if n := len(Default().Canonical()); n > MaxDocumentBytes/8 {
		t.Errorf("Plain's document is %d bytes; the cap leaves little room", n)
	}
}

// What a design may hold as text is accepted as text: Typst markup in a
// header slot or a brand line is data, which the runner's template sets
// literally, and characters JSON would escape for HTML are written as they
// are. A slot's tokens are the only thing the template substitutes.
func TestTextIsData(t *testing.T) {
	m := modern(t)
	const markup = `#import "@preview/x:0.1.0" & <b>Acme</b> — 第1页 #eval("1+1") {title}`
	set(m, "header.slots", []string{markup, "", ""})
	set(m, "brand.strapline", "#set page(fill: red)")
	set(m, "name", "Acme & Co")
	doc, _ := json.Marshal(m)
	d, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(d.Canonical(), []byte(`"Acme & Co"`)) {
		t.Fatalf("canonical escapes the text: %s", d.Canonical())
	}
	if d.Header.Slots[0] != markup || d.Brand.Strapline != "#set page(fill: red)" {
		t.Fatalf("the markup was changed: %q, %q", d.Header.Slots[0], d.Brand.Strapline)
	}
	if got := ExpandSlot(d.Header.Slots[0], map[string]string{"title": "Q3"}); got != strings.TrimSuffix(markup, "{title}")+"Q3" {
		t.Fatalf("ExpandSlot touched more than the token: %q", got)
	}
}

// The tokens: each known token is substituted, an unknown word between
// braces and an unclosed brace are literal, a token with no fact is empty,
// and TokensIn names each known token once in order.
func TestTokens(t *testing.T) {
	if !slices.Equal(Tokens, []string{"title", "author", "date", "page", "pages", "brand", "section", "confidentiality"}) {
		t.Fatalf("tokens %v", Tokens)
	}
	facts := map[string]string{"title": "Q3 review", "page": "2", "pages": "9", "brand": "Acme", "section": "Findings"}
	for _, c := range []struct{ slot, want string }{
		{"", ""},
		{"plain text", "plain text"},
		{"{title}", "Q3 review"},
		{"{page} of {pages}", "2 of 9"},
		{"{brand} — {section}", "Acme — Findings"},
		{"{author}", ""},
		{"{date}: {title}", ": Q3 review"},
		{"{Title} {TITLE} {price} {} { title }", "{Title} {TITLE} {price} {} { title }"},
		{"{title", "{title"},
		{"title}", "title}"},
		{"{{title}}", "{Q3 review}"},
		{"{title}{title}", "Q3 reviewQ3 review"},
		{"a {b {title} c} d", "a {b Q3 review c} d"},
	} {
		if got := ExpandSlot(c.slot, facts); got != c.want {
			t.Errorf("ExpandSlot(%q) = %q, want %q", c.slot, got, c.want)
		}
	}
	for _, c := range []struct {
		slot string
		want []string
	}{
		{"", nil},
		{"{title}", []string{"title"}},
		{"{page} of {pages} {page}", []string{"page", "pages"}},
		{"{price} {Title}", nil},
		{"{title", nil},
		{"{brand} — {confidentiality}", []string{"brand", "confidentiality"}},
	} {
		if got := TokensIn(c.slot); !slices.Equal(got, c.want) {
			t.Errorf("TokensIn(%q) = %v, want %v", c.slot, got, c.want)
		}
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
			for _, accent := range []string{
				fmt.Sprintf("#%02x%02x%02x", v, v, v),
				fmt.Sprintf("#%02x%02x%02x", v, 0x80, 0xff-v),
				fmt.Sprintf("#%02x%02x%02x", 0xe0-v/2, v, 0x40),
			} {
				d.Accent = accent
				err := d.Validate()
				var fe *FieldError
				if !errors.As(err, &fe) || fe.Field != "accent" {
					continue
				}
				m := reachesRatio.FindStringSubmatch(fe.Message)
				if m == nil {
					t.Fatalf("%s: %q prints no ratio", accent, fe.Message)
				}
				if shown, _ := strconv.ParseFloat(m[1], 64); shown >= need {
					t.Fatalf("%s: %q prints %s, which reaches %v", accent, fe.Message, m[1], need)
				}
			}
		}
	}
}

var reachesRatio = regexp.MustCompile(` reaches ([0-9.]+):1 on white`)

// The contrast table, for the accent and the secondary against each style
// that decides whether a colour carries text.
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

	// The two lines sit between neighbouring greys: 3:1 for a colour that
	// colours only graphics, 4.5:1 where it touches text. The message says
	// which, what the colour reaches, and a shade that does pass. The
	// fixture is Modern with a framed cover, so only the title block and
	// the headings decide the accent.
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
		{"#959595", "bar", "rule", false, GraphicsContrast, "needs 3.0:1", "an accent that colours only graphics", "#959595 reaches 2.99:1 on white"},
		{"#767676", "band", "rule", true, TextContrast, "", "", ""},
		{"#777777", "band", "rule", false, TextContrast, "needs 4.5:1", "an accent that colours text", "#777777 reaches 4.48:1 on white"},
		{"#767676", "bar", "smallcaps", true, TextContrast, "", "", ""},
		{"#777777", "bar", "smallcaps", false, TextContrast, "needs 4.5:1", "colours text", "#777777 reaches 4.48:1 on white"},
		{"#767676", "bar", "numbered", true, TextContrast, "", "", ""},
		{"#777777", "bar", "numbered", false, TextContrast, "needs 4.5:1", "colours text", "#777777 reaches 4.48:1 on white"},
		{"#a8c7fa", "bar", "rule", false, GraphicsContrast, "needs 3.0:1", "colours only graphics", "#a8c7fa reaches 1.72:1 on white"},
	} {
		m := modern(t)
		set(m, "cover.style", "framed")
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

	// An accent on graphics only needs 3:1; the same accent on text 4.5:1,
	// whichever way the design puts it there: the title block, the
	// headings, or a cover style that declares it, drawn at all.
	base := func() map[string]any {
		m := modern(t)
		set(m, "titleBlock", "bar")
		set(m, "headings", "rule")
		set(m, "cover.style", "framed")
		set(m, "accent", "#3d8bfd") // 3.4:1
		return m
	}
	d, err := Parse(mustJSON(t, base()))
	if err != nil {
		t.Fatalf("a 3.4:1 accent on graphics only is refused: %v", err)
	}
	if d.AccentOnText() || d.MinContrast() != GraphicsContrast {
		t.Fatalf("bar, rule and a framed cover put the accent on text")
	}
	for _, onText := range []struct{ path, value string }{
		{"titleBlock", "band"}, {"headings", "smallcaps"}, {"headings", "numbered"},
		{"cover.style", "band"}, {"cover.style", "largeType"}, {"cover.style", "plate"},
		// custom falls back to band when it cannot be drawn.
		{"cover.style", "custom"},
		// split with no secondary: the panel is the accent.
		{"cover.style", "split"},
	} {
		m := base()
		set(m, onText.path, onText.value)
		_, err := Parse(mustJSON(t, m))
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "accent" || !strings.Contains(fe.Message, "an accent that colours text needs 4.5:1; the nearest shade that does is #") {
			t.Errorf("%s %s with a 3.4:1 accent: %v", onText.path, onText.value, err)
		}
		// A cover never drawn decides nothing.
		if onText.path == "cover.style" {
			set(m, "cover.when", "never")
			if d, err := Parse(mustJSON(t, m)); err != nil || d.AccentOnText() {
				t.Errorf("%s %s never drawn still puts the accent on text: %v", onText.path, onText.value, err)
			}
		}
	}
	// The styles that colour only graphics take the 3.4:1 accent on the
	// cover, drawn always.
	for _, style := range []string{"geometric", "framed"} {
		m := base()
		set(m, "cover.style", style)
		set(m, "cover.when", "always")
		if d, err := Parse(mustJSON(t, m)); err != nil || d.AccentOnText() {
			t.Errorf("cover %s with a 3.4:1 accent: %v", style, err)
		}
	}
	// Below 3:1 is refused even on graphics.
	m := base()
	set(m, "accent", "#a8c7fa")
	if _, err := Parse(mustJSON(t, m)); err == nil {
		t.Error("a 1.8:1 accent on graphics is accepted")
	}

	// The secondary: 3:1 on graphics, 4.5:1 where split puts the brand on
	// it, and the refusal names it. With a secondary, split no longer puts
	// the accent on text.
	for _, c := range []struct {
		style, when, secondary string
		ok                     bool
		accentOnText           bool
		secondaryOnText        bool
	}{
		{"framed", "always", "#949494", true, false, false},  // 3.03:1 on graphics
		{"framed", "always", "#959595", false, false, false}, // 2.99:1
		{"split", "always", "#767676", true, false, true},    // 4.54:1 on text
		{"split", "always", "#777777", false, false, false},  // 4.48:1
		{"split", "never", "#777777", true, false, false},    // not drawn
		{"geometric", "always", "#777777", true, false, false},
		{"band", "always", "#949494", true, true, false},
	} {
		m := base()
		set(m, "accent", "#1f6feb")
		set(m, "cover.style", c.style)
		set(m, "cover.when", c.when)
		set(m, "secondary", c.secondary)
		d, err := Parse(mustJSON(t, m))
		if c.ok {
			if err != nil {
				t.Errorf("cover %s %s with secondary %s: %v", c.style, c.when, c.secondary, err)
				continue
			}
			if d.AccentOnText() != c.accentOnText || d.SecondaryOnText() != c.secondaryOnText {
				t.Errorf("cover %s %s with secondary %s: accent on text %v, secondary on text %v", c.style, c.when, c.secondary, d.AccentOnText(), d.SecondaryOnText())
			}
			want := GraphicsContrast
			if c.secondaryOnText {
				want = TextContrast
			}
			if d.MinSecondaryContrast() != want {
				t.Errorf("cover %s %s: the secondary needs %v, want %v", c.style, c.when, d.MinSecondaryContrast(), want)
			}
			continue
		}
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != "secondary" {
			t.Errorf("cover %s %s with secondary %s: %v, want a refusal on secondary", c.style, c.when, c.secondary, err)
			continue
		}
		use := "a secondary that colours only graphics needs 3.0:1"
		if c.style == "split" {
			use = "a secondary that colours text needs 4.5:1"
		}
		if !strings.Contains(fe.Message, c.secondary+" reaches ") || !strings.Contains(fe.Message, use) || !strings.Contains(fe.Message, "the nearest shade that does is #") {
			t.Errorf("cover %s with secondary %s: %q", c.style, c.secondary, fe.Message)
		}
		if r, err := Contrast(shadeOf(fe.Message), White); err != nil || r < d.MinSecondaryContrast() && r < GraphicsContrast {
			t.Errorf("the suggested secondary %q reaches %.2f:1 (%v)", shadeOf(fe.Message), r, err)
		}
	}

	// Each cover style's declaration, as the table reads.
	want := map[string][2]bool{
		"band": {true, false}, "split": {false, true}, "geometric": {false, false}, "largeType": {true, false},
		"framed": {false, false}, "plate": {true, false}, "custom": {true, false},
	}
	if got := CoverStyleNames(); !slices.Equal(got, []string{"band", "split", "geometric", "largeType", "framed", "plate", "custom"}) {
		t.Fatalf("cover styles %v", got)
	}
	for _, s := range CoverStyles() {
		if w := want[s.Name]; s.AccentOnText != w[0] || s.SecondaryOnText != w[1] {
			t.Errorf("%s declares accent %v, secondary %v", s.Name, s.AccentOnText, s.SecondaryOnText)
		}
	}
	if _, ok := CoverStyleByName("hero"); ok {
		t.Error("CoverStyleByName finds a style that is not one")
	}
	styles := CoverStyles()
	styles[0].Name = "edited"
	if CoverStyles()[0].Name != "band" {
		t.Error("editing the returned styles changed the list")
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

// There are twenty-two families, each role takes the right ones, each has
// a version-2 family of its own kind, and the built-ins use only those.
func TestFamilies(t *testing.T) {
	if n := len(Families()); n != 22 {
		t.Fatalf("%d families", n)
	}
	if got := FontsFor("code"); !slices.Equal(got, []string{"IBM Plex Mono", "JetBrains Mono", "Source Code Pro", "Fira Code"}) {
		t.Fatalf("code fonts %v", got)
	}
	body := FontsFor("body")
	for _, no := range []string{"Montserrat", "Playfair Display", "Fraunces", "IBM Plex Mono", "Fira Code"} {
		if slices.Contains(body, no) {
			t.Fatalf("body fonts %v take %s", body, no)
		}
	}
	if len(FontsFor("headings")) != 22 || FontsFor("logo") != nil {
		t.Fatal("headings take every family; an unknown role none")
	}

	// The whole list: name, kind, whether a face is for headings only, and
	// the version-2 family it projects to.
	want := []Family{
		{"Inter", Sans, false, "Inter"}, {"IBM Plex Sans", Sans, false, "IBM Plex Sans"}, {"Source Sans 3", Sans, false, "Source Sans 3"}, {"Work Sans", Sans, false, "Work Sans"},
		{"DM Sans", Sans, false, "Inter"}, {"Nunito Sans", Sans, false, "Source Sans 3"}, {"Raleway", Sans, false, "Work Sans"}, {"Space Grotesk", Sans, false, "IBM Plex Sans"},
		{"Montserrat", Sans, true, "Montserrat"},
		{"Source Serif 4", Serif, false, "Source Serif 4"}, {"Lora", Serif, false, "Lora"}, {"Merriweather", Serif, false, "Merriweather"},
		{"IBM Plex Serif", Serif, false, "IBM Plex Serif"}, {"EB Garamond", Serif, false, "EB Garamond"},
		{"Libre Baskerville", Serif, false, "Lora"}, {"Crimson Pro", Serif, false, "EB Garamond"},
		{"Playfair Display", Serif, true, "Playfair Display"}, {"Fraunces", Serif, true, "Playfair Display"},
		{"IBM Plex Mono", Mono, false, "IBM Plex Mono"}, {"JetBrains Mono", Mono, false, "JetBrains Mono"}, {"Source Code Pro", Mono, false, "Source Code Pro"}, {"Fira Code", Mono, false, "JetBrains Mono"},
	}
	if got := Families(); !slices.Equal(got, want) {
		t.Fatalf("families %+v, want %+v", got, want)
	}
	// The first fourteen are version 2's, each its own projection; every
	// other family projects to one of them, of its kind and headings-only
	// where it is.
	version2 := []string{"Inter", "IBM Plex Sans", "Source Sans 3", "Work Sans", "Montserrat", "Source Serif 4", "Lora", "Merriweather", "IBM Plex Serif", "EB Garamond", "Playfair Display", "IBM Plex Mono", "JetBrains Mono", "Source Code Pro"}
	for _, f := range Families() {
		v2, ok := FamilyByName(f.Version2)
		if !ok || !slices.Contains(version2, f.Version2) || v2.Kind != f.Kind || v2.HeadingsOnly != f.HeadingsOnly {
			t.Errorf("%s projects to %q", f.Name, f.Version2)
		}
		if slices.Contains(version2, f.Name) && f.Version2 != f.Name {
			t.Errorf("%s, a version-2 family, projects to %s", f.Name, f.Version2)
		}
	}
	if got := FontsFor("body"); !slices.Equal(got, []string{"Inter", "IBM Plex Sans", "Source Sans 3", "Work Sans", "DM Sans", "Nunito Sans", "Raleway", "Space Grotesk",
		"Source Serif 4", "Lora", "Merriweather", "IBM Plex Serif", "EB Garamond", "Libre Baskerville", "Crimson Pro"}) {
		t.Fatalf("body fonts %v", got)
	}

	// The list is a copy, and a family is found by its exact name.
	f := Families()
	f[0].Name = "edited"
	if Families()[0].Name != "Inter" {
		t.Fatal("editing the returned families changed the list")
	}
	if fam, ok := FamilyByName("Playfair Display"); !ok || fam != want[16] {
		t.Fatalf("FamilyByName(Playfair Display) = %+v, %v", fam, ok)
	}
	for _, name := range []string{"inter", "INTER", "Inter ", "", "Noto Sans"} {
		if fam, ok := FamilyByName(name); ok {
			t.Errorf("FamilyByName(%q) found %+v", name, fam)
		}
	}
}

// The version-2 projection of a version-3 design is a valid version-2
// document (every field version 2 had, in its order, from its closed lists)
// that keeps the look: the colour, the faces, the title block, the headings,
// the tables, the quotes, the page numbers and the logo carry over; a new
// family or built-in becomes its nearest; the footer's line is the first
// slot with text, its brand tokens filled and the rest dropped.
func TestVersion2Projection(t *testing.T) {
	v2Families := []string{"Inter", "IBM Plex Sans", "Source Sans 3", "Work Sans", "Montserrat", "Source Serif 4", "Lora", "Merriweather", "IBM Plex Serif", "EB Garamond", "Playfair Display", "IBM Plex Mono", "JetBrains Mono", "Source Code Pro"}
	v2Keys := []string{"agentryTheme", "name", "basedOn", "version", "paper", "fonts", "accent", "titleBlock", "headings", "tables", "quotes", "footer"}
	// isVersion2 holds a document to version 2's rules as its readers
	// apply them.
	isVersion2 := func(t *testing.T, doc []byte) map[string]any {
		t.Helper()
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(doc))
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("not JSON: %v", err)
		}
		keys := v2Keys
		if _, ok := m["logo"]; ok {
			keys = append(slices.Clone(keys), "logo")
		}
		if len(m) != len(keys) {
			t.Fatalf("the projection has %d keys, want %d: %s", len(m), len(keys), doc)
		}
		// The key order is version 2's: the document reads as the keys do.
		last := -1
		for _, k := range keys {
			i := bytes.Index(doc, []byte("\n  \""+k+"\":"))
			if i < last {
				t.Fatalf("key %s is out of version 2's order in %s", k, doc)
			}
			last = i
		}
		if m["agentryTheme"] != float64(2) {
			t.Fatalf("agentryTheme %v", m["agentryTheme"])
		}
		if !slices.Contains([]string{"plain", "classic", "modern", "editorial", "technical"}, m["basedOn"].(string)) {
			t.Fatalf("basedOn %v", m["basedOn"])
		}
		fonts := m["fonts"].(map[string]any)
		for _, role := range []string{"headings", "body", "code"} {
			if !slices.Contains(v2Families, fonts[role].(string)) {
				t.Fatalf("fonts.%s %v is not a version-2 family", role, fonts[role])
			}
		}
		if !hexColour.MatchString(m["accent"].(string)) {
			t.Fatalf("accent %v", m["accent"])
		}
		for k, list := range map[string][]string{"paper": Papers, "titleBlock": TitleBlocks, "headings": HeadingStyles, "quotes": QuoteStyles} {
			if !slices.Contains(list, m[k].(string)) {
				t.Fatalf("%s %v", k, m[k])
			}
		}
		footer := m["footer"].(map[string]any)
		if !slices.Contains(PageNumberStyles, footer["pageNumbers"].(string)) || len(footer) != 2 {
			t.Fatalf("footer %v", footer)
		}
		if text := footer["text"].(string); len([]rune(text)) > 120 || strings.ContainsAny(text, "\n\t") {
			t.Fatalf("footer text %q", text)
		}
		// Version 2's own contrast rule.
		onText := m["titleBlock"] == "band" || m["headings"] == "smallcaps" || m["headings"] == "numbered"
		if need := GraphicsContrast; onText {
			need = TextContrast
			if onWhite(m["accent"].(string)) < need {
				t.Fatalf("the accent fails version 2's rule")
			}
		} else if onWhite(m["accent"].(string)) < need {
			t.Fatalf("the accent fails version 2's rule")
		}
		return m
	}
	for _, d := range Builtins() {
		m := isVersion2(t, d.Version2())
		if m["name"] != d.Name || m["version"] != float64(d.Version) || m["accent"] != d.Accent || m["titleBlock"] != d.TitleBlock || m["headings"] != d.Headings || m["quotes"] != d.Quotes {
			t.Errorf("%s: the projection changed the look: %s", d.BasedOn, d.Version2())
		}
	}
	// New built-ins and new families map to their nearest.
	for id, near := range map[string]string{"boardroom": "classic", "studio": "modern", "field": "technical", "civic": "classic", "lumen": "modern"} {
		b, _ := Builtin(id)
		if m := isVersion2(t, b.Version2()); m["basedOn"] != near {
			t.Errorf("%s projects to %v, want %s", id, m["basedOn"], near)
		}
	}
	studio, _ := Builtin("studio")
	if m := isVersion2(t, studio.Version2()); m["fonts"].(map[string]any)["headings"] != "IBM Plex Sans" || m["fonts"].(map[string]any)["body"] != "Inter" || m["fonts"].(map[string]any)["code"] != "JetBrains Mono" {
		t.Errorf("Studio's faces project to %v", m["fonts"])
	}
	// The footer line.
	d := Default()
	d.Brand.Name, d.Brand.Confidentiality = "Acme Ltd", "Confidential"
	for _, c := range []struct {
		slots [SlotCount]string
		want  string
	}{
		{[SlotCount]string{"", "", ""}, ""},
		{[SlotCount]string{"Acme — all rights reserved", "", ""}, "Acme — all rights reserved"},
		{[SlotCount]string{"", "{brand} · {confidentiality}", ""}, "Acme Ltd · Confidential"},
		{[SlotCount]string{"{title}", "", "{brand}"}, "Acme Ltd"},
		{[SlotCount]string{"{page} of {pages}", "{confidentiality}", ""}, "of"},
		{[SlotCount]string{"{brand}  {section}   {date} ", "", ""}, "Acme Ltd"},
		{[SlotCount]string{strings.Repeat("x", 100) + " " + strings.Repeat("y", 30), "", ""}, strings.Repeat("x", 100) + " " + strings.Repeat("y", 19)},
	} {
		d.Footer.Slots = c.slots
		m := isVersion2(t, d.Version2())
		if got := m["footer"].(map[string]any)["text"]; got != c.want {
			t.Errorf("slots %q project to footer text %q, want %q", c.slots, got, c.want)
		}
	}
	// A version-2 document is refused on save, with no mapping.
	v2, _ := os.ReadFile("testdata/v2/modern.json")
	_, err := Parse(v2)
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "agentryTheme" {
		t.Errorf("a version-2 document: %v, want a refusal on agentryTheme", err)
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
	// Every field is required but the logo, the cover image and the custom
	// cover.
	if len(s.Required) != 18 || len(s.Properties) != 21 {
		t.Fatalf("the schema has %d properties, %d required", len(s.Properties), len(s.Required))
	}
	for _, optional := range []string{"logo", "coverImage", "customCover"} {
		if slices.Contains(s.Required, optional) {
			t.Errorf("%s is required", optional)
		}
		if _, ok := s.Properties[optional]; !ok {
			t.Errorf("%s is not a property", optional)
		}
	}
}

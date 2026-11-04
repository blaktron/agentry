package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/reportdesign"
)

// designRecord is one design as the API answers it.
type designRecord struct {
	ID             uuid.UUID       `json:"id"`
	Default        bool            `json:"default"`
	HasLogo        bool            `json:"hasLogo"`
	HasCoverImage  bool            `json:"hasCoverImage"`
	HasCustomCover bool            `json:"hasCustomCover"`
	Design         json.RawMessage `json:"design"`
}

// designList is the library as the API answers it.
type designList struct {
	Designs []struct {
		ID             uuid.UUID `json:"id"`
		Name           string    `json:"name"`
		BasedOn        string    `json:"basedOn"`
		Version        int       `json:"version"`
		Default        bool      `json:"default"`
		HasLogo        bool      `json:"hasLogo"`
		HasCoverImage  bool      `json:"hasCoverImage"`
		HasCustomCover bool      `json:"hasCustomCover"`
	} `json:"designs"`
	Default *uuid.UUID `json:"default"`
}

type designProblem struct {
	Detail string `json:"detail"`
	Errors []struct {
		Field   string `json:"field"`
		Message string `json:"message"`
	} `json:"errors"`
}

const designsPath = "/api/v1/user/report-designs"

// parseDesign is the design the server answered, which must parse.
func parseDesign(t *testing.T, raw json.RawMessage) reportdesign.Design {
	t.Helper()
	d, err := reportdesign.Parse(raw)
	if err != nil {
		t.Fatalf("the server answered a design that does not parse: %v (%.300s)", err, raw)
	}
	return d
}

// The report design library: an account with no designs reads an empty
// library with no default, which is not Plain; each built-in and an edited
// design round-trip as their canonical documents; the library holds ten and
// refuses an eleventh with 409; the default is set, moved and removed, and
// goes with its design when that is deleted; a design that breaks a rule is
// refused 422 naming design.<path> and the saved one stands; a version-2
// document is refused with no mapping; each account reaches only its own,
// a user:profile token included, since the CLI reads it that way; a stored
// document that no longer validates is still listed; and clearing the
// account's data removes the library.
func TestReportDesignsRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("rd-user")
	env.verifyEmail(u)
	sess := env.login(u)
	other := env.register("rd-other")
	env.verifyEmail(other)
	otherSess := env.login(other)

	var list designList
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 0 || list.Default != nil {
		t.Fatalf("a new account's library: %+v", list)
	}

	// Each built-in round-trips: the create's answer, and a later read, are
	// its canonical document byte for byte, and the library lists it. The
	// first is created as the default, the rest without a say, so the
	// default stays where it was put.
	ids := map[string]uuid.UUID{}
	for i, id := range reportdesign.BuiltinIDs() {
		doc, _ := reportdesign.BuiltinDocument(id)
		body := map[string]any{"design": json.RawMessage(doc)}
		if i == 0 {
			body["default"] = true
		}
		var rec designRecord
		env.doJSON(sess, http.MethodPost, designsPath, body, &rec, http.StatusCreated)
		if !bytes.Equal(parseDesign(t, rec.Design).Canonical(), doc) || rec.Default != (i == 0) || rec.HasLogo || rec.HasCoverImage || rec.HasCustomCover {
			t.Fatalf("POST %s answered %+v", id, rec)
		}
		ids[id] = rec.ID
		var got designRecord
		env.doJSON(sess, http.MethodGet, designsPath+"/"+rec.ID.String(), nil, &got, http.StatusOK)
		if !bytes.Equal(parseDesign(t, got.Design).Canonical(), doc) || got.ID != rec.ID {
			t.Fatalf("GET after POST %s read %s", id, got.Design)
		}
	}
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != reportdesign.MaxLibrary || list.Default == nil || *list.Default != ids["plain"] {
		t.Fatalf("the library after ten creates: %d designs, default %v", len(list.Designs), list.Default)
	}
	for i, d := range list.Designs {
		want := reportdesign.BuiltinIDs()[i]
		b, _ := reportdesign.Builtin(want)
		if d.ID != ids[want] || d.Name != b.Name || d.BasedOn != want || d.Version != b.Version || d.Default != (i == 0) {
			t.Fatalf("the library lists %+v at %d, want %s", d, i, want)
		}
	}

	// An eleventh is 409, and the library is unchanged.
	doc, _ := reportdesign.BuiltinDocument("modern")
	var p designProblem
	env.doJSON(sess, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(doc)}, &p, http.StatusConflict)
	if !strings.Contains(p.Detail, "ten designs") {
		t.Fatalf("the eleventh: %+v", p)
	}
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != reportdesign.MaxLibrary {
		t.Fatalf("the library after the refused eleventh: %d", len(list.Designs))
	}

	// The default moves to another design, and the previous one stays an
	// ordinary design; an id that is not the caller's is 404 and changes
	// nothing; none removes the default; a create as the default takes it.
	list = designList{}
	env.doJSON(sess, http.MethodPut, designsPath+"/default", map[string]any{"id": ids["lumen"]}, &list, http.StatusOK)
	if list.Default == nil || *list.Default != ids["lumen"] || !list.Designs[9].Default || list.Designs[0].Default {
		t.Fatalf("the default did not move: %+v", list)
	}
	env.doJSON(sess, http.MethodPut, designsPath+"/default", map[string]any{"id": uuid.New()}, nil, http.StatusNotFound)
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if list.Default == nil || *list.Default != ids["lumen"] {
		t.Fatalf("a 404 moved the default: %+v", list)
	}
	for _, body := range []map[string]any{{}, {"id": nil}} {
		list = designList{}
		env.doJSON(sess, http.MethodPut, designsPath+"/default", body, &list, http.StatusOK)
		if list.Default != nil {
			t.Fatalf("PUT default %v left a default: %+v", body, list)
		}
		for _, d := range list.Designs {
			if d.Default {
				t.Fatalf("PUT default %v left %s the default", body, d.Name)
			}
		}
	}
	// Deleting a design: the default goes with it, another account's or a
	// deleted id is 404.
	env.doJSON(sess, http.MethodPut, designsPath+"/default", map[string]any{"id": ids["civic"]}, nil, http.StatusOK)
	env.doJSON(sess, http.MethodDelete, designsPath+"/"+ids["civic"].String(), nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodDelete, designsPath+"/"+ids["civic"].String(), nil, nil, http.StatusNotFound)
	env.doJSON(sess, http.MethodGet, designsPath+"/"+ids["civic"].String(), nil, nil, http.StatusNotFound)
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 9 || list.Default != nil {
		t.Fatalf("after deleting the default: %d designs, default %v", len(list.Designs), list.Default)
	}
	delete(ids, "civic")
	var created designRecord
	env.doJSON(sess, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(doc), "default": true}, &created, http.StatusCreated)
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if list.Default == nil || *list.Default != created.ID || !created.Default {
		t.Fatalf("a create as the default: %+v, %+v", created, list)
	}
	env.doJSON(sess, http.MethodDelete, designsPath+"/"+created.ID.String(), nil, nil, http.StatusNoContent)

	// An edited design: the person's name, their colours, US Letter, a
	// brand block, header and footer slots and a cover, sent compact and in
	// another key order, is stored and answered in its canonical form; the
	// update keeps the id and whether it is the default.
	mine, _ := reportdesign.Builtin("technical")
	mine.Name, mine.Accent, mine.Secondary, mine.Paper = "Acme review", "#0b5c55", "#8a6a00", "letter"
	mine.Brand = reportdesign.Brand{Name: "Acme Ltd", Strapline: "Security reviews", Contact: []string{"1 High Street", "hello@acme.example"}, Website: "acme.example", Confidentiality: "Confidential"}
	mine.Header = reportdesign.Header{Style: "brandLine", Slots: [3]string{"{brand}", "", "{date}"}}
	mine.Footer.Slots = [3]string{"{confidentiality}", "", "{page} of {pages}"}
	mine.Cover = reportdesign.Cover{Style: "split", Shows: []string{"title", "brand", "logo"}, When: "always"}
	var loose map[string]any
	_ = json.Unmarshal(mine.Canonical(), &loose)
	env.doJSON(sess, http.MethodPut, designsPath+"/default", map[string]any{"id": ids["technical"]}, nil, http.StatusOK)
	var updated designRecord
	env.doJSON(sess, http.MethodPut, designsPath+"/"+ids["technical"].String(), map[string]any{"design": loose}, &updated, http.StatusOK)
	if !bytes.Equal(parseDesign(t, updated.Design).Canonical(), mine.Canonical()) || updated.ID != ids["technical"] || !updated.Default {
		t.Fatalf("the edited design was answered as %+v", updated)
	}
	var got designRecord
	env.doJSON(sess, http.MethodGet, designsPath+"/"+ids["technical"].String(), nil, &got, http.StatusOK)
	if !bytes.Equal(parseDesign(t, got.Design).Canonical(), mine.Canonical()) {
		t.Fatalf("the edited design read back %s", got.Design)
	}
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if list.Designs[4].Name != "Acme review" || list.Designs[4].BasedOn != "technical" {
		t.Fatalf("the library lists the edited design as %+v", list.Designs[4])
	}
	// An update of another account's design, or a deleted one, is 404.
	env.doJSON(sess, http.MethodPut, designsPath+"/"+uuid.New().String(), map[string]any{"design": loose}, nil, http.StatusNotFound)

	// set and drop edit a design document by a dotted path.
	holder := func(m map[string]any, path string) (map[string]any, string) {
		keys := strings.Split(path, ".")
		for _, k := range keys[:len(keys)-1] {
			m = m[k].(map[string]any)
		}
		return m, keys[len(keys)-1]
	}
	set := func(path string, v any) func(map[string]any) {
		return func(m map[string]any) { h, k := holder(m, path); h[k] = v }
	}
	drop := func(path string) func(map[string]any) {
		return func(m map[string]any) { h, k := holder(m, path); delete(h, k) }
	}
	both := func(edits ...func(map[string]any)) func(map[string]any) {
		return func(m map[string]any) {
			for _, e := range edits {
				e(m)
			}
		}
	}
	mineDoc := func() map[string]any {
		m := map[string]any{}
		_ = json.Unmarshal(mine.Canonical(), &m)
		return m
	}
	minePath := designsPath + "/" + ids["technical"].String()

	// Accepted at each bound: the longest name and lines (counted in
	// characters, not bytes), the lowest and highest revision, an accent
	// just over the contrast its use needs, a secondary at its line, and
	// one the graphics-only designs take and the designs that set text in
	// the accent do not.
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"a name of 60 characters", set("name", strings.Repeat("é", 60))},
		{"a footer slot of 120 characters", set("footer.slots", []string{strings.Repeat("é", 120), "", ""})},
		{"a strapline of 120 characters", set("brand.strapline", strings.Repeat("é", 120))},
		{"four contact lines", set("brand.contact", []string{"a", "b", "c", "d"})},
		{"revision 1", set("version", 1)},
		{"the highest revision", set("version", 1_000_000)},
		{"text accent just over 4.5:1, blue", set("accent", "#746cc2")},
		{"text accent just over 4.5:1, green", set("accent", "#148a03")},
		{"graphics accent just over 3:1, blue", both(set("headings", "rule"), set("cover.style", "framed"), set("accent", "#349be8"))},
		{"graphics accent just over 3:1, green", both(set("headings", "rule"), set("cover.style", "framed"), set("accent", "#2aac01"))},
		{"a 3.6:1 accent on a design with no accent text", both(set("headings", "bar"), set("cover.style", "geometric"), set("accent", "#3f8ad8"))},
		{"a 4.54:1 secondary on a split cover", set("secondary", "#767676")},
		{"a 3.03:1 secondary on a framed cover", both(set("cover.style", "framed"), set("secondary", "#949494"))},
		{"no secondary", set("secondary", "")},
		{"a website with a path", set("brand.website", "https://acme.example/reviews")},
		{"every token in a slot", set("header.slots", []string{"{title} {author} {date} {page} {pages} {brand} {section} {confidentiality}", "", ""})},
		{"a custom cover style with none stored", set("cover.style", "custom")},
	} {
		m := mineDoc()
		c.edit(m)
		want, err := reportdesign.Parse(mustJSON(t, m))
		if err != nil {
			t.Fatalf("%s: the fixture is not a valid design: %v", c.name, err)
		}
		var rec designRecord
		env.doJSON(sess, http.MethodPut, minePath, map[string]any{"design": m}, &rec, http.StatusOK)
		if !bytes.Equal(parseDesign(t, rec.Design).Canonical(), want.Canonical()) {
			t.Errorf("%s: answered %s", c.name, rec.Design)
		}
		env.doJSON(sess, http.MethodGet, minePath, nil, &rec, http.StatusOK)
		if !bytes.Equal(parseDesign(t, rec.Design).Canonical(), want.Canonical()) {
			t.Errorf("%s: read back %s", c.name, rec.Design)
		}
	}
	env.doJSON(sess, http.MethodPut, minePath, map[string]any{"design": json.RawMessage(mine.Canonical())}, nil, http.StatusOK)

	// Refusals name the field and say why, and the saved design stands, on
	// an update and on a create alike.
	const (
		colourMsg = "must be a colour #rrggbb in lower-case hex"
		oneLine   = "must be one line of plain text (no control, line-break, bidirectional formatting or other invisible format characters)"
		blankMsg  = "must not be empty or only spaces"
		versions  = "must be a whole number from 1 to 1000000"
	)
	rows := []struct {
		name  string
		edit  func(m map[string]any)
		field string
		// message is the refusal's exact message; has, when message is
		// empty, a part of it (the contrast refusals print a ratio and the
		// nearest shade that passes).
		message string
		has     string
	}{
		{"bad colour", set("accent", "#FFF"), "design.accent", colourMsg, ""},
		{"low contrast on text", set("accent", "#7fb3d5"), "design.accent", "", "#7fb3d5 reaches 2.26:1 on white, and an accent that colours text needs 4.5:1; the nearest shade that does is #387caa"},
		{"low secondary on a split cover", set("secondary", "#777777"), "design.secondary", "", "#777777 reaches 4.48:1 on white, and a secondary that colours text needs 4.5:1; the nearest shade that does is "},
		{"low secondary on graphics", both(set("cover.style", "framed"), set("secondary", "#959595")), "design.secondary", "", "a secondary that colours only graphics needs 3.0:1"},
		{"a secondary that is not a colour", set("secondary", "gold"), "design.secondary", "must be a colour #rrggbb in lower-case hex, or empty for none", ""},
		{"unknown font", set("fonts.body", "Papyrus"), "design.fonts.body", "must name a family of the report designs' list", ""},
		{"mono body", set("fonts.body", "IBM Plex Mono"), "design.fonts.body", "", "IBM Plex Mono cannot set body text (it is a mono or a headings-only face); choose one of Inter, "},
		{"unknown style", set("titleBlock", "banner"), "design.titleBlock", "must be one of band, bar, ruled, none", ""},
		{"long slot", set("footer.slots", []string{"", strings.Repeat("x", 121), ""}), "design.footer.slots.1", "is 121 characters, over the limit of 120", ""},
		{"two-line slot", set("header.slots", []string{"a\nb", "", ""}), "design.header.slots.0", oneLine, ""},
		{"two slots", set("header.slots", []string{"a", "b"}), "design.header.slots", "must be 3 texts: left, centre, right", ""},
		{"unknown header style", set("header.style", "banner"), "design.header.style", "must be one of none, rule, brandLine, titleAndPage, logoLeft", ""},
		{"unknown cover style", set("cover.style", "hero"), "design.cover.style", "must be one of band, split, geometric, largeType, framed, plate, custom", ""},
		{"a cover fact twice", set("cover.shows", []string{"title", "title"}), "design.cover.shows.1", "names a fact the cover already shows", ""},
		{"unknown cover when", set("cover.when", "sometimes"), "design.cover.when", "must be one of long, always, never", ""},
		{"five contact lines", set("brand.contact", []string{"a", "b", "c", "d", "e"}), "design.brand.contact", "is 5 lines, over the limit of 4", ""},
		{"an empty contact line", set("brand.contact", []string{""}), "design.brand.contact.0", blankMsg, ""},
		{"an http website", set("brand.website", "http://acme.example"), "design.brand.website", "", "must be a host name such as example.com, or an https address"},
		{"a website with a query", set("brand.website", "acme.example/?q=1"), "design.brand.website", "", "must be a host name"},
		{"a long confidentiality line", set("brand.confidentiality", strings.Repeat("c", 121)), "design.brand.confidentiality", "is 121 characters, over the limit of 120", ""},
		{"unknown heading scale", set("headingScale", "huge"), "design.headingScale", "must be one of compact, regular, generous", ""},
		{"unknown margins", set("margins", "tight"), "design.margins", "must be one of narrow, regular, wide", ""},
		{"unknown key", set("watermark", "x.png"), "design", `unknown key "watermark"`, ""},
		{"version 2's footer text", set("footer.text", "Acme"), "design", `unknown key "text"`, ""},
		// Images are pixels, never URLs.
		{"a logo by URL", set("logo", "https://x.example/logo.png"), "design.logo", "must be an object", ""},
		{"a logo's URL", set("logo", map[string]any{"png": "https://x.example/logo.png"}), "design.logo.png", "must be a PNG in standard base64", ""},
		{"a cover image's URL", set("coverImage", map[string]any{"jpeg": "https://x.example/cover.jpg"}), "design.coverImage", "must be a PNG or a JPEG in standard base64", ""},
		{"a custom cover by file", set("customCover", "cover.typ"), "design.customCover", "must be an object", ""},
		{"a custom cover with no source", set("customCover", map[string]any{"images": []any{}}), "design.customCover.source", "is required", ""},
		{"a custom cover source over 32 KiB", set("customCover", map[string]any{"source": strings.Repeat("x", reportdesign.MaxCoverSourceBytes+1), "images": []any{}}), "design.customCover.source", "is 32769 bytes, over the limit of 32768", ""},
		{"missing field", drop("quotes"), "design.quotes", "is required", ""},
		{"theme document 1", set("agentryTheme", 1), "design.agentryTheme", "must be 3; an earlier theme document is not read", ""},
		{"theme document 2", set("agentryTheme", 2), "design.agentryTheme", "must be 3; an earlier theme document is not read", ""},
		{"old name", set("basedOn", "formal"), "design.basedOn", "must be one of plain, classic, modern, editorial, technical, boardroom, studio, field, civic, lumen", ""},
		{"empty name", set("name", ""), "design.name", blankMsg, ""},
		{"name of 61 characters", set("name", strings.Repeat("é", 61)), "design.name", "is 61 characters, over the limit of 60", ""},
		{"revision 0", set("version", 0), "design.version", versions, ""},
		{"unknown paper", set("paper", "legal"), "design.paper", "must be one of a4, letter", ""},
		{"text accent just under 4.5:1", set("accent", "#4d70dc"), "design.accent", "", "#4d70dc reaches 4.49:1 on white, and an accent that colours text needs 4.5:1; the nearest shade that does is "},
		{"graphics accent just under 3:1", both(set("headings", "rule"), set("cover.style", "framed"), set("accent", "#7092eb")), "design.accent", "", "#7092eb reaches 2.99:1 on white, and an accent that colours only graphics needs 3.0:1; the nearest shade that does is "},
		// A 3.6:1 accent is enough for graphics and not for text: each way
		// the accent reaches text refuses it, the cover styles included.
		{"a band title sets text in the accent", both(set("titleBlock", "band"), set("headings", "rule"), set("cover.style", "framed"), set("accent", "#3f8ad8")), "design.accent", "", "#3f8ad8 reaches 3.60:1 on white, and an accent that colours text needs 4.5:1; the nearest shade that does is #2978cb"},
		{"a band cover sets text in the accent", both(set("headings", "rule"), set("cover.style", "band"), set("accent", "#3f8ad8")), "design.accent", "", "an accent that colours text needs 4.5:1"},
		{"a largeType cover sets text in the accent", both(set("headings", "rule"), set("cover.style", "largeType"), set("accent", "#3f8ad8")), "design.accent", "", "an accent that colours text needs 4.5:1"},
		{"a plate cover sets text in the accent", both(set("headings", "rule"), set("cover.style", "plate"), set("accent", "#3f8ad8")), "design.accent", "", "an accent that colours text needs 4.5:1"},
		{"a split cover with no secondary sets text in the accent", both(set("headings", "rule"), set("secondary", ""), set("accent", "#3f8ad8")), "design.accent", "", "an accent that colours text needs 4.5:1"},
		{"a tab in a slot", set("footer.slots", []string{"a\tb", "", ""}), "design.footer.slots.0", oneLine, ""},
		{"a bidirectional override in the brand name", set("brand.name", "a\u202eb"), "design.brand.name", oneLine, ""},
		{"a zero-width space in the strapline", set("brand.strapline", "a\u200bb"), "design.brand.strapline", oneLine, ""},
		{"accent as a number", set("accent", 5), "design.accent", "must be a string", ""},
		{"slots as a string", set("header.slots", "{title}"), "design.header.slots", "must be an array", ""},
	}
	for _, c := range rows {
		m := mineDoc()
		c.edit(m)
		for _, method := range []struct {
			name, path string
		}{{http.MethodPut, minePath}, {http.MethodPost, designsPath}} {
			var p designProblem
			env.doJSON(sess, method.name, method.path, map[string]any{"design": m}, &p, http.StatusUnprocessableEntity)
			if len(p.Errors) != 1 || p.Errors[0].Field != c.field {
				t.Errorf("%s (%s): refused with %+v, want field %s", c.name, method.name, p.Errors, c.field)
				continue
			}
			if got := p.Errors[0].Message; (c.message != "" && got != c.message) || !strings.Contains(got, c.has) {
				t.Errorf("%s (%s): refused with %q, want %q%s", c.name, method.name, got, c.message, c.has)
			}
			if p.Detail != "The report design is not valid." {
				t.Errorf("%s: the problem says %q", c.name, p.Detail)
			}
		}
	}
	// A version-2 document, as the earlier clients sent it, is refused by
	// its version with no mapping.
	v2, err := os.ReadFile("../../pkg/reportdesign/testdata/v2/modern.json")
	if err != nil {
		t.Fatal(err)
	}
	p = designProblem{}
	env.doJSON(sess, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(v2)}, &p, http.StatusUnprocessableEntity)
	if len(p.Errors) != 1 || p.Errors[0].Field != "design.agentryTheme" {
		t.Errorf("a version-2 document: %+v", p.Errors)
	}
	// The body goes out raw where the document's own bytes matter.
	putRaw := func(body []byte) (int, designProblem) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, env.srv.URL+minePath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		env.authenticate(req, sess)
		res, err := env.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var p designProblem
		_ = json.NewDecoder(res.Body).Decode(&p)
		return res.StatusCode, p
	}
	core := bytes.TrimRight(mine.Canonical(), "\n")
	padded := func(total int) []byte {
		return []byte(`{"design": {` + strings.Repeat(" ", total-len(core)) + string(core[1:]) + `}`)
	}
	// Whitespace as sent does not count against the document's cap, which
	// is on its canonical form without its images: a padded document is
	// taken, and a body past the most a document may be with its images is
	// refused before it is read.
	if st, p := putRaw(padded(reportdesign.MaxDocumentBytes * 4)); st != http.StatusOK {
		t.Fatalf("a padded design answered %d %+v", st, p)
	}
	hugeDoc := padded(reportdesign.MaxDocumentWithAssets + 1)
	if st, p := putRaw(hugeDoc); st != http.StatusUnprocessableEntity || len(p.Errors) != 1 || p.Errors[0].Field != "design" || !strings.Contains(p.Errors[0].Message, "bytes a document may be with its images and custom cover") {
		t.Errorf("a %d-byte design answered %d %+v", len(hugeDoc), st, p.Errors)
	}
	// A body past what the route reads at all is refused as a bad request.
	if st, _ := putRaw(padded(reportdesign.MaxDocumentWithAssets + 1<<12)); st != http.StatusBadRequest {
		t.Errorf("a body past the route's bound answered %d", st)
	}
	// A document that is not UTF-8 is refused whole, not repaired.
	badUTF8 := `{"design": ` + strings.Replace(string(core), "Acme review", "Acme \xff review", 1) + `}`
	if st, p := putRaw([]byte(badUTF8)); st != http.StatusUnprocessableEntity || len(p.Errors) != 1 || p.Errors[0].Field != "design" || p.Errors[0].Message != "the document is not UTF-8" {
		t.Errorf("a design with a byte that is not UTF-8 answered %d %+v", st, p.Errors)
	}
	// The images' fields do not count toward the cap.
	bigLogo := base64.StdEncoding.EncodeToString(noisePNG(t, 200, 200))
	if len(bigLogo) <= reportdesign.MaxDocumentBytes {
		t.Fatalf("the logo is %d bytes, not over the document bound", len(bigLogo))
	}
	withLogo := mineDoc()
	withLogo["logo"] = map[string]any{"png": bigLogo}
	var rec designRecord
	env.doJSON(sess, http.MethodPut, minePath+"?include=assets", map[string]any{"design": withLogo}, &rec, http.StatusOK)
	if d := parseDesign(t, rec.Design); d.Logo == (reportdesign.Logo{}) || !rec.HasLogo {
		t.Fatalf("a design with a large logo answered %+v", rec)
	}
	env.doJSON(sess, http.MethodDelete, minePath+"/logo", nil, nil, http.StatusOK)
	env.doJSON(sess, http.MethodPut, minePath, map[string]any{"design": "plain"}, nil, http.StatusUnprocessableEntity)
	env.doJSON(sess, http.MethodPut, minePath, map[string]any{}, nil, http.StatusUnprocessableEntity)
	// A theme is not a field of the body.
	env.doJSON(sess, http.MethodPut, minePath, map[string]any{"theme": "formal"}, nil, http.StatusBadRequest)
	env.doJSON(sess, http.MethodGet, minePath, nil, &rec, http.StatusOK)
	if !bytes.Equal(parseDesign(t, rec.Design).Canonical(), mine.Canonical()) {
		t.Fatalf("a refused PUT changed the design: %s", rec.Design)
	}
	env.doJSON(sess, http.MethodGet, minePath+"?include=watermark", nil, nil, http.StatusBadRequest)

	// The other account reads its own (none) and cannot see or change this
	// one's: the routes have no account in their path, so the only account
	// they reach is the caller's.
	list = designList{}
	env.doJSON(otherSess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 0 {
		t.Fatalf("another account reads designs it never made: %+v", list)
	}
	env.doJSON(otherSess, http.MethodGet, minePath, nil, nil, http.StatusNotFound)
	env.doJSON(otherSess, http.MethodPut, minePath, map[string]any{"design": json.RawMessage(doc)}, nil, http.StatusNotFound)
	env.doJSON(otherSess, http.MethodDelete, minePath, nil, nil, http.StatusNotFound)
	env.doJSON(otherSess, http.MethodPut, designsPath+"/default", map[string]any{"id": ids["technical"]}, nil, http.StatusNotFound)
	classic, _ := reportdesign.BuiltinDocument("classic")
	var theirs designRecord
	env.doJSON(otherSess, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(classic), "default": true}, &theirs, http.StatusCreated)
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 9 || list.Default == nil || *list.Default != ids["technical"] {
		t.Fatalf("another account's create reached this one: %+v", list)
	}
	env.doJSON(sess, http.MethodGet, designsPath+"/"+theirs.ID.String(), nil, nil, http.StatusNotFound)

	// A user:profile token reads and writes it, as the CLI's sign-in grant
	// does; a token without the scope does not; nobody without a credential.
	_, profilePAT := env.mintPAT(sess, "report-profile", "user:profile")
	env.doJSON(caller{name: "pat", pat: profilePAT}, http.MethodGet, minePath, nil, &rec, http.StatusOK)
	if !bytes.Equal(parseDesign(t, rec.Design).Canonical(), mine.Canonical()) {
		t.Fatalf("a user:profile token read %s", rec.Design)
	}
	list = designList{}
	env.doJSON(caller{name: "pat", pat: profilePAT}, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	_, agentPAT := env.mintPAT(sess, "report-agent", "agent:read")
	for _, c := range []struct {
		who  caller
		want int
	}{{caller{name: "pat", pat: agentPAT}, http.StatusForbidden}, {anonymous, http.StatusUnauthorized}} {
		env.doJSON(c.who, http.MethodGet, designsPath, nil, nil, c.want)
		env.doJSON(c.who, http.MethodGet, minePath, nil, nil, c.want)
		env.doJSON(c.who, http.MethodPost, designsPath, map[string]any{"design": json.RawMessage(classic)}, nil, c.want)
		env.doJSON(c.who, http.MethodPut, minePath, map[string]any{"design": json.RawMessage(classic)}, nil, c.want)
		env.doJSON(c.who, http.MethodDelete, minePath, nil, nil, c.want)
		env.doJSON(c.who, http.MethodPut, designsPath+"/default", map[string]any{}, nil, c.want)
	}
	env.doJSON(sess, http.MethodGet, minePath, nil, &rec, http.StatusOK)
	if !bytes.Equal(parseDesign(t, rec.Design).Canonical(), mine.Canonical()) {
		t.Fatalf("a refused write changed the design: %s", rec.Design)
	}
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 9 || *list.Default != ids["technical"] {
		t.Fatalf("a refused write changed the library: %+v", list)
	}

	// A stored document that no longer validates (a rule tightened since it
	// was saved) is still listed by what its JSON says and still counts; it
	// reads as 404 by id and the default reads as none through the seam.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE user_report_designs SET document = '{"agentryTheme":1,"name":"Old","basedOn":"plain","version":7}'::jsonb WHERE id = $1`, ids["plain"]); err != nil {
		t.Fatal(err)
	}
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 9 || list.Designs[0].Name != "Old" || list.Designs[0].Version != 7 {
		t.Fatalf("a stored design that no longer validates is listed as %+v", list.Designs[0])
	}
	env.doJSON(sess, http.MethodGet, designsPath+"/"+ids["plain"].String(), nil, nil, http.StatusInternalServerError)
	env.doJSON(sess, http.MethodDelete, designsPath+"/"+ids["plain"].String(), nil, nil, http.StatusNoContent)

	// Clearing the account's data removes the library; the other account's
	// stands.
	env.doJSON(sess, http.MethodPost, "/api/v1/user/clear-data", nil, nil, http.StatusNoContent)
	list = designList{}
	env.doJSON(sess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 0 || list.Default != nil {
		t.Fatalf("the library after clearing the account's data: %+v", list)
	}
	list = designList{}
	env.doJSON(otherSess, http.MethodGet, designsPath, nil, &list, http.StatusOK)
	if len(list.Designs) != 1 || list.Default == nil || *list.Default != theirs.ID {
		t.Fatalf("clearing one account's data changed another's library: %+v", list)
	}
}

// mustJSON is v as JSON.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The openapi's ReportDesign is pkg/reportdesign's schema: the same
// properties, required lists, enums, bounds and pattern, so the site's
// editor, which reads the openapi, cannot offer what the core refuses. The
// openapi's own annotations (descriptions, x-enum-varnames) and the JSON
// Schema's header are set aside.
func TestOpenAPIReportDesignIsTheCoreSchema(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	fromSpec, ok := spec.Components.Schemas["ReportDesign"]
	if !ok {
		t.Fatal("the openapi has no ReportDesign")
	}
	var fromCore map[string]any
	if err := json.Unmarshal(reportdesign.Schema(), &fromCore); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"$schema", "$id", "title"} {
		delete(fromCore, k)
	}
	norm := func(v any) any {
		b, err := json.Marshal(strip(v))
		if err != nil {
			t.Fatal(err)
		}
		var out any
		_ = json.Unmarshal(b, &out)
		return out
	}
	if a, b := norm(fromSpec), norm(fromCore); !reflect.DeepEqual(a, b) {
		as, _ := json.MarshalIndent(a, "", " ")
		bs, _ := json.MarshalIndent(b, "", " ")
		t.Fatalf("the openapi's ReportDesign differs from pkg/reportdesign's schema:\nopenapi %s\ncore %s", as, bs)
	}
	// The custom cover's own schema, which its PUT takes, is the design's.
	custom, ok := spec.Components.Schemas["ReportDesignCustomCover"]
	if !ok {
		t.Fatal("the openapi has no ReportDesignCustomCover")
	}
	if a, b := norm(custom), norm(fromCore["properties"].(map[string]any)["customCover"]); !reflect.DeepEqual(a, b) {
		as, _ := json.MarshalIndent(a, "", " ")
		bs, _ := json.MarshalIndent(b, "", " ")
		t.Fatalf("the openapi's ReportDesignCustomCover differs from the design's customCover:\nopenapi %s\ncore %s", as, bs)
	}
}

// strip drops the openapi-only annotations at every level.
func strip(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if k == "description" || strings.HasPrefix(k, "x-") {
				continue
			}
			out[k] = strip(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = strip(e)
		}
		return out
	}
	return v
}

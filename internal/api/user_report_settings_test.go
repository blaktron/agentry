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

// The report design: an account that never chose
// reads back with no design; each built-in and
// an edited design round-trip as their canonical documents; a design that
// breaks a rule is refused 422 naming design.<path> and saying why, and the
// saved one stands; a design at each bound is taken; a theme field is
// refused; a body with no design clears the choice; a stored design that no
// longer validates reads as never chosen; and each account reads only its
// own, a user:profile token included, since the CLI reads it that way.
func TestReportSettingsRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	u := env.register("report-user")
	env.verifyEmail(u)
	sess := env.login(u)
	other := env.register("report-other")
	env.verifyEmail(other)
	otherSess := env.login(other)

	type settings struct {
		Design json.RawMessage `json:"design"`
	}
	const path = "/api/v1/user/report-settings"
	var got settings
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Design != nil {
		t.Fatalf("never chosen must read back with no design, got %s", got.Design)
	}

	// Each built-in round-trips: the answer, and a later read, are its
	// canonical document byte for byte.
	canonical := func(raw json.RawMessage) []byte {
		t.Helper()
		d, err := reportdesign.Parse(raw)
		if err != nil {
			t.Fatalf("the server answered a design that does not parse: %v (%s)", err, raw)
		}
		return d.Canonical()
	}
	for _, id := range reportdesign.BuiltinIDs() {
		doc, _ := reportdesign.BuiltinDocument(id)
		got = settings{}
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(doc)}, &got, http.StatusOK)
		if !bytes.Equal(canonical(got.Design), doc) {
			t.Fatalf("PUT %s answered %s", id, got.Design)
		}
		got = settings{}
		env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
		if !bytes.Equal(canonical(got.Design), doc) {
			t.Fatalf("GET after PUT %s read %s", id, got.Design)
		}
	}

	// An edited design: the person's name, their accent, US Letter and a
	// footer line, sent compact and in another key order, is stored and
	// answered in its canonical form.
	mine, _ := reportdesign.Builtin("technical")
	mine.Name, mine.Accent, mine.Paper, mine.Footer.Text = "Acme review", "#0b5c55", "letter", "Acme Ltd — confidential"
	var loose map[string]any
	_ = json.Unmarshal(mine.Canonical(), &loose)
	got = settings{}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": loose}, &got, http.StatusOK)
	if !bytes.Equal(canonical(got.Design), mine.Canonical()) {
		t.Fatalf("the edited design was answered as %s", got.Design)
	}
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if !bytes.Equal(canonical(got.Design), mine.Canonical()) {
		t.Fatalf("the edited design read back %s", got.Design)
	}

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

	// Accepted at each bound: the longest name and footer line (counted in
	// characters, not bytes), the lowest and highest revision, an accent
	// just over the contrast its use needs, and one the graphics-only
	// designs take and the designs that set text in the accent do not.
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"a name of 60 characters", set("name", strings.Repeat("\u00e9", 60))},
		{"a footer line of 120 characters", set("footer.text", strings.Repeat("\u00e9", 120))},
		{"revision 1", set("version", 1)},
		{"the highest revision", set("version", 1_000_000)},
		{"text accent just over 4.5:1, blue", set("accent", "#746cc2")},
		{"text accent just over 4.5:1, green", set("accent", "#148a03")},
		{"graphics accent just over 3:1, blue", both(set("headings", "rule"), set("accent", "#349be8"))},
		{"graphics accent just over 3:1, green", both(set("headings", "rule"), set("accent", "#2aac01"))},
		{"a 3.6:1 accent on a design with no accent text", both(set("headings", "bar"), set("accent", "#3f8ad8"))},
	} {
		m := map[string]any{}
		_ = json.Unmarshal(mine.Canonical(), &m)
		c.edit(m)
		want, err := reportdesign.Parse(mustJSON(t, m))
		if err != nil {
			t.Fatalf("%s: the fixture is not a valid design: %v", c.name, err)
		}
		got = settings{}
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": m}, &got, http.StatusOK)
		if !bytes.Equal(canonical(got.Design), want.Canonical()) {
			t.Errorf("%s: answered %s", c.name, got.Design)
		}
		got = settings{}
		env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
		if !bytes.Equal(canonical(got.Design), want.Canonical()) {
			t.Errorf("%s: read back %s", c.name, got.Design)
		}
	}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(mine.Canonical())}, nil, http.StatusOK)

	// Refusals name the field and say why, and the saved design stands.
	type problem struct {
		Detail string `json:"detail"`
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
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
		{"bad colour", func(m map[string]any) { m["accent"] = "#FFF" }, "design.accent", colourMsg, ""},
		{"low contrast on text", func(m map[string]any) { m["accent"] = "#7fb3d5" }, "design.accent", "", "#7fb3d5 reaches 2.26:1 on white, and an accent that colours text needs 4.5:1; the nearest shade that does is #387caa"},
		{"unknown font", func(m map[string]any) { m["fonts"].(map[string]any)["body"] = "Papyrus" }, "design.fonts.body", "must name a family of the report designs' list", ""},
		{"mono body", func(m map[string]any) { m["fonts"].(map[string]any)["body"] = "IBM Plex Mono" }, "design.fonts.body", "", "IBM Plex Mono cannot set body text (it is a mono or a headings-only face); choose one of Inter, "},
		{"unknown style", func(m map[string]any) { m["titleBlock"] = "banner" }, "design.titleBlock", "must be one of band, bar, ruled, none", ""},
		{"long footer", func(m map[string]any) {
			m["footer"].(map[string]any)["text"] = strings.Repeat("x", 121)
		}, "design.footer.text", "is 121 characters, over the limit of 120", ""},
		{"two-line footer", func(m map[string]any) { m["footer"].(map[string]any)["text"] = "a\nb" }, "design.footer.text", oneLine, ""},
		{"unknown key", func(m map[string]any) { m["watermark"] = "x.png" }, "design", `unknown key "watermark"`, ""},
		// A logo is pixels, never a URL.
		{"a logo by URL", func(m map[string]any) { m["logo"] = "https://x.example/logo.png" }, "design.logo", "must be an object", ""},
		{"a logo's URL", func(m map[string]any) { m["logo"] = map[string]any{"png": "https://x.example/logo.png"} }, "design.logo.png", "must be a PNG in standard base64", ""},
		{"missing field", func(m map[string]any) { delete(m, "quotes") }, "design.quotes", "is required", ""},
		{"theme document 1", func(m map[string]any) { m["agentryTheme"] = 1 }, "design.agentryTheme", "must be 2; an earlier theme document is not read", ""},
		{"old name", func(m map[string]any) { m["basedOn"] = "formal" }, "design.basedOn", "must be one of plain, classic, modern, editorial, technical", ""},
		// The rest of the rules, one row each.
		{"theme document 3", set("agentryTheme", 3), "design.agentryTheme", "must be 2; an earlier theme document is not read", ""},
		{"empty name", set("name", ""), "design.name", blankMsg, ""},
		{"spaces-only name", set("name", "   "), "design.name", blankMsg, ""},
		{"name of 61 characters", set("name", strings.Repeat("\u00e9", 61)), "design.name", "is 61 characters, over the limit of 60", ""},
		{"revision 0", set("version", 0), "design.version", versions, ""},
		{"revision past the highest", set("version", 1_000_001), "design.version", versions, ""},
		{"unknown paper", set("paper", "legal"), "design.paper", "must be one of a4, letter", ""},
		{"unknown heading style", set("headings", "fancy"), "design.headings", "must be one of rule, bar, smallcaps, numbered, plain", ""},
		{"unknown quote style", set("quotes", "pull"), "design.quotes", "must be one of callout, plain", ""},
		{"unknown page numbers", set("footer.pageNumbers", "roman"), "design.footer.pageNumbers", "must be one of none, n, nOfN", ""},
		{"unknown heading font", set("fonts.headings", "Papyrus"), "design.fonts.headings", "must name a family of the report designs' list", ""},
		{"unknown code font", set("fonts.code", "Papyrus"), "design.fonts.code", "must name a family of the report designs' list", ""},
		{"headings-only face as body", set("fonts.body", "Montserrat"), "design.fonts.body", "", "Montserrat cannot set body text (it is a mono or a headings-only face); choose one of Inter, "},
		{"sans face as code", set("fonts.code", "Inter"), "design.fonts.code", "Inter cannot set code (it is not a mono face); choose one of IBM Plex Mono, JetBrains Mono, Source Code Pro", ""},
		{"upper-case colour", set("accent", "#0B5C55"), "design.accent", colourMsg, ""},
		{"five-digit colour", set("accent", "#0b5c5"), "design.accent", colourMsg, ""},
		{"colour with no hash", set("accent", "0b5c55"), "design.accent", colourMsg, ""},
		{"eight-digit colour", set("accent", "#0b5c55ff"), "design.accent", colourMsg, ""},
		{"three-digit colour", set("accent", "#fff"), "design.accent", colourMsg, ""},
		{"text accent just under 4.5:1, blue", set("accent", "#4d70dc"), "design.accent", "", "#4d70dc reaches 4.49:1 on white, and an accent that colours text needs 4.5:1; the nearest shade that does is "},
		{"text accent just under 4.5:1, green", set("accent", "#23891e"), "design.accent", "", "#23891e reaches 4.49:1 on white, and an accent that colours text needs 4.5:1; the nearest shade that does is "},
		{"graphics accent just under 3:1, blue", both(set("headings", "rule"), set("accent", "#7092eb")), "design.accent", "", "#7092eb reaches 2.99:1 on white, and an accent that colours only graphics needs 3.0:1; the nearest shade that does is "},
		{"graphics accent just under 3:1, green", both(set("headings", "rule"), set("accent", "#29ac0b")), "design.accent", "", "#29ac0b reaches 2.99:1 on white, and an accent that colours only graphics needs 3.0:1; the nearest shade that does is "},
		// A 3.6:1 accent is enough for graphics and not for text: each way
		// the accent reaches text refuses it.
		{"a band title sets text in the accent", both(set("titleBlock", "band"), set("headings", "rule"), set("accent", "#3f8ad8")), "design.accent", "", "#3f8ad8 reaches 3.60:1 on white, and an accent that colours text needs 4.5:1; the nearest shade that does is #2978cb"},
		{"small-caps headings set text in the accent", both(set("headings", "smallcaps"), set("accent", "#3f8ad8")), "design.accent", "", "an accent that colours text needs 4.5:1"},
		{"numbered headings set text in the accent", set("accent", "#3f8ad8"), "design.accent", "", "an accent that colours text needs 4.5:1"},
		{"spaces-only footer", set("footer.text", "   "), "design.footer.text", blankMsg, ""},
		{"a tab in the footer", set("footer.text", "a\tb"), "design.footer.text", oneLine, ""},
		{"a C1 control in the footer", set("footer.text", "a\u0085b"), "design.footer.text", oneLine, ""},
		{"a bidirectional override in the footer", set("footer.text", "a\u202eb"), "design.footer.text", oneLine, ""},
		{"a zero-width space in the footer", set("footer.text", "a\u200bb"), "design.footer.text", oneLine, ""},
		{"a soft hyphen in the footer", set("footer.text", "a\u00adb"), "design.footer.text", oneLine, ""},
		{"a tag character in the footer", set("footer.text", "a\U000e0041b"), "design.footer.text", oneLine, ""},
		{"a line separator in the footer", set("footer.text", "a\u2028b"), "design.footer.text", oneLine, ""},
		{"a paragraph separator in the footer", set("footer.text", "a\u2029b"), "design.footer.text", oneLine, ""},
		// A value of the wrong JSON type names its field.
		{"accent as a number", set("accent", 5), "design.accent", "must be a string", ""},
		{"revision as a string", set("version", "1"), "design.version", "must be a number", ""},
		{"tinted as a string", set("tables.tinted", "yes"), "design.tables.tinted", "must be a boolean", ""},
		{"fonts as a string", set("fonts", "Inter"), "design.fonts", "must be an object", ""},
	}
	// Every field of the document is required, the nested ones too.
	for _, p := range []string{
		"agentryTheme", "name", "basedOn", "version", "paper", "fonts", "fonts.headings", "fonts.body", "fonts.code",
		"accent", "titleBlock", "headings", "tables", "tables.tinted", "tables.banded", "quotes", "footer",
		"footer.pageNumbers", "footer.text",
	} {
		rows = append(rows, struct {
			name    string
			edit    func(m map[string]any)
			field   string
			message string
			has     string
		}{"missing " + p, drop(p), "design." + p, "is required", ""})
	}
	for _, c := range rows {
		m := map[string]any{}
		_ = json.Unmarshal(mine.Canonical(), &m)
		c.edit(m)
		var p problem
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": m}, &p, http.StatusUnprocessableEntity)
		if len(p.Errors) != 1 || p.Errors[0].Field != c.field {
			t.Errorf("%s: refused with %+v, want field %s", c.name, p.Errors, c.field)
			continue
		}
		if got := p.Errors[0].Message; (c.message != "" && got != c.message) || !strings.Contains(got, c.has) {
			t.Errorf("%s: refused with %q, want %q%s", c.name, got, c.message, c.has)
		}
		if p.Detail != "The report design is not valid." {
			t.Errorf("%s: the problem says %q", c.name, p.Detail)
		}
	}
	// The body goes out raw where the document's own bytes matter: whitespace
	// inside the document counts to its 16 KB, and doJSON would compact it.
	putRaw := func(body []byte) (int, problem) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, env.srv.URL+path, bytes.NewReader(body))
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
		var p problem
		_ = json.NewDecoder(res.Body).Decode(&p)
		return res.StatusCode, p
	}
	// padded is mine as a document of exactly total bytes, the padding
	// being whitespace after its opening brace.
	core := bytes.TrimRight(mine.Canonical(), "\n")
	padded := func(total int) []byte {
		return []byte(`{"design": {` + strings.Repeat(" ", total-len(core)) + string(core[1:]) + `}`)
	}
	// Over 16 KB as sent: the document at 16 KB is taken, one byte more is
	// refused.
	if st, p := putRaw(padded(reportdesign.MaxDocumentBytes)); st != http.StatusOK {
		t.Fatalf("a %d-byte design answered %d %+v", reportdesign.MaxDocumentBytes, st, p)
	}
	over := padded(reportdesign.MaxDocumentBytes + 1)
	st, p := putRaw(over)
	if st != http.StatusUnprocessableEntity {
		t.Fatalf("a %d-byte design answered %d", len(over), st)
	}
	if len(p.Errors) != 1 || p.Errors[0].Field != "design" || !strings.Contains(p.Errors[0].Message, "the document is 16385 bytes without its logo, over the 16384-byte limit") {
		t.Errorf("an over-size design was refused with %+v", p.Errors)
	}
	// A body past the most a document may be with the largest logo is
	// refused before it is read.
	hugeDoc := padded(reportdesign.MaxDocumentBytes * 50)
	if st, p := putRaw(hugeDoc); st != http.StatusUnprocessableEntity || len(p.Errors) != 1 || p.Errors[0].Field != "design" || !strings.Contains(p.Errors[0].Message, "bytes a document may be with its logo") {
		t.Errorf("a %d-byte design answered %d %+v", len(hugeDoc), st, p.Errors)
	}
	// A document that is not UTF-8 is refused whole, not repaired.
	badUTF8 := `{"design": ` + strings.Replace(string(core), "Acme review", "Acme \xff review", 1) + `}`
	if st, p := putRaw([]byte(badUTF8)); st != http.StatusUnprocessableEntity || len(p.Errors) != 1 || p.Errors[0].Field != "design" || p.Errors[0].Message != "the document is not UTF-8" {
		t.Errorf("a design with a byte that is not UTF-8 answered %d %+v", st, p.Errors)
	}

	// The logo's field does not count to those 16 KB, and the rest of the
	// document still does.
	bigLogo := base64.StdEncoding.EncodeToString(noisePNG(t, 150, 150))
	if len(bigLogo) <= reportdesign.MaxDocumentBytes {
		t.Fatalf("the logo is %d bytes, not over the document bound", len(bigLogo))
	}
	withLogo := map[string]any{}
	_ = json.Unmarshal(mine.Canonical(), &withLogo)
	withLogo["logo"] = map[string]any{"png": bigLogo}
	compact := mustJSON(t, withLogo)
	rest := len(compact) - len(bigLogo)
	paddedLogo := func(total int) []byte {
		return []byte(`{"design": {` + strings.Repeat(" ", total-rest) + string(compact[1:]) + `}`)
	}
	if st, p := putRaw(paddedLogo(reportdesign.MaxDocumentBytes)); st != http.StatusOK {
		t.Fatalf("a %d-byte design with a %d-byte logo answered %d %+v", reportdesign.MaxDocumentBytes, len(bigLogo), st, p)
	}
	if st, p := putRaw(paddedLogo(reportdesign.MaxDocumentBytes + 1)); st != http.StatusUnprocessableEntity || len(p.Errors) != 1 || p.Errors[0].Field != "design" || p.Errors[0].Message != "the document is 16385 bytes without its logo, over the 16384-byte limit" {
		t.Errorf("a design over 16 KB besides its logo answered %d %+v", st, p.Errors)
	}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": "plain"}, nil, http.StatusUnprocessableEntity)
	// A theme is not a field of the body.
	env.doJSON(sess, http.MethodPut, path, map[string]any{"theme": "formal"}, nil, http.StatusBadRequest)
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if !bytes.Equal(canonical(got.Design), mine.Canonical()) {
		t.Fatalf("a refused PUT changed the design: %s", got.Design)
	}

	// The other account reads its own (none) and cannot see or change this
	// one's: the route has no account in its path, so the only account it
	// reaches is the caller's.
	got = settings{}
	env.doJSON(otherSess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Design != nil {
		t.Fatalf("another account reads a design it never chose: %s", got.Design)
	}
	classic, _ := reportdesign.BuiltinDocument("classic")
	env.doJSON(otherSess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic)}, nil, http.StatusOK)
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if !bytes.Equal(canonical(got.Design), mine.Canonical()) {
		t.Fatalf("another account's PUT reached this one: %s", got.Design)
	}

	// A user:profile token reads it, as the CLI's sign-in grant does; a
	// token without the scope does not; nobody reads without a credential.
	_, profilePAT := env.mintPAT(sess, "report-profile", "user:profile")
	got = settings{}
	env.doJSON(caller{name: "pat", pat: profilePAT}, http.MethodGet, path, nil, &got, http.StatusOK)
	if !bytes.Equal(canonical(got.Design), mine.Canonical()) {
		t.Fatalf("a user:profile token read %s", got.Design)
	}
	_, agentPAT := env.mintPAT(sess, "report-agent", "agent:read")
	env.doJSON(caller{name: "pat", pat: agentPAT}, http.MethodGet, path, nil, nil, http.StatusForbidden)
	env.doJSON(anonymous, http.MethodGet, path, nil, nil, http.StatusUnauthorized)
	// Nor does either write: a PUT from a token without the scope or from
	// nobody changes nothing.
	env.doJSON(caller{name: "pat", pat: agentPAT}, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic)}, nil, http.StatusForbidden)
	env.doJSON(anonymous, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic)}, nil, http.StatusUnauthorized)
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if !bytes.Equal(canonical(got.Design), mine.Canonical()) {
		t.Fatalf("a refused write changed the design: %s", got.Design)
	}

	// A body with no design, or a null one, clears the choice back to never
	// chosen.
	for _, body := range []map[string]any{{}, {"design": nil}} {
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic)}, nil, http.StatusOK)
		got = settings{}
		env.doJSON(sess, http.MethodPut, path, body, &got, http.StatusOK)
		if got.Design != nil {
			t.Fatalf("a PUT of %v answered %s", body, got.Design)
		}
		env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
		if got.Design != nil {
			t.Fatalf("the cleared design reads back %s", got.Design)
		}
		// Clearing is the caller's: the other account's design stays.
		got = settings{}
		env.doJSON(otherSess, http.MethodGet, path, nil, &got, http.StatusOK)
		if !bytes.Equal(canonical(got.Design), classic) {
			t.Fatalf("clearing one account's design changed another's: %s", got.Design)
		}
	}

	// A stored design that no longer validates (a rule tightened since it
	// was saved) reads as never chosen, not as an error.
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": json.RawMessage(classic)}, nil, http.StatusOK)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE user_report_settings SET design = '{"agentryTheme":1}'::jsonb WHERE user_id = $1`, uuid.MustParse(env.userID(u))); err != nil {
		t.Fatal(err)
	}
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if got.Design != nil {
		t.Fatalf("a stored design that no longer validates read back %s", got.Design)
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

package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/reportdesign"
)

// The report design (agentry#989, agentry#1024): an account that never chose
// reads back with no design (DEV-227, plan invariant 10); each built-in and
// an edited design round-trip as their canonical documents; a design that
// breaks a rule is refused 422 naming design.<path>, and the saved one
// stands (invariant 3); the old theme names are gone; a body with no design
// clears the choice; and each account reads only its own, a user:profile
// token included, since the CLI reads it that way.
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
	// canonical document byte for byte (invariant 8).
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
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": loose}, &got, http.StatusOK)
	got = settings{}
	env.doJSON(sess, http.MethodGet, path, nil, &got, http.StatusOK)
	if !bytes.Equal(canonical(got.Design), mine.Canonical()) {
		t.Fatalf("the edited design read back %s", got.Design)
	}

	// Refusals name the field, and the saved design stands.
	type problem struct {
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	for _, c := range []struct {
		name  string
		edit  func(m map[string]any)
		field string
	}{
		{"bad colour", func(m map[string]any) { m["accent"] = "#FFF" }, "design.accent"},
		{"low contrast on text", func(m map[string]any) { m["accent"] = "#7fb3d5" }, "design.accent"},
		{"unknown font", func(m map[string]any) { m["fonts"].(map[string]any)["body"] = "Papyrus" }, "design.fonts.body"},
		{"mono body", func(m map[string]any) { m["fonts"].(map[string]any)["body"] = "IBM Plex Mono" }, "design.fonts.body"},
		{"unknown style", func(m map[string]any) { m["titleBlock"] = "banner" }, "design.titleBlock"},
		{"long footer", func(m map[string]any) {
			m["footer"].(map[string]any)["text"] = strings.Repeat("x", 121)
		}, "design.footer.text"},
		{"two-line footer", func(m map[string]any) { m["footer"].(map[string]any)["text"] = "a\nb" }, "design.footer.text"},
		{"unknown key", func(m map[string]any) { m["watermark"] = "x.png" }, "design"},
		// A logo is pixels, never a URL (invariant 12; agentry#1025).
		{"a logo by URL", func(m map[string]any) { m["logo"] = "https://x.example/logo.png" }, "design.logo"},
		{"a logo's URL", func(m map[string]any) { m["logo"] = map[string]any{"png": "https://x.example/logo.png"} }, "design.logo.png"},
		{"missing field", func(m map[string]any) { delete(m, "quotes") }, "design.quotes"},
		{"theme document 1", func(m map[string]any) { m["agentryTheme"] = 1 }, "design.agentryTheme"},
		{"old name", func(m map[string]any) { m["basedOn"] = "formal" }, "design.basedOn"},
	} {
		m := map[string]any{}
		_ = json.Unmarshal(mine.Canonical(), &m)
		c.edit(m)
		var p problem
		env.doJSON(sess, http.MethodPut, path, map[string]any{"design": m}, &p, http.StatusUnprocessableEntity)
		if len(p.Errors) != 1 || p.Errors[0].Field != c.field {
			t.Errorf("%s: refused with %+v, want field %s", c.name, p.Errors, c.field)
		}
	}
	// Over 16 KB as sent: whitespace inside the document counts, so the
	// body goes out raw (doJSON would compact it).
	over := []byte(`{"design": {` + strings.Repeat(" ", reportdesign.MaxDocumentBytes) + string(mine.Canonical()[1:]) + `}`)
	req, err := http.NewRequest(http.MethodPut, env.srv.URL+path, bytes.NewReader(over))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	env.authenticate(req, sess)
	res, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a %d-byte design answered %d", len(over), res.StatusCode)
	}
	env.doJSON(sess, http.MethodPut, path, map[string]any{"design": "plain"}, nil, http.StatusUnprocessableEntity)
	// The old setting is no longer a field of the body (D16, D20).
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
	}
}

// The openapi's ReportDesign is pkg/reportdesign's schema (D22): the same
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

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/pkg/reportdesign"
)

// An organization's house designs through its routes: an admin keeps the
// library, every active member reads it, membership is checked at every
// call, and anyone outside the organization is answered 404.

// orgDesignRecord is a house design as the API answers it.
type orgDesignRecord struct {
	ID             uuid.UUID       `json:"id"`
	Org            string          `json:"org"`
	HasLogo        bool            `json:"hasLogo"`
	HasCoverImage  bool            `json:"hasCoverImage"`
	HasCustomCover bool            `json:"hasCustomCover"`
	Design         json.RawMessage `json:"design"`
}

// orgDesignList is the organization's library as the API answers it.
type orgDesignList struct {
	Org     string `json:"org"`
	Designs []struct {
		ID             uuid.UUID `json:"id"`
		Name           string    `json:"name"`
		BasedOn        string    `json:"basedOn"`
		Version        int       `json:"version"`
		HasLogo        bool      `json:"hasLogo"`
		HasCoverImage  bool      `json:"hasCoverImage"`
		HasCustomCover bool      `json:"hasCustomCover"`
	} `json:"designs"`
}

// designOrg is an organization with an admin and a member, each signed in
// and holding a profile token, the admin an organization token too.
type designOrg struct {
	handle        string
	admin, member designMember
}

type designMember struct {
	handle   string
	sess     caller
	profile  caller // a user:profile token: what the CLI's sign-in carries
	orgAdmin caller // an org:admin token, minted for the admin alone
}

func newDesignMember(env *testEnv, name string) designMember {
	h := env.register(name)
	env.verifyEmail(h)
	sess := env.login(h)
	_, tok := env.mintPAT(sess, "profile", "user:profile")
	return designMember{handle: h, sess: sess, profile: caller{name: name + "-profile", pat: tok}}
}

func newDesignOrg(t *testing.T, env *testEnv, name string) designOrg {
	t.Helper()
	o := designOrg{handle: name + env.sfx, admin: newDesignMember(env, name+"-adm"), member: newDesignMember(env, name+"-mem")}
	env.doJSON(o.admin.sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": o.handle, "displayName": "House Designs"}, nil, http.StatusCreated)
	env.joinOrg(o.admin.sess, o.handle, o.member.handle)
	_, tok := env.mintPAT(o.admin.sess, "admin", "org:admin")
	o.admin.orgAdmin = caller{name: name + "-adm-org", pat: tok}
	return o
}

func (o designOrg) path(p string) string { return "/api/v1/orgs/" + o.handle + "/report-designs" + p }

// houseDesign is a built-in renamed, as the organization's.
func houseDesign(t *testing.T, builtin, name string) reportdesign.Design {
	t.Helper()
	d, ok := reportdesign.Builtin(builtin)
	if !ok {
		t.Fatalf("no built-in %s", builtin)
	}
	d.Name = name
	return d
}

func designBody(d reportdesign.Design) map[string]any {
	return map[string]any{"design": json.RawMessage(d.Canonical())}
}

// putOrgDesignFile uploads body as the one multipart part to an image route
// of one of the organization's designs and returns the status and the body.
func putOrgDesignFile(t *testing.T, env *testEnv, who caller, path string, body []byte) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, _ := mw.CreateFormFile("file", "image.png")
	_, _ = part.Write(body)
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPut, env.srv.URL+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	env.authenticate(req, who)
	res, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var b bytes.Buffer
	_, _ = b.ReadFrom(res.Body)
	return res.StatusCode, b.Bytes()
}

func smallPNG(t *testing.T) []byte {
	t.Helper()
	var pb bytes.Buffer
	if err := png.Encode(&pb, image.NewNRGBA(image.Rect(0, 0, 8, 4))); err != nil {
		t.Fatal(err)
	}
	return pb.Bytes()
}

// orgDesignAuditActions is every action recorded in the organization's
// audit log against the design, oldest first, with what each recorded.
func orgDesignAuditActions(t *testing.T, env *testEnv, org string, design uuid.UUID) []string {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT a.action || ' ' || coalesce(a.detail->>'name', '') || coalesce(' ' || (a.detail->>'image'), '')
		 FROM audit_events a JOIN handles h ON h.id = a.org_id
		 WHERE h.handle = $1 AND a.target_kind = 'report_design' AND a.target_id = $2 ORDER BY a.occurred_at, a.id`, org, design)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// TestHouseDesignsThroughTheAPI: an admin creates, replaces, images and
// deletes the organization's designs and every write is recorded in the
// organization's audit log; every active member reads them, by the session
// and by the profile token a CLI sign-in carries, and an admin's change is
// what the member reads next; a member writes nothing, and an admin's
// profile token writes nothing either; a name is one design's within the
// organization, compared without regard to case; the library holds ten;
// and the answers are the canonical document, the images only on
// include=assets.
func TestHouseDesignsThroughTheAPI(t *testing.T) {
	env := newTestEnv(t)
	o := newDesignOrg(t, env, "hd")

	// Empty, under the organization's handle, for the member and the admin.
	for _, c := range []caller{o.member.sess, o.member.profile, o.admin.sess, o.admin.profile} {
		var list orgDesignList
		env.doJSON(c, http.MethodGet, o.path(""), nil, &list, http.StatusOK)
		if list.Org != o.handle || len(list.Designs) != 0 {
			t.Fatalf("a new organization's library as %s: %+v", c.name, list)
		}
	}

	// The admin creates one; the answer and a later read are its
	// canonical document, under the organization.
	house := houseDesign(t, "technical", "Acme house")
	house.Brand.Name, house.Header = "Acme Ltd", reportdesign.Header{Style: "brandLine", Slots: [3]string{"{brand}", "", "{date}"}}
	var created orgDesignRecord
	env.doJSON(o.admin.orgAdmin, http.MethodPost, o.path(""), designBody(house), &created, http.StatusCreated)
	if created.Org != o.handle || !bytes.Equal(parseDesign(t, created.Design).Canonical(), house.Canonical()) || created.HasLogo || created.HasCoverImage || created.HasCustomCover {
		t.Fatalf("POST answered %+v", created)
	}
	for _, c := range []caller{o.member.sess, o.member.profile, o.admin.sess} {
		var list orgDesignList
		env.doJSON(c, http.MethodGet, o.path(""), nil, &list, http.StatusOK)
		if len(list.Designs) != 1 || list.Designs[0].ID != created.ID || list.Designs[0].Name != "Acme house" || list.Designs[0].BasedOn != "technical" || list.Designs[0].HasLogo {
			t.Fatalf("the library as %s: %+v", c.name, list)
		}
		var got orgDesignRecord
		env.doJSON(c, http.MethodGet, o.path("/"+created.ID.String()), nil, &got, http.StatusOK)
		if got.ID != created.ID || got.Org != o.handle || !bytes.Equal(parseDesign(t, got.Design).Canonical(), house.Canonical()) {
			t.Fatalf("GET as %s read %+v", c.name, got)
		}
	}
	// The session works for the admin's create as well as the token.
	var second orgDesignRecord
	env.doJSON(o.admin.sess, http.MethodPost, o.path(""), designBody(houseDesign(t, "classic", "Letters")), &second, http.StatusCreated)

	// A member writes nothing: 403, since the role is known and too low;
	// an admin's profile token writes nothing either, since the scope is
	// the person's profile, not the organization.
	logo := smallPNG(t)
	for _, c := range []caller{o.member.sess, o.member.profile, o.admin.profile} {
		for _, route := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, o.path(""), designBody(houseDesign(t, "modern", "Late"))},
			{http.MethodPut, o.path("/" + created.ID.String()), designBody(house)},
			{http.MethodDelete, o.path("/" + created.ID.String()), nil},
			{http.MethodDelete, o.path("/" + created.ID.String() + "/logo"), nil},
			{http.MethodDelete, o.path("/" + created.ID.String() + "/cover-image"), nil},
			{http.MethodPut, o.path("/" + created.ID.String() + "/custom-cover"), map[string]any{"source": "#page[]", "images": []any{}}},
			{http.MethodDelete, o.path("/" + created.ID.String() + "/custom-cover"), nil},
		} {
			if res := env.do(c, route.method, route.path, route.body); res.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s as %s: %d, want 403", route.method, route.path, c.name, res.StatusCode)
			}
		}
		for _, route := range []string{"/logo", "/cover-image"} {
			if st, body := putOrgDesignFile(t, env, c, o.path("/"+created.ID.String()+route), logo); st != http.StatusForbidden {
				t.Fatalf("PUT %s as %s: %d %s, want 403", route, c.name, st, body)
			}
		}
	}
	var list orgDesignList
	env.doJSON(o.member.sess, http.MethodGet, o.path(""), nil, &list, http.StatusOK)
	if len(list.Designs) != 2 {
		t.Fatalf("after the refused writes: %+v", list)
	}

	// A name is one design's within the organization, whatever its case:
	// a second create of the name, and a replace that takes another
	// design's name, are 409 and change nothing.
	var p designProblem
	env.doJSON(o.admin.sess, http.MethodPost, o.path(""), designBody(houseDesign(t, "modern", "ACME HOUSE")), &p, http.StatusConflict)
	if !strings.Contains(p.Detail, "design of that name") {
		t.Fatalf("a second of the name: %+v", p)
	}
	env.doJSON(o.admin.sess, http.MethodPut, o.path("/"+second.ID.String()), designBody(houseDesign(t, "classic", "acme house")), &p, http.StatusConflict)
	var got orgDesignRecord
	env.doJSON(o.member.sess, http.MethodGet, o.path("/"+second.ID.String()), nil, &got, http.StatusOK)
	if parseDesign(t, got.Design).Name != "Letters" {
		t.Fatalf("the refused rename took: %s", got.Design)
	}

	// An admin's replace is what a member reads next; the design that
	// breaks a rule is refused 422 naming the field and the saved one
	// stands.
	house.Accent, house.Name = "#0b5c55", "Acme house"
	var updated orgDesignRecord
	env.doJSON(o.admin.sess, http.MethodPut, o.path("/"+created.ID.String()), designBody(house), &updated, http.StatusOK)
	if updated.ID != created.ID || !bytes.Equal(parseDesign(t, updated.Design).Canonical(), house.Canonical()) {
		t.Fatalf("the replace answered %+v", updated)
	}
	env.doJSON(o.member.profile, http.MethodGet, o.path("/"+created.ID.String()), nil, &got, http.StatusOK)
	if parseDesign(t, got.Design).Accent != "#0b5c55" {
		t.Fatalf("the member read the old design: %s", got.Design)
	}
	bad := house
	bad.Accent = "#7fb3d5"
	env.doJSON(o.admin.sess, http.MethodPut, o.path("/"+created.ID.String()), designBody(bad), &p, http.StatusUnprocessableEntity)
	if len(p.Errors) != 1 || p.Errors[0].Field != "design.accent" {
		t.Fatalf("a design that breaks a rule: %+v", p)
	}
	env.doJSON(o.member.sess, http.MethodGet, o.path("/"+created.ID.String()), nil, &got, http.StatusOK)
	if !bytes.Equal(parseDesign(t, got.Design).Canonical(), house.Canonical()) {
		t.Fatalf("the refused replace took: %s", got.Design)
	}

	// The images: an admin's upload is kept as the core's own encoding,
	// listed as had, and carried to a member only on include=assets.
	st, body := putOrgDesignFile(t, env, o.admin.orgAdmin, o.path("/"+created.ID.String()+"/logo"), logo)
	if st != http.StatusOK {
		t.Fatalf("the admin's logo: %d %s", st, body)
	}
	var withLogo orgDesignRecord
	if err := json.Unmarshal(body, &withLogo); err != nil || !withLogo.HasLogo || parseDesign(t, withLogo.Design).Logo.PNG == "" {
		t.Fatalf("the logo's answer: %s", body)
	}
	env.doJSON(o.member.profile, http.MethodGet, o.path("/"+created.ID.String()), nil, &got, http.StatusOK)
	if !got.HasLogo || parseDesign(t, got.Design).Logo.PNG != "" {
		t.Fatalf("a read without include=assets carries the logo: %+v", got)
	}
	env.doJSON(o.member.profile, http.MethodGet, o.path("/"+created.ID.String()+"?include=assets"), nil, &got, http.StatusOK)
	if parseDesign(t, got.Design).Logo.PNG != parseDesign(t, withLogo.Design).Logo.PNG {
		t.Fatalf("the member's read with assets: %+v", got)
	}
	env.doJSON(o.member.sess, http.MethodGet, o.path(""), nil, &list, http.StatusOK)
	if !list.Designs[0].HasLogo {
		t.Fatalf("the library after the logo: %+v", list)
	}
	env.doJSON(o.admin.sess, http.MethodDelete, o.path("/"+created.ID.String()+"/logo"), nil, &got, http.StatusOK)
	if got.HasLogo {
		t.Fatalf("after removing the logo: %+v", got)
	}
	env.doJSON(o.admin.sess, http.MethodPut, o.path("/"+created.ID.String()+"/custom-cover"), map[string]any{"source": "#page[]", "images": []any{}}, &got, http.StatusOK)
	if !got.HasCustomCover {
		t.Fatalf("after the custom cover: %+v", got)
	}

	// The library holds ten: the eleventh is 409 and nothing is stored.
	for i := 2; i < reportdesign.MaxLibrary; i++ {
		env.doJSON(o.admin.sess, http.MethodPost, o.path(""), designBody(houseDesign(t, "plain", "Design "+string(rune('a'+i)))), nil, http.StatusCreated)
	}
	env.doJSON(o.admin.sess, http.MethodPost, o.path(""), designBody(houseDesign(t, "plain", "Eleventh")), &p, http.StatusConflict)
	if !strings.Contains(p.Detail, "ten designs") {
		t.Fatalf("the eleventh: %+v", p)
	}
	env.doJSON(o.member.sess, http.MethodGet, o.path(""), nil, &list, http.StatusOK)
	if len(list.Designs) != reportdesign.MaxLibrary {
		t.Fatalf("the library after the refused eleventh: %d", len(list.Designs))
	}

	// Delete: gone for the member too, and gone twice is 404; another
	// organization's id is 404.
	env.doJSON(o.admin.orgAdmin, http.MethodDelete, o.path("/"+second.ID.String()), nil, nil, http.StatusNoContent)
	env.doJSON(o.admin.orgAdmin, http.MethodDelete, o.path("/"+second.ID.String()), nil, nil, http.StatusNotFound)
	env.doJSON(o.member.sess, http.MethodGet, o.path("/"+second.ID.String()), nil, nil, http.StatusNotFound)
	env.doJSON(o.admin.sess, http.MethodGet, o.path("/"+uuid.New().String()), nil, nil, http.StatusNotFound)
	env.doJSON(o.admin.sess, http.MethodPut, o.path("/"+uuid.New().String()), designBody(houseDesign(t, "plain", "Nobody's")), nil, http.StatusNotFound)

	// Every write of the admin's is in the organization's audit log,
	// naming the design and never a byte of it.
	want := []string{"org.report_design_create Acme house", "org.report_design_update Acme house", "org.report_design_update Acme house logo", "org.report_design_update Acme house logo", "org.report_design_update Acme house custom cover"}
	if got := orgDesignAuditActions(t, env, o.handle, created.ID); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the audit log holds\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := orgDesignAuditActions(t, env, o.handle, second.ID); strings.Join(got, "\n") != "org.report_design_create Letters\norg.report_design_delete Letters" {
		t.Fatalf("the deleted design's audit log: %v", got)
	}
	var leaked int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE target_kind = 'report_design' AND detail::text LIKE '%#0b5c55%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("the audit detail carries the design: %d, %v", leaked, err)
	}
}

// TestHouseDesignsAreHiddenFromOutsiders: another organization's admin and
// member, an account in no organization, a pending member and platform
// staff are answered 404 on every route; a member who is removed is
// answered 404 from the next call on, their profile token included.
func TestHouseDesignsAreHiddenFromOutsiders(t *testing.T) {
	env := newTestEnv(t)
	o := newDesignOrg(t, env, "hdh")
	var created orgDesignRecord
	env.doJSON(o.admin.sess, http.MethodPost, o.path(""), designBody(houseDesign(t, "technical", "Acme house")), &created, http.StatusCreated)

	other := newDesignOrg(t, env, "hdo")
	plain := newDesignMember(env, "hdh-plain")
	pending := newDesignMember(env, "hdh-pend")
	env.seedMembership(o.handle, pending.handle, "member", "pending")
	staff := newDesignMember(env, "hdh-staff")
	env.makePlatformStaff(t, staff.handle)
	staff.sess = env.login(staff.handle)
	_, tok := env.mintPAT(staff.sess, "staff", "user:profile", "org:admin")
	staff.profile = caller{name: "hdh-staff-pat", pat: tok}

	routes := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, o.path(""), nil},
		{http.MethodGet, o.path("/" + created.ID.String()), nil},
		{http.MethodGet, o.path("/" + created.ID.String() + "?include=assets"), nil},
		{http.MethodPost, o.path(""), designBody(houseDesign(t, "modern", "Theirs"))},
		{http.MethodPut, o.path("/" + created.ID.String()), designBody(houseDesign(t, "modern", "Theirs"))},
		{http.MethodDelete, o.path("/" + created.ID.String()), nil},
		{http.MethodDelete, o.path("/" + created.ID.String() + "/logo"), nil},
		{http.MethodDelete, o.path("/" + created.ID.String() + "/cover-image"), nil},
		{http.MethodPut, o.path("/" + created.ID.String() + "/custom-cover"), map[string]any{"source": "#page[]", "images": []any{}}},
		{http.MethodDelete, o.path("/" + created.ID.String() + "/custom-cover"), nil},
	}
	logo := smallPNG(t)
	refused := func(who designMember) {
		t.Helper()
		for _, c := range []caller{who.profile, who.sess} {
			for _, route := range routes {
				res := env.do(c, route.method, route.path, route.body)
				var b bytes.Buffer
				_, _ = b.ReadFrom(res.Body)
				_ = res.Body.Close()
				if res.StatusCode != http.StatusNotFound || bytes.Contains(b.Bytes(), []byte("Acme house")) {
					t.Fatalf("%s %s as %s: %d %s, want 404", route.method, route.path, c.name, res.StatusCode, b.String())
				}
			}
			for _, route := range []string{"/logo", "/cover-image"} {
				if st, body := putOrgDesignFile(t, env, c, o.path("/"+created.ID.String()+route), logo); st != http.StatusNotFound {
					t.Fatalf("PUT %s as %s: %d %s, want 404", route, c.name, st, body)
				}
			}
		}
	}
	for _, out := range []designMember{other.admin, other.member, plain, pending, staff} {
		refused(out)
	}
	// The other organization's library is its own.
	var list orgDesignList
	env.doJSON(other.member.sess, http.MethodGet, other.path(""), nil, &list, http.StatusOK)
	if list.Org != other.handle || len(list.Designs) != 0 {
		t.Fatalf("the other organization's library: %+v", list)
	}

	// A member reads until they are removed, and not after.
	env.doJSON(o.member.profile, http.MethodGet, o.path("/"+created.ID.String()), nil, nil, http.StatusOK)
	env.doJSON(o.admin.sess, http.MethodDelete, "/api/v1/orgs/"+o.handle+"/members/"+o.member.handle, nil, nil, http.StatusNoContent)
	refused(o.member)
	var still orgDesignRecord
	env.doJSON(o.admin.sess, http.MethodGet, o.path("/"+created.ID.String()), nil, &still, http.StatusOK)
	if still.ID != created.ID {
		t.Fatalf("the design went with the member: %+v", still)
	}
}

// TestHouseDesignsInTheDecommissionHold: while an organization is held for
// its decommission its members still read its designs, and nothing is
// written.
func TestHouseDesignsInTheDecommissionHold(t *testing.T) {
	env := newTestEnv(t)
	o := newDesignOrg(t, env, "hdd")
	var created orgDesignRecord
	env.doJSON(o.admin.sess, http.MethodPost, o.path(""), designBody(houseDesign(t, "technical", "Acme house")), &created, http.StatusCreated)
	env.doJSON(o.admin.sess, http.MethodPost, "/api/v1/orgs/"+o.handle+"/decommission", map[string]any{"confirm": o.handle, "reason": "moving on"}, nil, http.StatusOK)

	env.doJSON(o.member.profile, http.MethodGet, o.path(""), nil, nil, http.StatusOK)
	env.doJSON(o.member.profile, http.MethodGet, o.path("/"+created.ID.String()+"?include=assets"), nil, nil, http.StatusOK)
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, o.path(""), designBody(houseDesign(t, "modern", "Late"))},
		{http.MethodPut, o.path("/" + created.ID.String()), designBody(houseDesign(t, "modern", "Acme house"))},
		{http.MethodDelete, o.path("/" + created.ID.String()), nil},
		{http.MethodDelete, o.path("/" + created.ID.String() + "/logo"), nil},
	} {
		if res := env.do(o.admin.orgAdmin, route.method, route.path, route.body); res.StatusCode != http.StatusConflict {
			t.Fatalf("the admin's %s %s during the hold: %d, want 409", route.method, route.path, res.StatusCode)
		}
	}
	if st, body := putOrgDesignFile(t, env, o.admin.orgAdmin, o.path("/"+created.ID.String()+"/logo"), smallPNG(t)); st != http.StatusConflict || problemTypeOf(body) != "org-decommissioning" {
		t.Fatalf("a logo during the hold: %d %s", st, body)
	}
}

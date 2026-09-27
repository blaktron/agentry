package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/pkg/packseal"
)

// An organization's shared knowledge (agentry#646; plan knowledge.md §4.7,
// D13, D26) through its routes: an admin writes a pack wrapped for the
// organization, every active member reads it and has its key unwrapped,
// membership is checked at every call, and anyone outside the organization
// is answered 404.

// sharedOrg is an organization with an admin and a member, each holding a
// knowledge token.
type sharedOrg struct {
	handle        string
	admin, member knowledgeOwner
}

func newSharedOrg(t *testing.T, env *testEnv, name string) sharedOrg {
	t.Helper()
	o := sharedOrg{handle: name + env.sfx, admin: newKnowledgeOwner(env, name+"-adm"), member: newKnowledgeOwner(env, name+"-mem")}
	env.doJSON(o.admin.sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": o.handle, "displayName": "Shared Knowledge"}, nil, http.StatusCreated)
	env.joinOrg(o.admin.sess, o.handle, o.member.handle)
	return o
}

func (o sharedOrg) path(p string) string { return "/api/v1/orgs/" + o.handle + "/knowledge" + p }

// sharedPackBody is a pack as the organization's routes show it.
type sharedPackBody struct {
	knowledgePackBody
	Shared     bool   `json:"shared"`
	Org        string `json:"org"`
	Exportable *bool  `json:"exportable"`
}

// putSharedPack has the admin wrap a fresh data key for the organization,
// create a pack and upload its tree.
func putSharedPack(t *testing.T, env *testEnv, o sharedOrg, name string, files []scan.PackFile) (sharedPackBody, []byte, []byte, []byte) {
	t.Helper()
	dataKey, err := packseal.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var wk knowledgeKey
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}, &wk, http.StatusOK)
	var created sharedPackBody
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/packs"), map[string]any{"name": name, "wrappedKey": wk}, &created, http.StatusCreated)
	if !created.Shared || created.Org != o.handle || created.Exportable == nil || *created.Exportable {
		t.Fatalf("a new shared pack reads shared=%v org=%q exportable=%v", created.Shared, created.Org, created.Exportable)
	}
	sealed, tree, digest := sealedPack(t, files, dataKey)
	st, _, body := env.raw(o.admin.pat, http.MethodPut, o.path("/packs/"+created.ID+"/tree"), sealed)
	if st != http.StatusAccepted {
		t.Fatalf("upload: %d %s", st, body)
	}
	var up sharedPackBody
	if err := json.Unmarshal(body, &up); err != nil {
		t.Fatal(err)
	}
	if up.State != knowledge.StateScanning || up.Digest != digest {
		t.Fatalf("after the upload the pack is %q with %s, want scanning with %s", up.State, up.Digest, digest)
	}
	return up, dataKey, sealed, tree
}

// orgAuditActions is every action recorded in the organization's audit
// log against the pack, oldest first.
func orgAuditActions(t *testing.T, env *testEnv, org, pack string) []string {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT a.action FROM audit_events a JOIN handles h ON h.id = a.org_id
		 WHERE h.handle = $1 AND a.target_kind = 'knowledge_pack' AND a.target_id = $2::uuid ORDER BY a.occurred_at, a.id`, org, pack)
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

func TestSharedKnowledgeThroughTheAPI(t *testing.T) {
	env := newTestEnv(t)
	o := newSharedOrg(t, env, "kns")
	p, dataKey, sealed, tree := putSharedPack(t, env, o, "handbook", knowledgeFiles())
	drainKnowledgeScans(t, env)

	// Every active member reads it: the list, the pack, the sealed tree,
	// the key and the organization's meter.
	for _, c := range []caller{o.member.pat, o.member.sess, o.admin.pat} {
		var list []sharedPackBody
		env.doJSON(c, http.MethodGet, o.path("/packs"), nil, &list, http.StatusOK)
		if len(list) != 1 || list[0].ID != p.ID || !list[0].Shared || list[0].Org != o.handle || list[0].State != knowledge.StateReady {
			t.Fatalf("list as %s = %+v", c.name, list)
		}
		st, hdr, body := env.raw(c, http.MethodGet, o.path("/packs/"+p.ID+"/tree"), nil)
		if st != http.StatusOK || !bytes.Equal(body, sealed) || hdr.Get("Cache-Control") != "no-store" {
			t.Fatalf("download as %s: %d, %d bytes", c.name, st, len(body))
		}
		var dk struct {
			Key []byte `json:"key"`
		}
		env.doJSON(c, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey, &dk, http.StatusOK)
		if !bytes.Equal(dk.Key, dataKey) {
			t.Fatalf("unwrap as %s did not give the pack's data key", c.name)
		}
		var usage struct {
			Bytes int64 `json:"bytes"`
			Packs int   `json:"packs"`
		}
		env.doJSON(c, http.MethodGet, o.path("/usage"), nil, &usage, http.StatusOK)
		if usage.Bytes != p.Bytes || usage.Packs != 1 {
			t.Fatalf("usage as %s = %+v", c.name, usage)
		}
	}

	// A member writes nothing: every write is the admins'.
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}},
		{http.MethodPost, o.path("/packs"), map[string]any{"name": "member-made", "wrappedKey": p.WrappedKey}},
		{http.MethodPatch, o.path("/packs/" + p.ID), map[string]any{"exportable": true}},
		{http.MethodDelete, o.path("/packs/" + p.ID), nil},
	} {
		if res := env.do(o.member.pat, route.method, route.path, route.body); res.StatusCode != http.StatusForbidden {
			t.Fatalf("a member's %s %s: %d, want 403", route.method, route.path, res.StatusCode)
		}
	}
	if st, _, body := env.raw(o.member.pat, http.MethodPut, o.path("/packs/"+p.ID+"/tree"), sealed); st != http.StatusForbidden {
		t.Fatalf("a member's upload: %d %s", st, body)
	}

	// Export unencrypted is the admins' until they mark the pack (D26).
	st, _, body := env.raw(o.member.pat, http.MethodGet, o.path("/packs/"+p.ID+"/export"), nil)
	if st != http.StatusForbidden || problemTypeOf(body) != "knowledge-not-exportable" {
		t.Fatalf("a member's export of an unmarked pack: %d %s", st, body)
	}
	if st, _, body := env.raw(o.admin.pat, http.MethodGet, o.path("/packs/"+p.ID+"/export"), nil); st != http.StatusOK || !bytes.Equal(body, tree) {
		t.Fatalf("the admin's export: %d, %d bytes", st, len(body))
	}
	var marked sharedPackBody
	env.doJSON(o.admin.pat, http.MethodPatch, o.path("/packs/"+p.ID), map[string]any{"exportable": true}, &marked, http.StatusOK)
	if marked.Exportable == nil || !*marked.Exportable {
		t.Fatalf("after marking, exportable = %v", marked.Exportable)
	}
	st, hdr, body := env.raw(o.member.sess, http.MethodGet, o.path("/packs/"+p.ID+"/export"), nil)
	if st != http.StatusOK || hdr.Get("Content-Type") != "application/x-tar" || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("a member's export of a marked pack: %d %s", st, body)
	}
	if sum := sha256.Sum256(body); "sha256:"+hex.EncodeToString(sum[:]) != p.Digest {
		t.Fatal("the exported tree is not the pack's digest")
	}

	// The organization's pack is not the member's own: the personal routes
	// do not find it, list it or open its key.
	var own []knowledgePackBody
	env.doJSON(o.member.pat, http.MethodGet, "/api/v1/knowledge/packs", nil, &own, http.StatusOK)
	if len(own) != 0 {
		t.Fatalf("the member's own list holds the organization's pack: %+v", own)
	}
	env.doJSON(o.member.pat, http.MethodGet, "/api/v1/knowledge/packs/"+p.ID, nil, nil, http.StatusNotFound)
	env.doJSON(o.member.pat, http.MethodPost, "/api/v1/knowledge/keys/unwrap", p.WrappedKey, nil, http.StatusNotFound)
	// And a pack of the admin's own does not open under the organization.
	mine, _, _, _ := putPack(t, env, o.admin, "admin-own", knowledgeFiles())
	env.doJSON(o.admin.pat, http.MethodGet, o.path("/packs/"+mine.ID), nil, nil, http.StatusNotFound)
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/keys/unwrap"), mine.WrappedKey, nil, http.StatusNotFound)

	env.doJSON(o.admin.pat, http.MethodDelete, o.path("/packs/"+p.ID), nil, nil, http.StatusNoContent)
	env.doJSON(o.member.pat, http.MethodGet, o.path("/packs/"+p.ID), nil, nil, http.StatusNotFound)

	got := orgAuditActions(t, env, o.handle, p.ID)
	want := []string{"org.knowledge_create", "org.knowledge_export", "org.knowledge_update", "org.knowledge_export", "org.knowledge_delete"}
	if len(got) != len(want) {
		t.Fatalf("audit = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit = %v, want %v", got, want)
		}
	}
}

// TestARemovedMemberCannotUnwrap is D13's rule: a member who is removed
// keeps the sealed bytes they downloaded and can no longer have the key
// that opens them unwrapped, over a token or a session.
func TestARemovedMemberCannotUnwrap(t *testing.T) {
	env := newTestEnv(t)
	o := newSharedOrg(t, env, "knr")
	p, dataKey, _, _ := putSharedPack(t, env, o, "handbook", knowledgeFiles())
	drainKnowledgeScans(t, env)

	for _, c := range []caller{o.member.pat, o.member.sess} {
		var dk struct {
			Key []byte `json:"key"`
		}
		env.doJSON(c, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey, &dk, http.StatusOK)
		if !bytes.Equal(dk.Key, dataKey) {
			t.Fatalf("a member's unwrap as %s did not open the key", c.name)
		}
	}
	env.doJSON(o.admin.sess, http.MethodDelete, "/api/v1/orgs/"+o.handle+"/members/"+o.member.handle, nil, nil, http.StatusNoContent)

	for _, c := range []caller{o.member.pat, o.member.sess} {
		res := env.do(c, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey)
		var b bytes.Buffer
		_, _ = b.ReadFrom(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound || bytes.Contains(b.Bytes(), []byte(base64.StdEncoding.EncodeToString(dataKey))) {
			t.Fatalf("a removed member's unwrap as %s: %d %s, want 404", c.name, res.StatusCode, b.String())
		}
		for _, path := range []string{"/packs", "/packs/" + p.ID, "/packs/" + p.ID + "/tree", "/usage"} {
			if st, _, body := env.raw(c, http.MethodGet, o.path(path), nil); st != http.StatusNotFound {
				t.Fatalf("a removed member's GET %s as %s: %d %s, want 404", path, c.name, st, body)
			}
		}
	}
	// The organization keeps its pack; its admin still opens it.
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey, nil, http.StatusOK)
}

// TestSharedKnowledgeIsHiddenFromOutsiders: another organization's member,
// an account in no organization, a pending member and platform staff are
// answered 404 on every route, the key presented whole included.
func TestSharedKnowledgeIsHiddenFromOutsiders(t *testing.T) {
	env := newTestEnv(t)
	o := newSharedOrg(t, env, "knh")
	p, dataKey, sealed, _ := putSharedPack(t, env, o, "handbook", knowledgeFiles())
	drainKnowledgeScans(t, env)

	other := newSharedOrg(t, env, "kno")
	plain := newKnowledgeOwner(env, "knh-plain")
	pending := newKnowledgeOwner(env, "knh-pend")
	env.seedMembership(o.handle, pending.handle, "member", "pending")
	staffO := newKnowledgeOwner(env, "knh-staff")
	env.makePlatformStaff(t, staffO.handle)
	staffO.sess = env.login(staffO.handle)
	_, tok := env.mintPAT(staffO.sess, "knowledge", "knowledge:read", "knowledge:write")
	staffO.pat = caller{name: "knh-staff-pat", pat: tok}

	for _, out := range []knowledgeOwner{other.admin, other.member, plain, pending, staffO} {
		for _, c := range []caller{out.pat, out.sess} {
			for _, route := range []struct {
				method, path string
				body         any
			}{
				{http.MethodGet, o.path("/packs"), nil},
				{http.MethodGet, o.path("/packs/" + p.ID), nil},
				{http.MethodGet, o.path("/packs/" + p.ID + "/tree"), nil},
				{http.MethodGet, o.path("/packs/" + p.ID + "/export"), nil},
				{http.MethodGet, o.path("/usage"), nil},
				{http.MethodPatch, o.path("/packs/" + p.ID), map[string]any{"exportable": true}},
				{http.MethodDelete, o.path("/packs/" + p.ID), nil},
				{http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}},
				{http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey},
			} {
				res := env.do(c, route.method, route.path, route.body)
				var b bytes.Buffer
				_, _ = b.ReadFrom(res.Body)
				_ = res.Body.Close()
				if res.StatusCode != http.StatusNotFound || bytes.Contains(b.Bytes(), []byte(base64.StdEncoding.EncodeToString(dataKey))) {
					t.Fatalf("%s %s as %s: %d %s, want 404", route.method, route.path, out.handle, res.StatusCode, b.String())
				}
			}
			if st, _, body := env.raw(c, http.MethodPut, o.path("/packs/"+p.ID+"/tree"), sealed); st != http.StatusNotFound {
				t.Fatalf("an outsider's upload as %s: %d %s", out.handle, st, body)
			}
		}
	}
	var got sharedPackBody
	env.doJSON(o.member.pat, http.MethodGet, o.path("/packs/"+p.ID), nil, &got, http.StatusOK)
	if got.Exportable == nil || *got.Exportable {
		t.Fatal("an outsider's PATCH marked the pack exportable")
	}

	// Staff see the organization's packs by name and size, as a person's.
	st, _, body := env.raw(staffO.sess, http.MethodGet, "/api/v1/platform/knowledge?owner="+o.handle, nil)
	var sizes []map[string]any
	if st != http.StatusOK || json.Unmarshal(body, &sizes) != nil || len(sizes) != 1 || sizes[0]["name"] != "handbook" {
		t.Fatalf("staff sizes of the organization: %d %s", st, body)
	}
	if _, ok := sizes[0]["wrappedKey"]; ok {
		t.Fatalf("staff see the wrapped key: %s", body)
	}
}

// TestSharedKnowledgeDrawsOnTheOrganization: on a core registry the
// organization's packs are counted against the organization's own
// allocation, apart from its members' (an extension may pool them).
func TestSharedKnowledgeDrawsOnTheOrganization(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.Limits.KnowledgeBytesPerAccount = 400 })
	o := newSharedOrg(t, env, "kna")
	putSharedPack(t, env, o, "first", sizedPack(300, 'a'))
	putPack(t, env, o.member, "members-own", sizedPack(300, 'm'))

	dataKey, _ := packseal.NewKey()
	var wk knowledgeKey
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}, &wk, http.StatusOK)
	var created sharedPackBody
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/packs"), map[string]any{"name": "second", "wrappedKey": wk}, &created, http.StatusCreated)
	sealed, _, _ := sealedPack(t, sizedPack(200, 'b'), dataKey)
	st, _, body := env.raw(o.admin.pat, http.MethodPut, o.path("/packs/"+created.ID+"/tree"), sealed)
	var refusal struct {
		Bytes int64 `json:"bytes"`
		Max   int64 `json:"max"`
	}
	_ = json.Unmarshal(body, &refusal)
	if st != http.StatusRequestEntityTooLarge || problemTypeOf(body) != "knowledge-allocation" || refusal.Bytes != 500 || refusal.Max != 400 {
		t.Fatalf("500 of the organization's 400: %d %s", st, body)
	}
}

// TestHiddenFromOutsidersIsOnlyOnMemberRoutes: the matrix takes a 404 as the
// denial of a route declared HiddenFromOutsiders, which is sound only where
// no caller outside the organization could ever be let in — an org-scoped,
// non-anonymous route of the chokepoint whose action needs a role.
func TestHiddenFromOutsidersIsOnlyOnMemberRoutes(t *testing.T) {
	org := uuid.New()
	outsider := &auth.Principal{UserID: uuid.New(), Via: "session", OrgRoles: map[uuid.UUID]auth.OrgRole{}}
	n := 0
	for id, d := range api.AllRouteAuthzDecls() {
		if !d.HiddenFromOutsiders {
			continue
		}
		n++
		if !d.OrgScoped || d.Anonymous || d.SelfAuthorized || d.NoAuthz || d.AgentScoped {
			t.Errorf("%s: HiddenFromOutsiders on a route that is not a plain org-scoped one: %+v", id, d)
		}
		if err := auth.Check(outsider, auth.Resource{OrgID: org}, d.Action); err == nil {
			t.Errorf("%s: %s admits a caller with no role in the organization", id, d.Action)
		}
	}
	if n != 11 {
		t.Fatalf("%d routes are HiddenFromOutsiders, want the 11 of shared knowledge", n)
	}
}

// TestSharedKnowledgeInTheDecommissionHold: while an organization is held
// for its decommission its members still read its shared packs and have
// their keys unwrapped (D23: members keep read and export), and nothing is
// written.
func TestSharedKnowledgeInTheDecommissionHold(t *testing.T) {
	env := newTestEnv(t)
	o := newSharedOrg(t, env, "knd")
	p, dataKey, sealed, _ := putSharedPack(t, env, o, "handbook", knowledgeFiles())
	drainKnowledgeScans(t, env)
	env.doJSON(o.admin.sess, http.MethodPost, "/api/v1/orgs/"+o.handle+"/decommission", map[string]any{"confirm": o.handle, "reason": "moving on"}, nil, http.StatusOK)

	env.doJSON(o.member.pat, http.MethodGet, o.path("/packs/"+p.ID), nil, nil, http.StatusOK)
	env.doJSON(o.member.pat, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey, nil, http.StatusOK)
	if st, _, _ := env.raw(o.admin.pat, http.MethodGet, o.path("/packs/"+p.ID+"/export"), nil); st != http.StatusOK {
		t.Fatalf("the admin's export during the hold: %d", st)
	}
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}},
		{http.MethodPost, o.path("/packs"), map[string]any{"name": "late", "wrappedKey": p.WrappedKey}},
		{http.MethodPatch, o.path("/packs/" + p.ID), map[string]any{"exportable": true}},
		{http.MethodDelete, o.path("/packs/" + p.ID), nil},
	} {
		if res := env.do(o.admin.pat, route.method, route.path, route.body); res.StatusCode != http.StatusConflict {
			t.Fatalf("the admin's %s %s during the hold: %d, want 409", route.method, route.path, res.StatusCode)
		}
	}
	if st, _, body := env.raw(o.admin.pat, http.MethodPut, o.path("/packs/"+p.ID+"/tree"), sealed); st != http.StatusConflict || problemTypeOf(body) != "org-decommissioning" {
		t.Fatalf("an upload during the hold: %d %s", st, body)
	}
}

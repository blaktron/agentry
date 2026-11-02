package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/pkg/packseal"
)

// An organization's shared knowledge through its routes: an admin writes a pack wrapped for the
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

// orgAuditDetail is what the organization's latest audit event of the
// action against the pack recorded.
func orgAuditDetail(t *testing.T, env *testEnv, org, pack, action string) map[string]any {
	t.Helper()
	var raw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.detail FROM audit_events a JOIN handles h ON h.id = a.org_id
		 WHERE h.handle = $1 AND a.target_kind = 'knowledge_pack' AND a.target_id = $2::uuid AND a.action = $3
		 ORDER BY a.occurred_at DESC, a.id DESC LIMIT 1`, org, pack, action).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// packObjectKeys is the keys of the sealed trees the pack holds.
func packObjectKeys(t *testing.T, env *testEnv, pack string) []string {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(), `SELECT key FROM knowledge_objects WHERE pack_id = $1::uuid`, pack)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	return keys
}

func TestSharedKnowledgeThroughTheAPI(t *testing.T) {
	env := newTestEnv(t)
	o := newSharedOrg(t, env, "kns")
	p, dataKey, sealed, tree := putSharedPack(t, env, o, "handbook", knowledgeFiles())

	// While its scan runs the tree is neither downloaded nor exported.
	for _, route := range []string{"/tree", "/export"} {
		if st, _, body := env.raw(o.admin.pat, http.MethodGet, o.path("/packs/"+p.ID+route), nil); st != http.StatusConflict || problemTypeOf(body) != "knowledge-scanning" {
			t.Fatalf("GET %s while scanning: %d %s", route, st, body)
		}
	}
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
		if hdr.Get("Content-Type") != "application/octet-stream" || hdr.Get("X-Agentry-Knowledge-Digest") != p.Digest {
			t.Fatalf("download as %s is %q with digest %q, want an octet stream with %s", c.name, hdr.Get("Content-Type"), hdr.Get("X-Agentry-Knowledge-Digest"), p.Digest)
		}
		var dk struct {
			Key []byte `json:"key"`
		}
		env.doJSON(c, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey, &dk, http.StatusOK)
		if !bytes.Equal(dk.Key, dataKey) {
			t.Fatalf("unwrap as %s did not give the pack's data key", c.name)
		}
		// The key is never cached on its way.
		unwrapped := env.do(c, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey)
		_ = unwrapped.Body.Close()
		if unwrapped.StatusCode != http.StatusOK || unwrapped.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("unwrap as %s: %d with Cache-Control %q, want 200 and no-store", c.name, unwrapped.StatusCode, unwrapped.Header.Get("Cache-Control"))
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

	// An admin's token carries the scopes its use needs: read-only it
	// reads and writes nothing, write-only it reads nothing.
	_, readOnly := env.mintPAT(o.admin.sess, "org-read", "knowledge:read")
	_, writeOnly := env.mintPAT(o.admin.sess, "org-write", "knowledge:write")
	ro, wo := caller{name: "admin-read-only", pat: readOnly}, caller{name: "admin-write-only", pat: writeOnly}
	env.doJSON(ro, http.MethodGet, o.path("/packs"), nil, nil, http.StatusOK)
	env.doJSON(ro, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey, nil, http.StatusOK)
	env.doJSON(wo, http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}, nil, http.StatusOK)
	for _, route := range []struct {
		who          caller
		method, path string
		body         any
	}{
		{ro, http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}},
		{ro, http.MethodPost, o.path("/packs"), map[string]any{"name": "token-made", "wrappedKey": p.WrappedKey}},
		{ro, http.MethodPatch, o.path("/packs/" + p.ID), map[string]any{"exportable": true}},
		{ro, http.MethodDelete, o.path("/packs/" + p.ID), nil},
		{wo, http.MethodGet, o.path("/packs"), nil},
		{wo, http.MethodPost, o.path("/keys/unwrap"), p.WrappedKey},
	} {
		if res := env.do(route.who, route.method, route.path, route.body); res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s's %s %s: %d, want 403", route.who.name, route.method, route.path, res.StatusCode)
		}
	}

	// A pack is made only with a key that opens for the organization, and
	// under a name a pack may have; a key is 32 bytes.
	mineFirst, _, _, _ := putPack(t, env, o.admin, "admin-first", knowledgeFiles())
	foreign := env.do(o.admin.pat, http.MethodPost, o.path("/packs"), map[string]any{"name": "foreign-key", "wrappedKey": mineFirst.WrappedKey})
	foreignBody, _ := io.ReadAll(foreign.Body)
	_ = foreign.Body.Close()
	if foreign.StatusCode != http.StatusNotFound || problemTypeOf(foreignBody) != "knowledge-key-not-found" {
		t.Fatalf("a pack made with a key wrapped for the admin alone: %d %s", foreign.StatusCode, foreignBody)
	}
	badName := env.do(o.admin.pat, http.MethodPost, o.path("/packs"), map[string]any{"name": "Not A Name", "wrappedKey": p.WrappedKey})
	badNameBody, _ := io.ReadAll(badName.Body)
	_ = badName.Body.Close()
	if badName.StatusCode != http.StatusUnprocessableEntity || !bytes.Contains(badNameBody, []byte(`"name"`)) {
		t.Fatalf("a pack named Not A Name: %d %s", badName.StatusCode, badNameBody)
	}
	shortKey := env.do(o.admin.pat, http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey[:31]})
	shortKeyBody, _ := io.ReadAll(shortKey.Body)
	_ = shortKey.Body.Close()
	if shortKey.StatusCode != http.StatusUnprocessableEntity || !bytes.Contains(shortKeyBody, []byte(`"key"`)) {
		t.Fatalf("a wrapped key of 31 bytes: %d %s", shortKey.StatusCode, shortKeyBody)
	}
	// A pack with no tree yet has nothing to download or export.
	var wkNew knowledgeKey
	newKey, _ := packseal.NewKey()
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": newKey}, &wkNew, http.StatusOK)
	var bare sharedPackBody
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/packs"), map[string]any{"name": "no-tree-yet", "wrappedKey": wkNew}, &bare, http.StatusCreated)
	for _, route := range []string{"/tree", "/export"} {
		env.doJSON(o.admin.pat, http.MethodGet, o.path("/packs/"+bare.ID+route), nil, nil, http.StatusNotFound)
	}
	env.doJSON(o.admin.pat, http.MethodDelete, o.path("/packs/"+bare.ID), nil, nil, http.StatusNoContent)

	// Export unencrypted is the admins' until they mark the pack.
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
	if hdr.Get("Content-Disposition") != `attachment; filename="handbook.tar"` || hdr.Get("X-Agentry-Knowledge-Digest") != p.Digest {
		t.Fatalf("the export is %q with digest %q, want an attachment handbook.tar with %s", hdr.Get("Content-Disposition"), hdr.Get("X-Agentry-Knowledge-Digest"), p.Digest)
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
	var mineBody sharedPackBody
	env.doJSON(o.admin.pat, http.MethodGet, "/api/v1/knowledge/packs/"+mine.ID, nil, &mineBody, http.StatusOK)
	if mineBody.Shared || mineBody.Org != "" || mineBody.Exportable != nil {
		t.Fatalf("a person's own pack reads shared=%v org=%q exportable=%v", mineBody.Shared, mineBody.Org, mineBody.Exportable)
	}
	env.doJSON(o.admin.pat, http.MethodGet, o.path("/packs/"+mine.ID), nil, nil, http.StatusNotFound)
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/keys/unwrap"), mine.WrappedKey, nil, http.StatusNotFound)

	// Deleting the pack takes its sealed trees from the store too.
	treeKeys := packObjectKeys(t, env, p.ID)
	if len(treeKeys) == 0 {
		t.Fatal("the pack holds no stored tree before it is deleted")
	}
	for _, k := range treeKeys {
		if ok, err := env.srvObj.Blobs().Exists(context.Background(), k); err != nil || !ok {
			t.Fatalf("the pack's tree %s is not stored (%v, %v)", k, ok, err)
		}
	}
	env.doJSON(o.admin.pat, http.MethodDelete, o.path("/packs/"+p.ID), nil, nil, http.StatusNoContent)
	env.doJSON(o.member.pat, http.MethodGet, o.path("/packs/"+p.ID), nil, nil, http.StatusNotFound)
	if left := packObjectKeys(t, env, p.ID); len(left) != 0 {
		t.Fatalf("a deleted pack still has stored trees: %v", left)
	}
	for _, k := range treeKeys {
		if ok, err := env.srvObj.Blobs().Exists(context.Background(), k); err != nil || ok {
			t.Fatalf("the deleted pack's tree %s is still stored (%v, %v)", k, ok, err)
		}
	}

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
	// Each event names the pack, and the mark says what it was set to.
	for _, action := range want {
		if d := orgAuditDetail(t, env, o.handle, p.ID, action); d["name"] != "handbook" {
			t.Fatalf("%s recorded %v, want the pack's name", action, d)
		}
	}
	if d := orgAuditDetail(t, env, o.handle, p.ID, "org.knowledge_update"); d["exportable"] != true {
		t.Fatalf("the mark recorded %v, want exportable true", d)
	}
}

// TestARemovedMemberCannotUnwrap: a member who is removed
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
	otherPack, _, _, _ := putSharedPack(t, env, other, "others", knowledgeFiles())
	drainKnowledgeScans(t, env)
	plain := newKnowledgeOwner(env, "knh-plain")
	pending := newKnowledgeOwner(env, "knh-pend")
	env.seedMembership(o.handle, pending.handle, "member", "pending")
	staffO := newKnowledgeOwner(env, "knh-staff")
	env.makePlatformStaff(t, staffO.handle)
	staffO.sess = env.login(staffO.handle)
	_, tok := env.mintPAT(staffO.sess, "knowledge", "knowledge:read", "knowledge:write")
	staffO.pat = caller{name: "knh-staff-pat", pat: tok}

	routes := []struct {
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
	}
	for _, out := range []knowledgeOwner{other.admin, other.member, plain, pending, staffO} {
		for _, c := range []caller{out.pat, out.sess} {
			for _, route := range routes {
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

	// A caller with no credential is not an outsider but unauthenticated:
	// 401 on every route, not the 404 a signed-in outsider gets.
	for _, route := range routes {
		if res := env.do(anonymous, route.method, route.path, route.body); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("anonymous %s %s: %d, want 401", route.method, route.path, res.StatusCode)
		}
	}

	// Another organization's admin, who administers an organization of
	// their own, still finds nothing of this one's under their own: a pack
	// is looked up by its owner as well as its id, on every route.
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, other.path("/packs/" + p.ID), nil},
		{http.MethodGet, other.path("/packs/" + p.ID + "/tree"), nil},
		{http.MethodGet, other.path("/packs/" + p.ID + "/export"), nil},
		{http.MethodPatch, other.path("/packs/" + p.ID), map[string]any{"exportable": true}},
		{http.MethodDelete, other.path("/packs/" + p.ID), nil},
		{http.MethodPost, other.path("/keys/unwrap"), p.WrappedKey},
		{http.MethodPost, other.path("/packs"), map[string]any{"name": "taken-key", "wrappedKey": p.WrappedKey}},
	} {
		if res := env.do(other.admin.pat, route.method, route.path, route.body); res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s as another organization's admin: %d, want 404", route.method, route.path, res.StatusCode)
		}
	}
	if st, _, body := env.raw(other.admin.pat, http.MethodPut, other.path("/packs/"+p.ID+"/tree"), sealed); st != http.StatusNotFound {
		t.Fatalf("an upload to another organization's pack: %d %s", st, body)
	}
	var otherList []sharedPackBody
	env.doJSON(other.admin.pat, http.MethodGet, other.path("/packs"), nil, &otherList, http.StatusOK)
	if len(otherList) != 1 || otherList[0].ID != otherPack.ID {
		t.Fatalf("the other organization lists %+v, want only its own pack %s", otherList, otherPack.ID)
	}
	env.doJSON(o.member.pat, http.MethodGet, o.path("/packs/"+p.ID), nil, &got, http.StatusOK)
	if got.Exportable == nil || *got.Exportable {
		t.Fatal("another organization's admin marked the pack exportable")
	}
	if st, _, body := env.raw(o.member.pat, http.MethodGet, o.path("/packs/"+p.ID+"/tree"), nil); st != http.StatusOK || !bytes.Equal(body, sealed) {
		t.Fatalf("the pack's tree after another organization's admin tried it: %d, %d bytes", st, len(body))
	}

	// Staff see the organization's packs by name and size, as a person's.
	st, _, body := env.raw(staffO.sess, http.MethodGet, "/api/v1/platform/knowledge?owner="+o.handle, nil)
	var sizes []map[string]any
	if st != http.StatusOK || json.Unmarshal(body, &sizes) != nil || len(sizes) != 1 || sizes[0]["name"] != "handbook" {
		t.Fatalf("staff sizes of the organization: %d %s", st, body)
	}
	if sizes[0]["state"] != "ready" || sizes[0]["bytes"] != float64(p.Bytes) {
		t.Fatalf("staff see %v of the pack, want it ready at %d bytes", sizes[0], p.Bytes)
	}
	if _, ok := sizes[0]["wrappedKey"]; ok {
		t.Fatalf("staff see the wrapped key: %s", body)
	}

	// The staff route is staff's: an admin, a member and a caller with no
	// credential are refused, a staff token needs the read scope, and an
	// owner that does not exist is a 404.
	sizesPath := "/api/v1/platform/knowledge?owner=" + o.handle
	for _, c := range []struct {
		who  caller
		want int
	}{{o.admin.sess, http.StatusForbidden}, {o.member.pat, http.StatusForbidden}, {anonymous, http.StatusUnauthorized}} {
		if st, _, body := env.raw(c.who, http.MethodGet, sizesPath, nil); st != c.want {
			t.Fatalf("staff sizes as %s: %d %s, want %d", c.who.name, st, body, c.want)
		}
	}
	_, writeTok := env.mintPAT(staffO.sess, "knowledge-write", "knowledge:write")
	if st, _, body := env.raw(caller{name: "staff-write-only", pat: writeTok}, http.MethodGet, sizesPath, nil); st != http.StatusForbidden {
		t.Fatalf("staff sizes with a token that cannot read knowledge: %d %s", st, body)
	}
	if st, _, body := env.raw(staffO.sess, http.MethodGet, "/api/v1/platform/knowledge?owner=nobody"+env.sfx, nil); st != http.StatusNotFound {
		t.Fatalf("staff sizes of an owner that does not exist: %d %s", st, body)
	}
	// Each owner's sizes are that owner's: the other organization's are
	// its one pack.
	st, _, body = env.raw(staffO.sess, http.MethodGet, "/api/v1/platform/knowledge?owner="+other.handle, nil)
	var otherSizes []map[string]any
	if st != http.StatusOK || json.Unmarshal(body, &otherSizes) != nil || len(otherSizes) != 1 || otherSizes[0]["name"] != "others" {
		t.Fatalf("staff sizes of the other organization: %d %s", st, body)
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

	// The organization's meter counts its own packs against its own
	// allocation, not its members'.
	var meter struct {
		Bytes  int64 `json:"bytes"`
		Packs  int   `json:"packs"`
		Used   int64 `json:"used"`
		Max    int64 `json:"max"`
		Pooled bool  `json:"pooled"`
	}
	env.doJSON(o.member.pat, http.MethodGet, o.path("/usage"), nil, &meter, http.StatusOK)
	if meter.Bytes != 300 || meter.Packs != 1 || meter.Used != 300 || meter.Max != 400 || meter.Pooled {
		t.Fatalf("the organization's meter = %+v, want 300 bytes in 1 pack, 300 of 400 used, not pooled", meter)
	}

	dataKey, _ := packseal.NewKey()
	var wk knowledgeKey
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/keys/wrap"), map[string]any{"key": dataKey}, &wk, http.StatusOK)
	var created sharedPackBody
	env.doJSON(o.admin.pat, http.MethodPost, o.path("/packs"), map[string]any{"name": "second", "wrappedKey": wk}, &created, http.StatusCreated)
	// upload puts a tree of n bytes into the second pack.
	upload := func(n int, fill byte) (int, []byte) {
		t.Helper()
		sealed, _, _ := sealedPack(t, sizedPack(n, fill), dataKey)
		st, _, body := env.raw(o.admin.pat, http.MethodPut, o.path("/packs/"+created.ID+"/tree"), sealed)
		return st, body
	}
	refused := func(what string, n int, fill byte, wantBytes, wantMax int64) {
		t.Helper()
		st, body := upload(n, fill)
		var refusal struct {
			Bytes int64 `json:"bytes"`
			Max   int64 `json:"max"`
		}
		_ = json.Unmarshal(body, &refusal)
		if st != http.StatusRequestEntityTooLarge || problemTypeOf(body) != "knowledge-allocation" || refusal.Bytes != wantBytes || refusal.Max != wantMax {
			t.Fatalf("%s: %d %s, want knowledge-allocation with %d of %d", what, st, body, wantBytes, wantMax)
		}
	}
	taken := func(what string, n int, fill byte) {
		t.Helper()
		if st, body := upload(n, fill); st != http.StatusAccepted {
			t.Fatalf("%s: %d %s, want 202", what, st, body)
		}
	}
	refused("500 of the organization's 400", 200, 'b', 500, 400)
	// The allocation is exact: 400 fits, and a replacement tree is
	// counted against the others alone, not beside the one it replaces.
	taken("300 and 100 of 400", 100, 'c')
	taken("the 100 replaced by another 100 of 400", 100, 'd')
	refused("401 of 400", 101, 'e', 401, 400)

	// A smaller allocation never deletes: with the organization's tier
	// capped at 350 beneath the 400 it holds, a tree no larger than the one
	// it replaces is still taken, one that grows is not, and a smaller one
	// is. The tier is the organization's own, not its members'.
	env.setEntitlements(tierResolverFor(func(f *entitlements.Features) { f.KnowledgeBytes = entitlements.Cap{Enabled: true, Max: 350} }))
	taken("the same size under a cap of 350", 100, 'f')
	refused("101 under a cap of 350", 101, 'g', 401, 350)
	taken("a smaller tree under a cap of 350", 50, 'h')
	// With knowledge off for the organization nothing grows.
	env.setEntitlements(tierResolverFor(func(f *entitlements.Features) { f.KnowledgeBytes = entitlements.Cap{} }))
	taken("the same size with the allocation off", 50, 'i')
	if st, body := upload(60, 'j'); st != http.StatusRequestEntityTooLarge || problemTypeOf(body) != "knowledge-allocation" {
		t.Fatalf("a tree that grows with the allocation off: %d %s", st, body)
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
// their keys unwrapped (members keep read and export), and nothing is
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

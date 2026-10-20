package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/scan"
)

// A release that ships knowledge packs makes their contents readable by
// everyone who can download it, so an upload through the API confirms it:
// every pack shipped has an entry, every entry names a pack shipped, and an
// origin an entry claims is true. The confirmation is kept with the version,
// an organization's pack leaves a line in the organization's audit log, and
// making an agent public asks for the confirmation again.

// acknowledgeShippedPacks is the knowledgeShipping part for a release's
// files: an entry for each pack under knowledge/, no origins.
func acknowledgeShippedPacks(files map[string]string) string {
	var packs []map[string]any
	for p := range files {
		if rest, ok := strings.CutPrefix(p, "knowledge/"); ok {
			if name, file, _ := strings.Cut(rest, "/"); file == "manifest.json" {
				packs = append(packs, map[string]any{"name": name})
			}
		}
	}
	if len(packs) == 0 {
		return ""
	}
	return shippingBody(packs...)
}

// shippingBody is a knowledgeShipping part from its entries.
func shippingBody(entries ...map[string]any) string {
	if entries == nil {
		entries = []map[string]any{}
	}
	b, _ := json.Marshal(map[string]any{"packs": entries})
	return string(b)
}

// packEntry is one entry of a knowledgeShipping part; origin may be nil.
func packEntry(name string, origin map[string]any) map[string]any {
	e := map[string]any{"name": name}
	if origin != nil {
		e["origin"] = origin
	}
	return e
}

func ownOrigin(packID string) map[string]any {
	return map[string]any{"kind": "own", "packId": packID}
}

func orgOrigin(org, packID string) map[string]any {
	return map[string]any{"kind": "org", "org": org, "packId": packID}
}

// shippingProblem is a refused upload's problem body.
type shippingProblem struct {
	Type   string   `json:"type"`
	Detail string   `json:"detail"`
	Packs  []string `json:"packs"`
}

func (p shippingProblem) slug() string { return p.Type[strings.LastIndex(p.Type, "/")+1:] }

// uploadShipping uploads files with the given knowledgeShipping part (none
// when ack is empty) and returns the status and the body.
func (env *testEnv) uploadShipping(ns, name, pat string, files map[string]string, ack string) (int, string) {
	env.t.Helper()
	fields := map[string]string{}
	if ack != "" {
		fields["knowledgeShipping"] = ack
	}
	return env.uploadVersionCLIWithFields(ns, name, pat, files, fields)
}

func wantShippingRefusal(t *testing.T, code int, body, slug string, packs ...string) {
	t.Helper()
	var p shippingProblem
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("not a problem: %s", body)
	}
	if code != http.StatusUnprocessableEntity || p.slug() != slug {
		t.Fatalf("got %d %s, want 422 %s: %s", code, p.slug(), slug, body)
	}
	if strings.Join(p.Packs, ",") != strings.Join(packs, ",") {
		t.Fatalf("problem names packs %v, want %v: %s", p.Packs, packs, body)
	}
	for _, n := range packs {
		if !strings.Contains(p.Detail, `"`+n+`"`) {
			t.Fatalf("detail does not name %q: %s", n, p.Detail)
		}
	}
}

// versionCount is how many versions an agent holds.
func (env *testEnv) versionCount(ns, name string) int {
	env.t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agent_versions v JOIN agents a ON a.id = v.agent_id JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`,
		ns, name).Scan(&n); err != nil {
		env.t.Fatal(err)
	}
	return n
}

// shippedRecord is the knowledgeShipping object a version serves.
type shippedRecord struct {
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	Via   string    `json:"via"`
	Packs []struct {
		Name   string `json:"name"`
		Origin *struct {
			Kind   string `json:"kind"`
			Org    string `json:"org"`
			PackID string `json:"packId"`
		} `json:"origin"`
	} `json:"packs"`
}

func (env *testEnv) shippedRecordOf(c caller, ns, name, version string) *shippedRecord {
	env.t.Helper()
	var v struct {
		KnowledgeShipping *shippedRecord `json:"knowledgeShipping"`
	}
	env.doJSON(c, http.MethodGet, "/api/v1/agents/"+ns+"/"+name+"/versions/"+version, nil, &v, http.StatusOK)
	return v.KnowledgeShipping
}

// shippingPublisher is a signed-in person with an agent and a publish token.
type shippingPublisher struct {
	handle string
	sess   caller
	pat    string
}

func newShippingPublisher(env *testEnv, prefix, agent, visibility string) shippingPublisher {
	h := env.register(prefix)
	env.verifyEmail(h)
	sess := env.login(h)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": h, "name": agent, "modes": []string{"autonomous"}, "visibility": visibility}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub-"+agent, "agent:publish", "agent:read")
	return shippingPublisher{handle: h, sess: sess, pat: pat}
}

func TestShippingUploadNeedsTheAcknowledgement(t *testing.T) {
	env := newTestEnv(t)
	pub := newShippingPublisher(env, "ksa-pub", "reviewer", "private")
	files := shippingFiles(t, pub.handle, "reviewer", "1.0.0", "aws-docs")

	// No knowledgeShipping part: refused, naming the pack, and nothing is
	// recorded.
	code, body := env.uploadShipping(pub.handle, "reviewer", pub.pat, files, "")
	wantShippingRefusal(t, code, body, "knowledge-shipping-unacknowledged", "aws-docs")
	// An empty confirmation confirms nothing.
	code, body = env.uploadShipping(pub.handle, "reviewer", pub.pat, files, shippingBody())
	wantShippingRefusal(t, code, body, "knowledge-shipping-unacknowledged", "aws-docs")
	if n := env.versionCount(pub.handle, "reviewer"); n != 0 {
		t.Fatalf("a refused upload left %d versions", n)
	}

	// Every shipped pack needs an entry: with two shipped and one
	// confirmed, the other is named.
	two := shippingFiles(t, pub.handle, "reviewer", "1.0.0", "aws-docs", "gcp-docs")
	code, body = env.uploadShipping(pub.handle, "reviewer", pub.pat, two, shippingBody(packEntry("aws-docs", nil)))
	wantShippingRefusal(t, code, body, "knowledge-shipping-unacknowledged", "gcp-docs")

	// Each entry names a pack the release ships, once.
	code, body = env.uploadShipping(pub.handle, "reviewer", pub.pat, files, shippingBody(packEntry("aws-docs", nil), packEntry("other", nil)))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "other")
	code, body = env.uploadShipping(pub.handle, "reviewer", pub.pat, files, shippingBody(packEntry("aws-docs", nil), packEntry("aws-docs", nil)))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")

	// A confirmation that is not the object the API describes is a
	// validation failure.
	for _, bad := range []string{`{"packs": [{"name": "aws-docs", "extra": 1}]}`, `[1]`, `{"packs": [`} {
		if code, body := env.uploadShipping(pub.handle, "reviewer", pub.pat, files, bad); code != http.StatusUnprocessableEntity || !strings.Contains(strings.ToLower(body), "knowledgeshipping") {
			t.Errorf("confirmation %q: %d %s", bad, code, body)
		}
	}
	if n := env.versionCount(pub.handle, "reviewer"); n != 0 {
		t.Fatalf("refused uploads left %d versions", n)
	}
}

func TestAcknowledgedShippingIsRecorded(t *testing.T) {
	env := newTestEnv(t)
	pub := newShippingPublisher(env, "ksr-pub", "reviewer", "public")
	files := shippingFiles(t, pub.handle, "reviewer", "1.0.0", "aws-docs")

	code, body := env.uploadShipping(pub.handle, "reviewer", pub.pat, files, shippingBody(packEntry("aws-docs", nil)))
	if code != http.StatusAccepted {
		t.Fatalf("acknowledged upload: %d %s", code, body)
	}
	// The publish token does not manage the agent, so its response carries
	// no record; the manager's reads do.
	if strings.Contains(body, "knowledgeShipping") {
		t.Fatalf("a publish token is served the record: %s", body)
	}

	rec := env.shippedRecordOf(pub.sess, pub.handle, "reviewer", "1.0.0")
	if rec == nil || rec.Via != "client" || rec.By != pub.handle || time.Since(rec.At) > time.Minute || len(rec.Packs) != 1 || rec.Packs[0].Name != "aws-docs" || rec.Packs[0].Origin != nil {
		t.Fatalf("record = %+v", rec)
	}
	var list []struct {
		Version           string         `json:"version"`
		KnowledgeShipping *shippedRecord `json:"knowledgeShipping"`
	}
	env.doJSON(pub.sess, http.MethodGet, "/api/v1/agents/"+pub.handle+"/reviewer/versions", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].KnowledgeShipping == nil || list[0].KnowledgeShipping.Via != "client" {
		t.Fatalf("version list = %+v", list)
	}

	// Whoever only reads the agent, or publishes to it, does not get the
	// record: it names an account and the stored packs the release came from.
	reader := env.register("ksr-reader")
	env.verifyEmail(reader)
	readerS := env.login(reader)
	if rec := env.shippedRecordOf(anonymous, pub.handle, "reviewer", "1.0.0"); rec != nil {
		t.Errorf("anonymous reads the record: %+v", rec)
	}
	if rec := env.shippedRecordOf(readerS, pub.handle, "reviewer", "1.0.0"); rec != nil {
		t.Errorf("a signed-in reader reads the record: %+v", rec)
	}
	env.doJSON(pub.sess, http.MethodPut, "/api/v1/agents/"+pub.handle+"/reviewer/grants/user/"+reader, map[string]any{"role": "publish"}, nil, http.StatusNoContent)
	if rec := env.shippedRecordOf(readerS, pub.handle, "reviewer", "1.0.0"); rec != nil {
		t.Errorf("a publisher who does not manage the agent reads the record: %+v", rec)
	}
}

func TestAReleaseShippingNothingIsUnaffected(t *testing.T) {
	env := newTestEnv(t)
	pub := newShippingPublisher(env, "ksn-pub", "plain", "public")
	// No confirmation, and an empty one, both accepted; the version has no record.
	for i, ack := range []string{"", shippingBody()} {
		v := []string{"1.0.0", "1.1.0"}[i]
		code, body := env.uploadShipping(pub.handle, "plain", pub.pat, skillFiles(pub.handle, "plain", v, nil), ack)
		if code != http.StatusAccepted {
			t.Fatalf("release %s shipping nothing: %d %s", v, code, body)
		}
		if rec := env.shippedRecordOf(pub.sess, pub.handle, "plain", v); rec != nil {
			t.Errorf("release %s shipping nothing has a record: %+v", v, rec)
		}
	}
	// A confirmation of a pack it does not ship is wrong.
	code, body := env.uploadShipping(pub.handle, "plain", pub.pat, skillFiles(pub.handle, "plain", "1.2.0", nil), shippingBody(packEntry("aws-docs", nil)))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
	// Making it public needs nothing.
	env.doJSON(pub.sess, http.MethodPatch, "/api/v1/agents/"+pub.handle+"/plain", map[string]any{"visibility": "private"}, nil, http.StatusOK)
	env.doJSON(pub.sess, http.MethodPatch, "/api/v1/agents/"+pub.handle+"/plain", map[string]any{"visibility": "public"}, nil, http.StatusOK)
}

// storedPackOfShippedTree is a ready pack of the owner's holding the tree
// shippedPackFiles ships.
func storedPackOfShippedTree(t *testing.T, env *testEnv, o knowledgeOwner, name string) knowledgePackBody {
	t.Helper()
	p, _, _, _ := putPack(t, env, o, name, shippedPackTree())
	drainKnowledgeScans(t, env)
	return p
}

func TestShippedPackOriginIsHeldToTheFacts(t *testing.T) {
	env := newTestEnv(t)
	owner := newKnowledgeOwner(env, "kso-owner")
	other := newKnowledgeOwner(env, "kso-other")
	ownerPub := func(agent string) string {
		env.doJSON(owner.sess, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": owner.handle, "name": agent, "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
		_, pat := env.mintPAT(owner.sess, "pub-"+agent, "agent:publish", "agent:read")
		return pat
	}
	mine := storedPackOfShippedTree(t, env, owner, "aws-docs")
	theirs := storedPackOfShippedTree(t, env, other, "aws-docs")
	// A pack of the owner's whose content differs from what is shipped.
	changedTree := shippedPackTree()
	changedTree[3].Content = []byte("An EC2 instance is a virtual machine, with one edit.\n")
	changed, _, _, _ := putPack(t, env, owner, "changed-docs", changedTree)
	drainKnowledgeScans(t, env)
	// A pack of the owner's whose tree has not finished scanning.
	pending, _, _, _ := putPack(t, env, owner, "pending-docs", shippedPackTree())

	cases := []struct {
		name   string
		origin map[string]any
		ok     bool
	}{
		{"an own pack of the submitter", ownOrigin(mine.ID), true},
		{"no origin: the publisher's own files", nil, true},
		{"another account's pack", ownOrigin(theirs.ID), false},
		{"a pack that does not exist", ownOrigin(uuid.NewString()), false},
		{"a pack still scanning", ownOrigin(pending.ID), false},
		{"a pack whose digest is not the shipped tree's", ownOrigin(changed.ID), false},
		{"an organization pack from a personal namespace", orgOrigin("someorg", mine.ID), false},
		{"an origin of an unknown kind", map[string]any{"kind": "team", "packId": mine.ID}, false},
		{"an own origin that names an organization", map[string]any{"kind": "own", "org": "someorg", "packId": mine.ID}, false},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			agent := "origin" + string(rune('a'+i))
			pat := ownerPub(agent)
			files := shippingFiles(t, owner.handle, agent, "1.0.0", "aws-docs")
			code, body := env.uploadShipping(owner.handle, agent, pat, files, shippingBody(packEntry("aws-docs", c.origin)))
			if c.ok {
				if code != http.StatusAccepted {
					t.Fatalf("%d %s", code, body)
				}
				rec := env.shippedRecordOf(owner.sess, owner.handle, agent, "1.0.0")
				if rec == nil || len(rec.Packs) != 1 || (c.origin != nil) != (rec.Packs[0].Origin != nil) {
					t.Fatalf("record = %+v", rec)
				}
				return
			}
			wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
			if n := env.versionCount(owner.handle, agent); n != 0 {
				t.Fatalf("a wrong claim left %d versions", n)
			}
		})
	}
}

func TestAnOrganizationsPackShipsOnlyFromItsAdminIntoItsNamespace(t *testing.T) {
	env := newTestEnv(t)
	o := newSharedOrg(t, env, "ksg")
	pack, _, _, _ := putSharedPack(t, env, o, "aws-docs", shippedPackTree())
	drainKnowledgeScans(t, env)

	// A second organization the admin does not belong to, and a personal
	// namespace of the admin's own.
	rival := newSharedOrg(t, env, "ksr")
	newAgent := func(c caller, ns, name string) {
		env.doJSON(c, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": ns, "name": name, "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	}
	newAgent(o.admin.sess, o.handle, "handbook")
	newAgent(o.admin.sess, o.admin.handle, "personal")
	newAgent(rival.admin.sess, rival.handle, "elsewhere")
	// The member is made a publisher of the organization's agent, so the
	// refusal below is the origin's and not a missing role.
	env.doJSON(o.admin.sess, http.MethodPut, "/api/v1/agents/"+o.handle+"/handbook/grants/user/"+o.member.handle, map[string]any{"role": "publish"}, nil, http.StatusNoContent)
	_, adminPAT := env.mintPAT(o.admin.sess, "pub", "agent:publish", "agent:read")
	_, memberPAT := env.mintPAT(o.member.sess, "pub", "agent:publish", "agent:read")
	_, adminPATRival := env.mintPAT(rival.admin.sess, "pub", "agent:publish", "agent:read")
	// The rival's admin holds a pack of the same tree in their own organization.
	rivalPack, _, _, _ := putSharedPack(t, env, rival, "aws-docs", shippedPackTree())
	drainKnowledgeScans(t, env)

	ack := func(org string, id string) string {
		return shippingBody(packEntry("aws-docs", orgOrigin(org, id)))
	}
	files := func(ns, name string) map[string]string { return shippingFiles(t, ns, name, "1.0.0", "aws-docs") }

	// The member publishes to the organization's agent but is not an admin.
	code, body := env.uploadShipping(o.handle, "handbook", memberPAT, files(o.handle, "handbook"), ack(o.handle, pack.ID))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
	// The admin cannot ship it into a personal namespace.
	code, body = env.uploadShipping(o.admin.handle, "personal", adminPAT, files(o.admin.handle, "personal"), ack(o.handle, pack.ID))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
	// Nor into another organization's namespace, whose own admin does not
	// administer the pack's organization either.
	code, body = env.uploadShipping(rival.handle, "elsewhere", adminPATRival, files(rival.handle, "elsewhere"), ack(o.handle, pack.ID))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
	// The organization's own admin, in the organization's own namespace,
	// naming another organization as the pack's origin: the record would
	// say a thing that is not so.
	code, body = env.uploadShipping(o.handle, "handbook", adminPAT, files(o.handle, "handbook"), ack(rival.handle, pack.ID))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
	// An organization's pack id under another organization's handle is not a pack.
	code, body = env.uploadShipping(rival.handle, "elsewhere", adminPATRival, files(rival.handle, "elsewhere"), ack(rival.handle, pack.ID))
	wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
	for _, a := range [][2]string{{o.handle, "handbook"}, {o.admin.handle, "personal"}, {rival.handle, "elsewhere"}} {
		if n := env.versionCount(a[0], a[1]); n != 0 {
			t.Fatalf("%s/%s holds %d versions after refusals", a[0], a[1], n)
		}
	}
	if got := orgAuditActions(t, env, o.handle, pack.ID); strings.Contains(strings.Join(got, ","), "org.knowledge_ship") {
		t.Fatalf("a refused upload was audited: %v", got)
	}

	// The admin ships it into the organization's own namespace.
	code, body = env.uploadShipping(o.handle, "handbook", adminPAT, files(o.handle, "handbook"), ack(o.handle, pack.ID))
	if code != http.StatusAccepted {
		t.Fatalf("admin ships the organization's pack: %d %s", code, body)
	}
	rec := env.shippedRecordOf(o.admin.sess, o.handle, "handbook", "1.0.0")
	if rec == nil || rec.Via != "client" || rec.By != o.admin.handle || rec.Packs[0].Origin == nil ||
		rec.Packs[0].Origin.Kind != "org" || rec.Packs[0].Origin.Org != o.handle || rec.Packs[0].Origin.PackID != pack.ID {
		t.Fatalf("record = %+v", rec)
	}
	_ = rivalPack

	// One line in the organization's audit log, naming the pack, the agent,
	// the version and the submitter, and none of the pack's content.
	var detail map[string]any
	var raw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.detail FROM audit_events a JOIN handles h ON h.id = a.org_id
		 WHERE h.handle = $1 AND a.action = 'org.knowledge_ship' AND a.target_id = $2::uuid`, o.handle, pack.ID).Scan(&raw); err != nil {
		t.Fatalf("no org.knowledge_ship event: %v", err)
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["name"] != "aws-docs" || detail["agent"] != o.handle+"/handbook" || detail["version"] != "1.0.0" || detail["submitter"] == "" || detail["submitter"] == nil {
		t.Fatalf("audit detail = %v", detail)
	}
	if strings.Contains(string(raw), "virtual machine") {
		t.Fatalf("the audit detail carries content: %s", raw)
	}
	var events int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'org.knowledge_ship'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("%d org.knowledge_ship events, want 1", events)
	}
	// The organization's admins read it in the organization's audit log.
	res := env.do(o.admin.sess, http.MethodGet, "/api/v1/orgs/"+o.handle+"/audit", nil)
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "org.knowledge_ship") {
		t.Fatalf("organization audit log: %d %s", res.StatusCode, b)
	}
}

func TestOneAuditLinePerOrganizationPack(t *testing.T) {
	env := newTestEnv(t)
	o := newSharedOrg(t, env, "ksp")
	a, _, _, _ := putSharedPack(t, env, o, "aws-docs", shippedPackTree())
	other := []scan.PackFile{
		{Path: "wiki/index.md", Content: []byte("# Index\n\n- [GCP](topics/gcp.md)\n")},
		{Path: "wiki/log.md", Content: []byte("# Log\n")},
		{Path: "wiki/topics/gcp.md", Content: []byte("---\ntitle: GCP\n---\nA VM on GCP. [src: doc:gcp.txt]\n")},
		{Path: "sources/gcp.txt", Content: []byte("A GCP VM.\n")},
	}
	b, _, _, _ := putSharedPack(t, env, o, "gcp-docs", other)
	drainKnowledgeScans(t, env)
	env.doJSON(o.admin.sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": o.handle, "name": "handbook", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(o.admin.sess, "pub", "agent:publish", "agent:read")

	files := shippingFiles(t, o.handle, "handbook", "1.0.0", "aws-docs")
	for k, v := range shippedFilesOf(t, "gcp-docs", other) {
		files[k] = v
	}
	files["agent.yaml"] = strings.Replace(files["agent.yaml"], "    - name: aws-docs\n", "    - name: aws-docs\n    - name: gcp-docs\n", 1)
	ack := shippingBody(packEntry("aws-docs", orgOrigin(o.handle, a.ID)), packEntry("gcp-docs", orgOrigin(o.handle, b.ID)))
	if code, body := env.uploadShipping(o.handle, "handbook", pat, files, ack); code != http.StatusAccepted {
		t.Fatalf("%d %s", code, body)
	}
	for _, id := range []string{a.ID, b.ID} {
		if got := orgAuditActions(t, env, o.handle, id); strings.Count(strings.Join(got, ","), "org.knowledge_ship") != 1 {
			t.Errorf("pack %s audit = %v, want one org.knowledge_ship", id, got)
		}
	}
}

// makePublic is the PATCH that makes ns's reviewer agent public, with the
// acknowledgement when ack is not nil.
func (env *testEnv) makePublic(c caller, ns string, ack *bool) (int, string) {
	env.t.Helper()
	body := map[string]any{"visibility": "public"}
	if ack != nil {
		body["acknowledgeShippedKnowledge"] = *ack
	}
	res := env.do(c, http.MethodPatch, "/api/v1/agents/"+ns+"/reviewer", body)
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

type shippedUnacknowledged struct {
	Type     string `json:"type"`
	Detail   string `json:"detail"`
	Versions []struct {
		Version string   `json:"version"`
		Packs   []string `json:"packs"`
	} `json:"versions"`
}

func TestMakingAnAgentPublicNeedsTheAcknowledgement(t *testing.T) {
	env := newTestEnv(t)
	pub := newShippingPublisher(env, "ksm-pub", "reviewer", "private")
	env.publishVersions(t, pub.sess, pub.handle, "reviewer", []versionFiles{
		{"1.0.0", shippingFiles(t, pub.handle, "reviewer", "1.0.0", "aws-docs")},
		{"1.1.0", shippingFiles(t, pub.handle, "reviewer", "1.1.0", "aws-docs", "gcp-docs")},
	})
	yes, no := true, false

	// Without it: 409, naming the packs and the versions that ship them.
	for _, ack := range []*bool{nil, &no} {
		code, body := env.makePublic(pub.sess, pub.handle, ack)
		var p shippedUnacknowledged
		_ = json.Unmarshal([]byte(body), &p)
		if code != http.StatusConflict || !strings.HasSuffix(p.Type, "/shipped-knowledge-unacknowledged") {
			t.Fatalf("make public without the acknowledgement: %d %s", code, body)
		}
		if len(p.Versions) != 2 || p.Versions[0].Version != "1.0.0" || strings.Join(p.Versions[0].Packs, ",") != "aws-docs" ||
			p.Versions[1].Version != "1.1.0" || strings.Join(p.Versions[1].Packs, ",") != "aws-docs,gcp-docs" {
			t.Fatalf("versions = %+v", p.Versions)
		}
		for _, w := range []string{"1.0.0", "1.1.0", "aws-docs", "gcp-docs"} {
			if !strings.Contains(p.Detail, w) {
				t.Errorf("detail does not name %q: %s", w, p.Detail)
			}
		}
	}
	var a struct {
		Visibility string `json:"visibility"`
	}
	env.doJSON(pub.sess, http.MethodGet, "/api/v1/agents/"+pub.handle+"/reviewer", nil, &a, http.StatusOK)
	if a.Visibility != "private" {
		t.Fatalf("a refused request made the agent %s", a.Visibility)
	}

	// A token that holds only agent:manage may send the visibility with the
	// acknowledgement: the acknowledgement is not another setting.
	_, manage := env.mintPAT(pub.sess, "manage", "agent:manage", "agent:read")
	if code, body := env.makePublic(caller{pat: manage}, pub.handle, &yes); code != http.StatusOK {
		t.Fatalf("make public with the acknowledgement: %d %s", code, body)
	}
	env.doJSON(pub.sess, http.MethodGet, "/api/v1/agents/"+pub.handle+"/reviewer", nil, &a, http.StatusOK)
	if a.Visibility != "public" {
		t.Fatalf("visibility = %s", a.Visibility)
	}
	// The acknowledgement is on the record.
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'agent.update' AND detail->>'acknowledgedShippedKnowledge' = 'true' AND actor_id = (SELECT id FROM handles WHERE handle = $1)`, pub.handle).Scan(&n); err != nil || n != 1 {
		t.Fatalf("acknowledged updates audited: %d, %v", n, err)
	}

	// Private again, and public again: the packs are still shipped, so it asks again.
	env.doJSON(pub.sess, http.MethodPatch, "/api/v1/agents/"+pub.handle+"/reviewer", map[string]any{"visibility": "private"}, nil, http.StatusOK)
	if code, _ := env.makePublic(pub.sess, pub.handle, nil); code != http.StatusConflict {
		t.Fatalf("second time round: %d", code)
	}
}

func TestAYankedVersionDoesNotHoldMakePublic(t *testing.T) {
	env := newTestEnv(t)
	pub := newShippingPublisher(env, "ksy-pub", "reviewer", "private")
	env.publishVersions(t, pub.sess, pub.handle, "reviewer", []versionFiles{
		{"1.0.0", shippingFiles(t, pub.handle, "reviewer", "1.0.0", "aws-docs")},
		{"1.1.0", shippingFiles(t, pub.handle, "reviewer", "1.1.0")},
	})
	if code, _ := env.makePublic(pub.sess, pub.handle, nil); code != http.StatusConflict {
		t.Fatalf("a published version ships a pack: %d", code)
	}
	env.doJSON(pub.sess, http.MethodPost, "/api/v1/agents/"+pub.handle+"/reviewer/versions/1.0.0/yank", map[string]any{"reason": "no longer shipped"}, nil, http.StatusNoContent)
	if code, body := env.makePublic(pub.sess, pub.handle, nil); code != http.StatusOK {
		t.Fatalf("after the only shipping version is yanked: %d %s", code, body)
	}
}

// TestMakePublicIsDecidedAgainUnderTheRowLock: a version that ships a pack
// lands while the request waits for the agent's row, and the request that
// passed the check before it still refuses.
func TestMakePublicIsDecidedAgainUnderTheRowLock(t *testing.T) {
	env := newTestEnv(t)
	pub := newShippingPublisher(env, "ksl-pub", "reviewer", "private")
	env.publishVersions(t, pub.sess, pub.handle, "reviewer", []versionFiles{{"1.0.0", shippingFiles(t, pub.handle, "reviewer", "1.0.0")}})

	ctx := context.Background()
	tx, err := env.st.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var agentID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'reviewer' FOR UPDATE`, pub.handle).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var code int
	var body string
	wg.Add(1)
	go func() {
		defer wg.Done()
		code, body = env.makePublic(pub.sess, pub.handle, nil)
	}()
	// The request reads the agent and its versions, finds nothing shipped,
	// and waits on the row lock we hold.
	time.Sleep(500 * time.Millisecond)
	if _, err := tx.Exec(ctx,
		`INSERT INTO agent_versions (id, agent_id, version, manifest, capabilities, channel, submitted_by, source)
		 SELECT gen_random_uuid(), $1, '9.9.9', '{}', '{"knowledge":["aws-docs"]}', 'stable', u.id, 'cli-upload' FROM handles u WHERE u.handle = $2`, agentID, pub.handle); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if code != http.StatusConflict || !strings.Contains(body, "shipped-knowledge-unacknowledged") || !strings.Contains(body, "9.9.9") {
		t.Fatalf("make public across a version landing under the lock: %d %s", code, body)
	}
}

// TestAForksFirstVersionRecordsThatItWasCopied: the fork's copy of a
// release that ships a pack was neither confirmed in a client nor pushed
// as a tag, and its record says so.
func TestAForksFirstVersionRecordsThatItWasCopied(t *testing.T) {
	env := newForkEnv(t)
	alice := newShippingPublisher(env.testEnv, "ksf-alice", "reviewer", "public")
	env.publishVersions(t, alice.sess, alice.handle, "reviewer", []versionFiles{
		{"1.0.0", shippingFiles(t, alice.handle, "reviewer", "1.0.0", "aws-docs")},
	})
	bob := env.register("ksf-bob")
	env.verifyEmail(bob)
	bobS := env.login(bob)
	env.fork(bobS, alice.handle, "reviewer", map[string]any{"namespace": bob})
	env.runCopies()

	rec := env.shippedRecordOf(bobS, bob, "reviewer", "1.0.0")
	if rec == nil || rec.Via != "fork" || rec.By != "" || len(rec.Packs) != 1 || rec.Packs[0].Name != "aws-docs" {
		t.Fatalf("the fork's record = %+v", rec)
	}
}

// TestAnotherAccountsPackAnswersAsAMissingOne: a pack id that belongs to
// someone else and one that does not exist are refused in the same words,
// so a claim cannot be used to find out which ids are real.
func TestAnotherAccountsPackAnswersAsAMissingOne(t *testing.T) {
	env := newTestEnv(t)
	owner := newKnowledgeOwner(env, "ksq-owner")
	other := newKnowledgeOwner(env, "ksq-other")
	theirs := storedPackOfShippedTree(t, env, other, "aws-docs")
	env.doJSON(owner.sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": owner.handle, "name": "probe", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(owner.sess, "pub", "agent:publish", "agent:read")
	files := shippingFiles(t, owner.handle, "probe", "1.0.0", "aws-docs")

	detail := func(id string) string {
		code, body := env.uploadShipping(owner.handle, "probe", pat, files, shippingBody(packEntry("aws-docs", ownOrigin(id))))
		wantShippingRefusal(t, code, body, "knowledge-shipping-invalid", "aws-docs")
		var p shippingProblem
		_ = json.Unmarshal([]byte(body), &p)
		return p.Detail
	}
	if a, b := detail(theirs.ID), detail(uuid.NewString()); a != b {
		t.Fatalf("a real foreign pack and a missing one are told apart:\n%s\n%s", a, b)
	}
}

// TestAVersionsShippingRecordCannotBeChanged: the confirmation is part of
// what a version is, so the table refuses to rewrite it once the version
// has left submitted.
func TestAVersionsShippingRecordCannotBeChanged(t *testing.T) {
	env := newTestEnv(t)
	pub := newShippingPublisher(env, "ksi-pub", "reviewer", "private")
	env.publishVersions(t, pub.sess, pub.handle, "reviewer", []versionFiles{
		{"1.0.0", shippingFiles(t, pub.handle, "reviewer", "1.0.0", "aws-docs")},
	})
	_, err := env.st.Pool().Exec(context.Background(),
		`UPDATE agent_versions SET knowledge_shipping = '{"via":"client","packs":[]}'::jsonb
		 WHERE agent_id = (SELECT a.id FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'reviewer')`, pub.handle)
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("rewriting a published version's record: %v", err)
	}
}

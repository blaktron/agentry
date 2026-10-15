package api_test

// Account installs: the
// per-account record of a QuickAgent release a person accepted and the
// contract they consented to, behind GET/PUT/DELETE /user/installs.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// installCapsFiles is skillFiles with a capability block: egress to the
// hosts given, and the secrets named. Exact hosts publish without review;
// only a wildcard would route to a reviewer.
func installCapsFiles(ns, name, version string, egress, secrets []string) map[string]string {
	files := skillFiles(ns, name, version, nil)
	caps := "capabilities:\n"
	if len(egress) > 0 {
		caps += "  network:\n    egress: [" + strings.Join(egress, ", ") + "]\n"
	}
	if len(secrets) > 0 {
		caps += "  secrets: [" + strings.Join(secrets, ", ") + "]\n"
	}
	files["agent.yaml"] = strings.Replace(files["agent.yaml"], "entrypoints:\n", caps+"entrypoints:\n", 1)
	return files
}

// versionFiles is one release to publish, in order.
type versionFiles struct {
	version string
	files   map[string]string
}

// publishVersions publishes each release of ns/name through the pipeline as
// the author, in order. A release the gate sends to review — a widened
// contract is one, S9 flags it — is approved by a platform reviewer, as it
// would be; the status is read as the author, so a private QuickAgent's
// publish is seen too.
func (env *testEnv) publishVersions(t *testing.T, author caller, ns, name string, releases []versionFiles) {
	t.Helper()
	_, pat := env.mintPAT(author, "pub-"+name+"-"+env.sfx, "agent:publish", "agent:read")
	status := func(v string) string {
		var out struct {
			Status string `json:"status"`
		}
		res := env.do(author, http.MethodGet, "/api/v1/agents/"+ns+"/"+name+"/versions/"+v, nil)
		_ = json.NewDecoder(res.Body).Decode(&out)
		_ = res.Body.Close()
		return out.Status
	}
	settle := func(v string) string {
		for i := 0; i < 500; i++ {
			switch st := status(v); st {
			case "published", "needs_review", "rejected":
				return st
			}
			sleep10ms()
		}
		t.Fatalf("%s/%s@%s did not settle", ns, name, v)
		return ""
	}
	for _, rel := range releases {
		if code, body := env.uploadVersionCLI(ns, name, pat, rel.files); code != http.StatusAccepted {
			t.Fatalf("publish %s/%s %s: %d %s", ns, name, rel.version, code, body)
		}
		switch st := settle(rel.version); st {
		case "published":
		case "needs_review":
			env.approveAsReviewer(t, ns, rel.version)
			if st := settle(rel.version); st != "published" {
				t.Fatalf("%s/%s@%s after approval: %s", ns, name, rel.version, st)
			}
		default:
			t.Fatalf("%s/%s@%s: %s", ns, name, rel.version, st)
		}
	}
}

// approveAsReviewer approves the pending platform review item for a
// version in a personal namespace, as a platform reviewer who is not its
// author.
func (env *testEnv) approveAsReviewer(t *testing.T, ns, version string) {
	t.Helper()
	staffH := env.register("ai-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	var queue []struct {
		Id        string `json:"id"`
		Namespace string `json:"namespace"`
		Version   string `json:"version"`
	}
	env.doJSON(staff, http.MethodGet, "/api/v1/review-queue?queue=platform&limit=100", nil, &queue, http.StatusOK)
	for _, it := range queue {
		if it.Namespace == ns && it.Version == version {
			env.doJSON(staff, http.MethodPost, "/api/v1/review-items/"+it.Id+"/decision",
				map[string]any{"decision": "approve", "rationale": "the widening is what the release says it is"}, nil, http.StatusNoContent)
			return
		}
	}
	t.Fatalf("no pending platform review item for %s@%s", ns, version)
}

// accountInstall is the wire shape read back by the tests.
type accountInstall struct {
	Ref               string          `json:"ref"`
	Readable          bool            `json:"readable"`
	InstalledVersion  *string         `json:"installedVersion"`
	Capabilities      map[string]any  `json:"capabilities"`
	AcceptedUnsigned  *bool           `json:"acceptedUnsigned"`
	AcceptedUnscanned *bool           `json:"acceptedUnscanned"`
	LatestVersion     *string         `json:"latestVersion"`
	Verdict           *string         `json:"verdict"`
	FindingCounts     map[string]int  `json:"findingCounts"`
	Signed            *bool           `json:"signed"`
	QuarantineState   *string         `json:"quarantineState"`
	InstalledAt       *string         `json:"installedAt"`
	UpdatedAt         *string         `json:"updatedAt"`
	raw               json.RawMessage // the body, for the bare-ref assertion
}

// installProblem is the consent refusal's body.
type installProblem struct {
	Type    string   `json:"type"`
	Status  int      `json:"status"`
	Missing []string `json:"missing"`
	Widened []string `json:"widened"`
}

func (env *testEnv) putInstall(t *testing.T, c caller, ref string, body map[string]any) (int, accountInstall, installProblem) {
	t.Helper()
	res := env.do(c, http.MethodPut, "/api/v1/user/installs/"+ref, body)
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	var rec accountInstall
	var prob installProblem
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatalf("decode record: %v (%s)", err, raw)
		}
		rec.raw = raw
	} else {
		_ = json.Unmarshal(raw, &prob)
	}
	return res.StatusCode, rec, prob
}

func (env *testEnv) listInstalls(t *testing.T, c caller) []accountInstall {
	t.Helper()
	var out []accountInstall
	env.doJSON(c, http.MethodGet, "/api/v1/user/installs", nil, &out, http.StatusOK)
	return out
}

func (env *testEnv) activityActions(t *testing.T, c caller) []string {
	t.Helper()
	var page struct {
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	env.doJSON(c, http.MethodGet, "/api/v1/user/activity", nil, &page, http.StatusOK)
	actions := make([]string, 0, len(page.Events))
	for _, e := range page.Events {
		actions = append(actions, e.Action)
	}
	return actions
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// The release's acceptances are asked for, and the record is composed for
// the list once given: the declared capabilities always on a first
// install; the record carries the version, the snapshot, the verdict with
// its counts, the attestation and the latest version; an outsider's list
// is empty; the action is audited as agent.install.
func TestAccountInstallNeedsTheReleasesAcceptances(t *testing.T) {
	env := newTestEnv(t)
	authorH := env.register("ai-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "keeper", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, author, authorH, "keeper", []versionFiles{
		{"1.0.0", installCapsFiles(authorH, "keeper", "1.0.0", []string{"api.example"}, nil)},
	})
	personH := env.register("ai-person")
	env.verifyEmail(personH)
	person := env.login(personH)
	ref := authorH + "/keeper"

	// The capabilities are the acceptance every release needs.
	code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0"})
	if code != http.StatusConflict || !strings.HasSuffix(prob.Type, "/install-consent-required") || !reflect.DeepEqual(prob.Missing, []string{"capabilities"}) {
		t.Fatalf("PUT without acceptCapabilities: %d %+v, want 409 install-consent-required missing [capabilities]", code, prob)
	}
	if len(env.listInstalls(t, person)) != 0 {
		t.Fatal("a refused PUT recorded something")
	}

	code, rec, _ := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true})
	if code != http.StatusOK {
		t.Fatalf("PUT with the acceptance: %d", code)
	}
	check := func(rec accountInstall) {
		t.Helper()
		if rec.Ref != ref || !rec.Readable || deref(rec.InstalledVersion) != "1.0.0" || deref(rec.LatestVersion) != "1.0.0" {
			t.Fatalf("record = %s", rec.raw)
		}
		net, _ := rec.Capabilities["network"].(map[string]any)
		if eg, _ := net["egress"].([]any); len(eg) != 1 || eg[0] != "api.example" {
			t.Fatalf("the snapshot is not the release's declared block: %v", rec.Capabilities)
		}
		if rec.AcceptedUnsigned == nil || *rec.AcceptedUnsigned || rec.AcceptedUnscanned == nil || *rec.AcceptedUnscanned {
			t.Fatalf("consents the release did not need are recorded as given: %s", rec.raw)
		}
		// The dev signer signs every publish, and the static scanner ran.
		if rec.Signed == nil || !*rec.Signed || deref(rec.Verdict) != "scanned" || rec.FindingCounts == nil {
			t.Fatalf("composition: signed=%v verdict=%s counts=%v", rec.Signed, deref(rec.Verdict), rec.FindingCounts)
		}
		if deref(rec.QuarantineState) != "none" || rec.InstalledAt == nil || rec.UpdatedAt == nil {
			t.Fatalf("composition: %s", rec.raw)
		}
	}
	check(rec)
	list := env.listInstalls(t, person)
	if len(list) != 1 {
		t.Fatalf("list = %d records, want 1", len(list))
	}
	check(list[0])

	// Someone else's list is their own.
	outsiderH := env.register("ai-outsider")
	env.verifyEmail(outsiderH)
	if got := env.listInstalls(t, env.login(outsiderH)); len(got) != 0 {
		t.Fatalf("an outsider's list = %d records", len(got))
	}

	// Audited beside agent.star, so the person's activity shows it — and
	// the QuickAgent's own feed does not, to its author either: whose
	// account holds it is the person's business.
	actions := env.activityActions(t, person)
	found := false
	for _, a := range actions {
		found = found || a == "agent.install"
	}
	if !found {
		t.Fatalf("activity = %v, want agent.install", actions)
	}
	var feed struct {
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	env.doJSON(author, http.MethodGet, "/api/v1/agents/"+ref+"/activity", nil, &feed, http.StatusOK)
	for _, e := range feed.Events {
		if e.Action == "agent.install" {
			t.Fatalf("the QuickAgent's feed shows the install to its author: %+v", feed.Events)
		}
	}
}

// An update re-asks for the capability acceptance only when the new
// version's declared capabilities widened against the accepted snapshot;
// the record's version moves; DELETE removes it, idempotently, and is
// audited once as agent.uninstall.
func TestAccountInstallUpdateReasksOnlyWhenWidened(t *testing.T) {
	env := newTestEnv(t)
	authorH := env.register("au-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "grower", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, author, authorH, "grower", []versionFiles{
		{"1.0.0", installCapsFiles(authorH, "grower", "1.0.0", []string{"api.example"}, nil)},
		{"1.1.0", installCapsFiles(authorH, "grower", "1.1.0", []string{"api.example"}, nil)},
		{"2.0.0", installCapsFiles(authorH, "grower", "2.0.0", []string{"api.example", "other.example"}, []string{"OTHER_TOKEN"})},
	})
	personH := env.register("au-person")
	env.verifyEmail(personH)
	person := env.login(personH)
	ref := authorH + "/grower"

	code, first, _ := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true})
	if code != http.StatusOK {
		t.Fatalf("first install: %d", code)
	}
	if deref(first.LatestVersion) != "2.0.0" {
		t.Fatalf("latest = %s, want 2.0.0 (the newest published)", deref(first.LatestVersion))
	}

	// The same contract: no question asked.
	code, rec, _ := env.putInstall(t, person, ref, map[string]any{"version": "1.1.0"})
	if code != http.StatusOK || deref(rec.InstalledVersion) != "1.1.0" {
		t.Fatalf("update to an unchanged contract without acceptCapabilities: %d %s", code, rec.raw)
	}

	// A widened one: refused, naming what widened; the record stays.
	code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "2.0.0"})
	if code != http.StatusConflict || !reflect.DeepEqual(prob.Missing, []string{"capabilities"}) {
		t.Fatalf("update to a widened contract without acceptCapabilities: %d %+v", code, prob)
	}
	if !reflect.DeepEqual(prob.Widened, []string{"adds network egress to other.example", "asks for a new secret: OTHER_TOKEN"}) {
		t.Fatalf("widened = %v", prob.Widened)
	}
	if got := env.listInstalls(t, person); len(got) != 1 || deref(got[0].InstalledVersion) != "1.1.0" {
		t.Fatalf("a refused update moved the record: %+v", got)
	}

	code, rec, _ = env.putInstall(t, person, ref, map[string]any{"version": "2.0.0", "acceptCapabilities": true})
	if code != http.StatusOK || deref(rec.InstalledVersion) != "2.0.0" || deref(rec.LatestVersion) != "2.0.0" {
		t.Fatalf("accepted update: %d %s", code, rec.raw)
	}
	if deref(rec.InstalledAt) != deref(first.InstalledAt) || deref(rec.UpdatedAt) == deref(first.UpdatedAt) {
		t.Fatalf("an update keeps installedAt and moves updatedAt: first %s / %s, now %s / %s",
			deref(first.InstalledAt), deref(first.UpdatedAt), deref(rec.InstalledAt), deref(rec.UpdatedAt))
	}
	if secrets, _ := rec.Capabilities["secrets"].([]any); len(secrets) != 1 {
		t.Fatalf("the snapshot did not follow the version: %v", rec.Capabilities)
	}

	// A version that is not a published release, and one that does not
	// exist.
	code, _, prob = env.putInstall(t, person, ref, map[string]any{"version": "3.0.0", "acceptCapabilities": true})
	if code != http.StatusNotFound {
		t.Fatalf("a version that does not exist: %d %+v", code, prob)
	}

	for i := 0; i < 2; i++ {
		res := env.do(person, http.MethodDelete, "/api/v1/user/installs/"+ref, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE #%d: %d", i+1, res.StatusCode)
		}
	}
	if got := env.listInstalls(t, person); len(got) != 0 {
		t.Fatalf("after DELETE the list = %+v", got)
	}
	uninstalls := 0
	for _, a := range env.activityActions(t, person) {
		if a == "agent.uninstall" {
			uninstalls++
		}
	}
	if uninstalls != 1 {
		t.Fatalf("agent.uninstall audited %d times, want once (the second DELETE removed nothing)", uninstalls)
	}
}

// Unsigned and unscanned are their own consents: asked whenever the release
// needs them, on an update too, and recorded as given.
func TestAccountInstallUnsignedAndUnscannedConsents(t *testing.T) {
	env := newTestEnvWith(t, onTier(unscannedOn(true)))
	adminH := env.register("ac-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "acorg" + env.sfx
	env.createOrg(admin, orgH)

	// A version that predates signing: its attestation row is gone.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "elder", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, admin, orgH, "elder", []versionFiles{
		{"1.0.0", skillFiles(orgH, "elder", "1.0.0", nil)},
	})
	if _, err := env.st.Pool().Exec(context.Background(),
		`DELETE FROM attestations WHERE version_id = (SELECT av.id FROM agent_versions av JOIN agents a ON a.id = av.agent_id
		   JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = 'elder' AND av.version = '1.0.0')`, orgH); err != nil {
		t.Fatal(err)
	}
	code, _, prob := env.putInstall(t, admin, orgH+"/elder", map[string]any{"version": "1.0.0", "acceptCapabilities": true})
	if code != http.StatusConflict || !reflect.DeepEqual(prob.Missing, []string{"unsigned"}) {
		t.Fatalf("an unsigned release without acceptUnsigned: %d %+v", code, prob)
	}
	code, rec, _ := env.putInstall(t, admin, orgH+"/elder", map[string]any{"version": "1.0.0", "acceptCapabilities": true, "acceptUnsigned": true})
	if code != http.StatusOK || rec.Signed == nil || *rec.Signed || rec.AcceptedUnsigned == nil || !*rec.AcceptedUnsigned || deref(rec.Verdict) != "scanned" {
		t.Fatalf("an unsigned release accepted: %d %s", code, rec.raw)
	}

	// A version admitted without a scan: no report, no attestation; both
	// consents, each its own.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "quiet", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/quiet", map[string]any{"pipelineSkip": true}, nil, http.StatusOK)
	env.publishVersions(t, admin, orgH, "quiet", []versionFiles{
		{"1.0.0", skillFiles(orgH, "quiet", "1.0.0", nil)},
	})
	code, _, prob = env.putInstall(t, admin, orgH+"/quiet", map[string]any{"version": "1.0.0", "acceptCapabilities": true, "acceptUnsigned": true})
	if code != http.StatusConflict || !reflect.DeepEqual(prob.Missing, []string{"unscanned"}) {
		t.Fatalf("an unscanned release with acceptUnsigned only: %d %+v", code, prob)
	}
	code, _, prob = env.putInstall(t, admin, orgH+"/quiet", map[string]any{"version": "1.0.0", "acceptCapabilities": true})
	if code != http.StatusConflict || !reflect.DeepEqual(prob.Missing, []string{"unsigned", "unscanned"}) {
		t.Fatalf("an unscanned release with neither: %d %+v", code, prob)
	}
	code, rec, _ = env.putInstall(t, admin, orgH+"/quiet", map[string]any{"version": "1.0.0", "acceptCapabilities": true, "acceptUnsigned": true, "acceptUnscanned": true})
	if code != http.StatusOK || deref(rec.Verdict) != "unscanned" || rec.FindingCounts != nil || rec.Signed == nil || *rec.Signed ||
		rec.AcceptedUnscanned == nil || !*rec.AcceptedUnscanned || rec.AcceptedUnsigned == nil || !*rec.AcceptedUnsigned {
		t.Fatalf("an unscanned release accepted: %d %s", code, rec.raw)
	}
}

// The private-agent rule holds for the install routes: a
// PUT by a non-reader answers exactly what a missing name answers; a
// record whose QuickAgent the caller can no longer read is listed as the
// bare ref with readable: false and nothing else, under the ref stored
// when they installed it; and DELETE, which reads no QuickAgent, removes
// it by that ref and answers 204 whatever the name is.
func TestAccountInstallInvisibleToNonReaders(t *testing.T) {
	env := newTestEnv(t)
	ownerH := env.register("ap-owner")
	env.verifyEmail(ownerH)
	owner := env.login(ownerH)
	env.doJSON(owner, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": ownerH, "name": "secret", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, owner, ownerH, "secret", []versionFiles{
		{"1.0.0", skillFiles(ownerH, "secret", "1.0.0", nil)},
	})
	strangerH := env.register("ap-stranger")
	env.verifyEmail(strangerH)
	stranger := env.login(strangerH)
	ref := ownerH + "/secret"

	// Installed while public.
	if code, _, _ := env.putInstall(t, stranger, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("install while public: %d", code)
	}
	// Then made private: the stranger is a non-reader now.
	env.doJSON(owner, http.MethodPatch, "/api/v1/agents/"+ref, map[string]any{"visibility": "private"}, nil, http.StatusOK)

	problem := func(c caller, method, path string, body any) (int, map[string]any) {
		res := env.do(c, method, path, body)
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		var doc map[string]any
		_ = json.Unmarshal(b, &doc)
		delete(doc, "instance")
		return res.StatusCode, doc
	}
	missingStatus, missingBody := problem(stranger, http.MethodPut, "/api/v1/user/installs/"+ownerH+"/no-such-agent",
		map[string]any{"version": "1.0.0", "acceptCapabilities": true})
	if missingStatus != http.StatusNotFound {
		t.Fatalf("missing agent: got %d", missingStatus)
	}
	for _, c := range []struct {
		name string
		c    caller
	}{{"anonymous", anonymous}, {"stranger", stranger}} {
		st, body := problem(c.c, http.MethodPut, "/api/v1/user/installs/"+ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true})
		if st != http.StatusNotFound || !reflect.DeepEqual(body, missingBody) {
			t.Fatalf("%s PUT private: %d %v, want the missing agent's 404 %v", c.name, st, body, missingBody)
		}
	}
	// A public name keeps the conventional answer for an anonymous write.
	if st, _ := problem(anonymous, http.MethodPut, "/api/v1/user/installs/"+ownerH+"/no-such-agent", map[string]any{"version": "1.0.0"}); st != http.StatusNotFound {
		t.Fatalf("anonymous PUT on a missing name: %d, want 404", st)
	}
	// DELETE reads no QuickAgent: 401 anonymous whatever the name, 204 for
	// a signed-in caller whether the name is private, public or nobody's.
	for _, path := range []string{ref, ownerH + "/no-such-agent"} {
		if st, _ := problem(anonymous, http.MethodDelete, "/api/v1/user/installs/"+path, nil); st != http.StatusUnauthorized {
			t.Fatalf("anonymous DELETE %s: %d, want 401", path, st)
		}
	}
	if st, _ := problem(stranger, http.MethodDelete, "/api/v1/user/installs/"+ownerH+"/no-such-agent", nil); st != http.StatusNoContent {
		t.Fatalf("DELETE of a name that is nobody's: %d, want 204", st)
	}

	// The record is still theirs, as the bare ref, and nothing more.
	res := env.do(stranger, http.MethodGet, "/api/v1/user/installs", nil)
	var rows []map[string]any
	if err := json.NewDecoder(res.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if len(rows) != 1 || !reflect.DeepEqual(rows[0], map[string]any{"ref": ref, "readable": false}) {
		t.Fatalf("a former reader is told more than the ref: %v", rows)
	}
	if got := env.listInstalls(t, owner); len(got) != 0 {
		t.Fatalf("owner's list = %+v", got)
	}

	// Public again: composed again, under the name it lives at.
	env.doJSON(owner, http.MethodPatch, "/api/v1/agents/"+ref, map[string]any{"visibility": "public"}, nil, http.StatusOK)
	if list := env.listInstalls(t, stranger); len(list) != 1 || !list[0].Readable || deref(list[0].InstalledVersion) != "1.0.0" {
		t.Fatalf("readable again: %+v", list)
	}

	// A QuickAgent that moved since — an erasure's transfer into an
	// organization, say — is listed under the ref stored at install time
	// while the caller cannot read it, never under where it went, and is
	// removed by that ref. Simulated by re-homing the stored ref: the
	// row's current name resolves to nothing for the caller.
	env.doJSON(owner, http.MethodPatch, "/api/v1/agents/"+ref, map[string]any{"visibility": "private"}, nil, http.StatusOK)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE account_installs SET ref_namespace = $1, ref_name = 'as-it-was' WHERE ref_name = 'secret' AND ref_namespace = $1`, ownerH); err != nil {
		t.Fatal(err)
	}
	if list := env.listInstalls(t, stranger); len(list) != 1 || list[0].Ref != ownerH+"/as-it-was" || list[0].Readable {
		t.Fatalf("a moved QuickAgent's record: %+v, want the stored ref, unreadable", list)
	}
	if st, _ := problem(stranger, http.MethodDelete, "/api/v1/user/installs/"+ownerH+"/as-it-was", nil); st != http.StatusNoContent {
		t.Fatalf("DELETE by the stored ref: %d, want 204", st)
	}
	if got := env.listInstalls(t, stranger); len(got) != 0 {
		t.Fatalf("after DELETE by the stored ref: %+v", got)
	}
	uninstalls := 0
	for _, a := range env.activityActions(t, stranger) {
		if a == "agent.uninstall" {
			uninstalls++
		}
	}
	if uninstalls != 1 {
		t.Fatalf("agent.uninstall audited %d times, want once", uninstalls)
	}
}

// A blocked QuickAgent stays readable and the row says so; nothing of it
// can be installed while it is.
func TestAccountInstallListsABlockedQuickAgentAsBlocked(t *testing.T) {
	env := newTestEnv(t)
	authorH := env.register("ab-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "blocked", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, author, authorH, "blocked", []versionFiles{
		{"1.0.0", skillFiles(authorH, "blocked", "1.0.0", nil)},
	})
	personH := env.register("ab-person")
	env.verifyEmail(personH)
	person := env.login(personH)
	ref := authorH + "/blocked"
	if code, _, _ := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("install: %d", code)
	}
	staffH := env.register("ab-staff")
	env.verifyEmail(staffH)
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/agents/"+ref+"/block", map[string]any{"reason": "fixture"}, nil, http.StatusNoContent)

	list := env.listInstalls(t, person)
	if len(list) != 1 || !list[0].Readable || deref(list[0].QuarantineState) != "blocked" || deref(list[0].InstalledVersion) != "1.0.0" {
		t.Fatalf("a blocked QuickAgent's row: %+v, want readable and blocked", list)
	}
	code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true})
	if code != http.StatusGone || !strings.HasSuffix(prob.Type, "/blocked") {
		t.Fatalf("PUT on a blocked QuickAgent: %d %+v, want 410 blocked", code, prob)
	}
}

// An account install touches no verdict and no statistic: installsTotal and
// installs30d stay download rollups.
func TestAccountInstallMovesNoDownloadCounter(t *testing.T) {
	env := newTestEnv(t)
	authorH := env.register("as-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "counted", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	env.publishVersions(t, author, authorH, "counted", []versionFiles{
		{"1.0.0", skillFiles(authorH, "counted", "1.0.0", nil)},
	})
	stats := func() (int64, int64) {
		var out struct {
			InstallsTotal int64 `json:"installsTotal"`
			Installs30d   int64 `json:"installs30d"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+authorH+"/counted/stats", nil, &out, http.StatusOK)
		return out.InstallsTotal, out.Installs30d
	}
	beforeTotal, before30 := stats()
	personH := env.register("as-person")
	env.verifyEmail(personH)
	person := env.login(personH)
	if code, _, _ := env.putInstall(t, person, authorH+"/counted", map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("install: %d", code)
	}
	if code, _, _ := env.putInstall(t, person, authorH+"/counted", map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("re-install: %d", code)
	}
	if afterTotal, after30 := stats(); afterTotal != beforeTotal || after30 != before30 {
		t.Fatalf("installs moved: total %d→%d, 30d %d→%d", beforeTotal, afterTotal, before30, after30)
	}
	var rollups int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM download_stats ds JOIN agents a ON a.id = ds.agent_id WHERE a.name = 'counted'`).Scan(&rollups); err != nil {
		t.Fatal(err)
	}
	if rollups != 0 {
		t.Fatalf("download_stats gained %d rows from account installs", rollups)
	}
}

// Optional secrets: the stored
// contract carries capabilities.optionalSecrets through the account install
// and the version read, and a release that only moves a secret between
// optional and required asks for no capability acceptance again, in either
// direction, because the names and their scoping are unchanged.
func TestAccountInstallOptionalSecretFlipAsksNothing(t *testing.T) {
	env := newTestEnv(t)
	authorH := env.register("ao-author")
	env.verifyEmail(authorH)
	author := env.login(authorH)
	env.doJSON(author, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": authorH, "name": "flipper", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	optional := func(version string) map[string]string {
		files := installCapsFiles(authorH, "flipper", version, []string{"api.example"}, []string{"OTHER_TOKEN"})
		files["agent.yaml"] = strings.Replace(files["agent.yaml"], "  secrets: [OTHER_TOKEN]\n",
			"  secrets: [OTHER_TOKEN]\n  optionalSecrets: [OTHER_TOKEN]\n", 1)
		return files
	}
	env.publishVersions(t, author, authorH, "flipper", []versionFiles{
		{"1.0.0", installCapsFiles(authorH, "flipper", "1.0.0", []string{"api.example"}, []string{"OTHER_TOKEN"})},
		{"1.1.0", optional("1.1.0")},
		{"1.2.0", installCapsFiles(authorH, "flipper", "1.2.0", []string{"api.example"}, []string{"OTHER_TOKEN"})},
	})
	personH := env.register("ao-person")
	env.verifyEmail(personH)
	person := env.login(personH)
	ref := authorH + "/flipper"

	if code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("first install: %d %+v", code, prob)
	}
	code, rec, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.1.0"})
	if code != http.StatusOK || deref(rec.InstalledVersion) != "1.1.0" {
		t.Fatalf("required → optional asked again: %d %+v", code, prob)
	}
	if opt, _ := rec.Capabilities["optionalSecrets"].([]any); len(opt) != 1 || opt[0] != "OTHER_TOKEN" {
		t.Fatalf("the snapshot lost optionalSecrets: %v", rec.Capabilities)
	}
	var v struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	env.doJSON(person, http.MethodGet, "/api/v1/agents/"+ref+"/versions/1.1.0", nil, &v, http.StatusOK)
	if opt, _ := v.Capabilities["optionalSecrets"].([]any); len(opt) != 1 {
		t.Fatalf("the version read lost optionalSecrets: %v", v.Capabilities)
	}
	code, rec, prob = env.putInstall(t, person, ref, map[string]any{"version": "1.2.0"})
	if code != http.StatusOK || deref(rec.InstalledVersion) != "1.2.0" {
		t.Fatalf("optional → required asked again: %d %+v", code, prob)
	}
	if _, has := rec.Capabilities["optionalSecrets"]; has {
		t.Fatalf("the snapshot kept a marking the release dropped: %v", rec.Capabilities)
	}
}

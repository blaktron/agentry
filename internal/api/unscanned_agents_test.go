package api_test

// Unscanned private agents: an organization's administrator may take a
// private agent of the organization's off the pipeline, behind the tier's
// switch; a submission to it is published as submitted — no scan run, no
// findings, no attestation — and served everywhere as unscanned; and the
// agent cannot become public while the flag is set or a version published
// unscanned stands, so the property holds for public content as it
// always did.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// unscannedOn answers the tier as including unscanned agents, or not.
func unscannedOn(on bool) func(*entitlements.Features) {
	return func(f *entitlements.Features) { f.UnscannedAgents = on }
}

func TestPipelineSkipIsRefusedWhereItMustBe(t *testing.T) {
	env := newTestEnvWith(t, onTier(unscannedOn(true)))
	adminH := env.register("us-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "usorg" + env.sfx
	env.createOrg(admin, orgH)
	memberH := env.register("us-member")
	env.verifyEmail(memberH)
	env.seedMembership(orgH, memberH, "member", "active")
	member := env.login(memberH)
	patch := func(c caller, ns, name string, body map[string]any) (int, string) {
		code, slug, _ := problemOf(t, env.do(c, http.MethodPatch, "/api/v1/agents/"+ns+"/"+name, body))
		return code, slug
	}

	// A personal namespace has no organization to answer for what it
	// skips.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": adminH, "name": "mine", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	if code, s := patch(admin, adminH, "mine", map[string]any{"pipelineSkip": true}); code != http.StatusConflict || s != "pipeline-skip-personal" {
		t.Fatalf("a personal agent: %d %s, want 409 pipeline-skip-personal", code, s)
	}

	// A public agent is always scanned — the flag is refused on one, and
	// on a private one the same request makes public.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "open", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	if code, s := patch(admin, orgH, "open", map[string]any{"pipelineSkip": true}); code != http.StatusConflict || s != "pipeline-skip-public" {
		t.Fatalf("a public agent: %d %s, want 409 pipeline-skip-public", code, s)
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "quiet", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	if code, s := patch(admin, orgH, "quiet", map[string]any{"pipelineSkip": true, "visibility": "public"}); code != http.StatusConflict || s != "pipeline-skip-public" {
		t.Fatalf("the flag and public in one request: %d %s, want 409 pipeline-skip-public", code, s)
	}

	// The administrators' act, not a member's.
	if code, _ := patch(member, orgH, "quiet", map[string]any{"pipelineSkip": true}); code != http.StatusForbidden {
		t.Fatalf("a member setting the flag: %d, want 403", code)
	}

	// The tier must include it, and a resolver that cannot answer is a no.
	env.setEntitlements(tierResolverFor(unscannedOn(false)))
	if code, s := patch(admin, orgH, "quiet", map[string]any{"pipelineSkip": true}); code != http.StatusForbidden || s != "feature-not-included" {
		t.Fatalf("a tier without the switch: %d %s, want 403 feature-not-included", code, s)
	}
	env.setEntitlements(brokenTierResolver())
	if code, _ := patch(admin, orgH, "quiet", map[string]any{"pipelineSkip": true}); code != http.StatusInternalServerError {
		t.Fatalf("a resolver that cannot answer: %d, want a refusal, never the flag", code)
	}
	env.setEntitlements(tierResolverFor(unscannedOn(true)))

	// Set: the agent says so to its maintainers.
	var a struct {
		PipelineSkip *bool `json:"pipelineSkip"`
	}
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/quiet", map[string]any{"pipelineSkip": true}, &a, http.StatusOK)
	if a.PipelineSkip == nil || !*a.PipelineSkip {
		t.Fatalf("the flag is not shown set: %+v", a)
	}
	// While set, the agent cannot become public.
	if code, s := patch(admin, orgH, "quiet", map[string]any{"visibility": "public"}); code != http.StatusConflict || s != "agent-unscanned" {
		t.Fatalf("public while flagged: %d %s, want 409 agent-unscanned", code, s)
	}
	// Clearing it is never refused, even where the tier no longer includes it.
	env.setEntitlements(tierResolverFor(unscannedOn(false)))
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/quiet", map[string]any{"pipelineSkip": false}, &a, http.StatusOK)
	if a.PipelineSkip == nil || *a.PipelineSkip {
		t.Fatalf("the flag is not shown cleared: %+v", a)
	}
	if code, _ := patch(admin, orgH, "quiet", map[string]any{"visibility": "public"}); code != http.StatusOK {
		t.Fatalf("public after clearing, with nothing published unscanned: %d, want 200", code)
	}
	// Clearing a flag that is not set is no more refused than clearing one
	// that is, whatever the tier says.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "never-flagged", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	if code, _ := patch(admin, orgH, "never-flagged", map[string]any{"pipelineSkip": false}); code != http.StatusOK {
		t.Fatalf("clearing a flag that is not set, tier without the switch: %d, want 200", code)
	}

	// A version admitted unscanned that still stands keeps the agent from
	// going public in every state it can return to published from, and not
	// once it is yanked or was never published.
	insertSkipped := func(name, status string) {
		t.Helper()
		env.doJSON(admin, http.MethodPost, "/api/v1/agents",
			map[string]any{"namespace": orgH, "name": name, "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO agent_versions (id, agent_id, version, manifest, capabilities, channel, submitted_by, source, status, scan_status)
			 SELECT gen_random_uuid(), a.id, '1.0.0', '{}', '{}', 'stable', (SELECT id FROM handles WHERE handle = $4), 'cli-upload', $3, 'skipped'
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2`, orgH, name, status, adminH); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		status string
		stands bool
	}{{"published", true}, {"quarantined", true}, {"blocked", true}, {"yanked", false}, {"rejected", false}} {
		name := "st-" + tc.status
		insertSkipped(name, tc.status)
		code, slug, _ := problemOf(t, env.do(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/"+name, map[string]any{"visibility": "public"}))
		if tc.stands && (code != http.StatusConflict || slug != "agent-unscanned") {
			t.Fatalf("public with an unscanned version %s: %d %s, want 409 agent-unscanned", tc.status, code, slug)
		}
		if !tc.stands && code != http.StatusOK {
			t.Fatalf("public with an unscanned version %s: %d %s, want 200", tc.status, code, slug)
		}
	}
}

func TestAnUnscannedSubmissionIsPublishedWithoutTheGate(t *testing.T) {
	env := newTestEnvWith(t, onTier(unscannedOn(true)))
	adminH := env.register("uv-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "uvorg" + env.sfx
	orgID := env.createOrg(admin, orgH)
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "internal", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/internal", map[string]any{"pipelineSkip": true}, nil, http.StatusOK)
	// An endpoint subscribed to the publish: the edge is an event like
	// any publish.
	var hook struct {
		Id string `json:"id"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url": "https://example.invalid/hook", "events": []string{"version.published"}}, &hook, http.StatusCreated)
	_, pat := env.mintPAT(admin, "pub", "agent:publish", "agent:read")

	// Submitted, and published as submitted: no scan run anywhere.
	status, body := env.uploadVersionCLI(orgH, "internal", pat, skillFiles(orgH, "internal", "1.0.0", nil))
	if status != http.StatusAccepted {
		t.Fatalf("upload: %d %s", status, body)
	}
	var v struct {
		Id         string  `json:"id"`
		Status     string  `json:"status"`
		ScanStatus *string `json:"scanStatus"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/internal/versions/1.0.0", nil, &v, http.StatusOK)
	if v.Status != "published" || v.ScanStatus == nil || *v.ScanStatus != "skipped" {
		t.Fatalf("version = %+v, want published, scanStatus skipped", v)
	}
	var runs int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM scan_runs WHERE version_id = $1`, v.Id).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("scan runs = %d, want none", runs)
	}
	// The report says what it is: unscanned, its own verdict, no findings
	// — never an empty report a reader could take for a clean one.
	var rep struct {
		VersionStatus string  `json:"versionStatus"`
		ScanStatus    *string `json:"scanStatus"`
		Verdict       *string `json:"verdict"`
		ScanRunId     *string `json:"scanRunId"`
		Findings      []any   `json:"findings"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/internal/versions/1.0.0/report", nil, &rep, http.StatusOK)
	if rep.Verdict == nil || *rep.Verdict != "unscanned" || rep.ScanStatus == nil || *rep.ScanStatus != "skipped" || rep.ScanRunId != nil || len(rep.Findings) != 0 {
		t.Fatalf("report = %+v, want verdict unscanned, scanStatus skipped, no run, no findings", rep)
	}
	// No attestation: nothing to attest.
	env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/internal/versions/1.0.0/attestation", nil, nil, http.StatusNotFound)
	var atts int
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM attestations WHERE version_id = $1`, v.Id).Scan(&atts); err != nil {
		t.Fatal(err)
	}
	if atts != 0 {
		t.Fatalf("attestations = %d, want none", atts)
	}
	// The publish was fanned out as one.
	var deliveries []struct {
		EventType string `json:"eventType"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+hook.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) != 1 || deliveries[0].EventType != "version.published" {
		t.Fatalf("deliveries = %+v, want one version.published", deliveries)
	}
	// The audit trail carries the edge and its reason.
	var reason string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail->>'reason' FROM audit_events WHERE action = 'version.transition' AND target_id = $1 AND detail->>'to' = 'published'`, v.Id).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "unscanned") {
		t.Fatalf("the transition's reason is %q", reason)
	}

	// A scan asked for by name does nothing to it, and the sweeps' reads
	// leave it out.
	sweepsLeaveOut := func(id string) {
		t.Helper()
		q := env.st.Queries()
		rescan, err := q.ListPublishedVersionsForRescan(context.Background(), storegen.ListPublishedVersionsForRescanParams{Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rescan {
			if r.ID.String() == id {
				t.Fatalf("the rescan sweep lists %s", id)
			}
		}
		using, err := q.ListPublishedVersionsUsingMCPServer(context.Background(), storegen.ListPublishedVersionsUsingMCPServerParams{Ecosystem: "npm", Package: "left-pad", Version: "1.0.0"})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range using {
			if r.ID.String() == id {
				t.Fatalf("the MCP sweep lists %s", id)
			}
		}
	}
	pl := env.srvObj.Pipeline()
	if err := pl.Scan(context.Background(), uuid.MustParse(v.Id), "rescan"); err != nil {
		t.Fatalf("a scan asked for on an unscanned version: %v", err)
	}
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM scan_runs WHERE version_id = $1`, v.Id).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("a scan asked for by name ran on an unscanned version")
	}
	q := env.st.Queries()
	rescan, err := q.ListPublishedVersionsForRescan(context.Background(), storegen.ListPublishedVersionsForRescanParams{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rescan {
		if r.ID.String() == v.Id {
			t.Fatal("the rescan sweep lists an unscanned version")
		}
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO agent_version_mcp_servers (version_id, ecosystem, package, version) VALUES ($1, 'npm', 'left-pad', '1.0.0')`, v.Id); err != nil {
		t.Fatal(err)
	}
	using, err := q.ListPublishedVersionsUsingMCPServer(context.Background(), storegen.ListPublishedVersionsUsingMCPServerParams{Ecosystem: "npm", Package: "left-pad", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(using) != 0 {
		t.Fatalf("the MCP sweep lists an unscanned version: %d rows", len(using))
	}
	backfill, err := q.ListPublishedVersionsWithoutAttestation(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range backfill {
		if r.ID.String() == v.Id {
			t.Fatal("the attestation backfill lists an unscanned version")
		}
	}

	// Resolve says how the version was admitted, so a client asks for
	// consent from the field and not from a missing attestation.
	var resolved struct {
		ScanStatus     *string `json:"scanStatus"`
		AttestationUrl *string `json:"attestationUrl"`
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/resolve?ref="+orgH+"/internal@1.0.0", nil, &resolved, http.StatusOK)
	if resolved.ScanStatus == nil || *resolved.ScanStatus != "skipped" || resolved.AttestationUrl != nil {
		t.Fatalf("resolve = %+v, want scanStatus skipped and no attestation", resolved)
	}

	// A person who installs it is asked, by name, for what the release
	// lacks: the scan it never had and the attestation it cannot carry.
	personH := env.register("uv-person")
	env.verifyEmail(personH)
	env.joinOrg(admin, orgH, personH)
	person := env.login(personH)
	ref := orgH + "/internal"
	code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true})
	if code != http.StatusConflict || !strings.HasSuffix(prob.Type, "/install-consent-required") || len(prob.Missing) != 2 ||
		!slices.Contains(prob.Missing, "unscanned") || !slices.Contains(prob.Missing, "unsigned") {
		t.Fatalf("install without the two acceptances: %d %+v, want 409 install-consent-required missing unscanned and unsigned", code, prob)
	}
	if code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true, "acceptUnsigned": true}); code != http.StatusConflict || len(prob.Missing) != 1 || prob.Missing[0] != "unscanned" {
		t.Fatalf("install without the acceptance of the missing scan: %d %+v, want 409 missing unscanned", code, prob)
	}
	if code, _, prob := env.putInstall(t, person, ref, map[string]any{"version": "1.0.0", "acceptCapabilities": true, "acceptUnscanned": true, "acceptUnsigned": true}); code != http.StatusOK {
		t.Fatalf("install with the two acceptances: %d %+v, want 200", code, prob)
	}
	if list := env.listInstalls(t, person); len(list) != 1 || deref(list[0].Verdict) != "unscanned" || list[0].FindingCounts != nil ||
		list[0].AcceptedUnscanned == nil || !*list[0].AcceptedUnscanned || list[0].AcceptedUnsigned == nil || !*list[0].AcceptedUnsigned ||
		list[0].Signed == nil || *list[0].Signed {
		t.Fatalf("the install row of an unscanned release: %+v, want verdict unscanned, both acceptances recorded, no findings, not signed", list)
	}

	// Public is refused while a version admitted unscanned stands, even
	// after the flag is cleared — and quarantined counts as standing: the
	// version is still there, and only a yank ends it.
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/internal", map[string]any{"pipelineSkip": false}, nil, http.StatusOK)
	// The sweeps leave it out on its own account, with the flag gone too.
	sweepsLeaveOut(v.Id)
	res := env.do(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/internal", map[string]any{"visibility": "public"})
	var p struct {
		Type      string `json:"type"`
		Unscanned int    `json:"unscanned"`
	}
	_ = json.NewDecoder(res.Body).Decode(&p)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusConflict || !strings.HasSuffix(p.Type, "/agent-unscanned") || p.Unscanned != 1 {
		t.Fatalf("public with an unscanned version standing: %d %+v", res.StatusCode, p)
	}
	staffH := env.register("uv-staff")
	env.makePlatformStaff(t, staffH)
	staff := env.login(staffH)
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/agents/"+orgH+"/internal/quarantine", map[string]any{"reason": "looking"}, nil, http.StatusNoContent)
	if code, slug, _ := problemOf(t, env.do(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/internal", map[string]any{"visibility": "public"})); code != http.StatusConflict || slug != "agent-unscanned" {
		t.Fatalf("public with an unscanned version quarantined: %d %s, want 409 agent-unscanned", code, slug)
	}
	// A reinstate asks for a scan of what it releases, and a version admitted
	// without one has none to judge: it stays held, and still stands.
	env.doJSON(staff, http.MethodPost, "/api/v1/platform/agents/"+orgH+"/internal/reinstate", map[string]any{"reason": "done"}, nil, http.StatusAccepted)
	env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/internal/versions/1.0.0", nil, &v, http.StatusOK)
	if v.Status != "quarantined" {
		t.Fatalf("reinstated, admitted unscanned: %s, want quarantined", v.Status)
	}
	// Yanked, it stands no more.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents/"+orgH+"/internal/versions/1.0.0/yank", map[string]any{"reason": "unscanned"}, nil, http.StatusNoContent)

	// With the flag cleared the next submission goes through the pipeline
	// like any other: scanning, a run, a scanned verdict.
	status, body = env.uploadVersionCLI(orgH, "internal", pat, skillFiles(orgH, "internal", "1.1.0", nil))
	if status != http.StatusAccepted {
		t.Fatalf("upload after clearing: %d %s", status, body)
	}
	// Any terminal outcome will do: what matters is that the pipeline ran.
	for i := 0; i < 200; i++ {
		env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/internal/versions/1.1.0", nil, &v, http.StatusOK)
		if v.Status != "submitted" && v.Status != "scanning" {
			break
		}
		sleep10ms()
	}
	if v.Status == "submitted" || v.Status == "scanning" {
		t.Fatalf("after clearing the flag the version did not go through the pipeline: %s", v.Status)
	}
	if v.ScanStatus == nil || *v.ScanStatus != "pipeline" {
		t.Fatalf("after clearing: scanStatus %v, want pipeline", v.ScanStatus)
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/internal/versions/1.1.0/report", nil, &rep, http.StatusOK)
	if rep.Verdict == nil || *rep.Verdict != "scanned" || rep.ScanRunId == nil {
		t.Fatalf("a scanned version's report = %+v, want verdict scanned with its run", rep)
	}
	// With nothing published unscanned standing, public is the admins' to
	// choose again.
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/internal", map[string]any{"visibility": "public"}, nil, http.StatusOK)

	// The flag is read again at every submission: with the tier's switch
	// gone, or the tier unreadable, a flagged agent's version goes through
	// the pipeline like any other.
	var probe struct {
		Id         string  `json:"id"`
		Status     string  `json:"status"`
		ScanStatus *string `json:"scanStatus"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "tierless", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/tierless", map[string]any{"pipelineSkip": true}, nil, http.StatusOK)
	for _, tc := range []struct {
		version string
		tier    entitlements.Resolver
	}{{"1.0.0", tierResolverFor(unscannedOn(false))}, {"1.0.1", brokenTierResolver()}} {
		env.setEntitlements(tc.tier)
		if status, body := env.uploadVersionCLI(orgH, "tierless", pat, skillFiles(orgH, "tierless", tc.version, nil)); status != http.StatusAccepted {
			t.Fatalf("upload %s with the tier off: %d %s", tc.version, status, body)
		}
		env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/tierless/versions/"+tc.version, nil, &probe, http.StatusOK)
		if probe.ScanStatus == nil || *probe.ScanStatus != "pipeline" {
			t.Fatalf("version %s with the tier's switch gone: scanStatus %v, want pipeline", tc.version, probe.ScanStatus)
		}
	}
	env.setEntitlements(tierResolverFor(unscannedOn(true)))

	// The sweeps leave out an agent off the pipeline altogether, a
	// version that went through the pipeline before the flag was set
	// included.
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "scanned-then-flagged", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	if status, body := env.uploadVersionCLI(orgH, "scanned-then-flagged", pat, skillFiles(orgH, "scanned-then-flagged", "1.0.0", nil)); status != http.StatusAccepted {
		t.Fatalf("upload before the flag: %d %s", status, body)
	}
	env.doJSON(admin, http.MethodGet, "/api/v1/agents/"+orgH+"/scanned-then-flagged/versions/1.0.0", nil, &probe, http.StatusOK)
	if probe.Status != "published" || probe.ScanStatus == nil || *probe.ScanStatus != "pipeline" {
		t.Fatalf("version before the flag: %+v, want published through the pipeline", probe)
	}
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/scanned-then-flagged", map[string]any{"pipelineSkip": true}, nil, http.StatusOK)
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO agent_version_mcp_servers (version_id, ecosystem, package, version) VALUES ($1, 'npm', 'left-pad', '1.0.0')`, probe.Id); err != nil {
		t.Fatal(err)
	}
	sweepsLeaveOut(probe.Id)

	// The gate-skipping edge is closed to a version not marked skipped:
	// the state machine refuses it under the row lock.
	reg := env.srvObj.Reg()
	var pending uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(),
		`INSERT INTO agent_versions (id, agent_id, version, manifest, capabilities, channel, submitted_by, source)
		 SELECT gen_random_uuid(), agent_id, '9.9.9', manifest, capabilities, channel, submitted_by, source FROM agent_versions WHERE id = $1 RETURNING id`, v.Id).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	err = reg.Transition(context.Background(), pending, registry.StatusPublished, "by hand", audit.Event{ActorKind: audit.ActorSystem, OrgID: uuid.MustParse(orgID)})
	if !errors.Is(err, registry.ErrBadTransition) {
		t.Fatalf("submitted → published on a version not marked skipped: %v, want ErrBadTransition", err)
	}

	// And to a version marked skipped whose agent is public now — the
	// gate-skipping edge and a reinstate from quarantine alike — the
	// choke point refuses under the agent's lock.
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE agent_versions SET scan_status = 'skipped' WHERE id = $1`, pending); err != nil {
		t.Fatal(err)
	}
	err = reg.Transition(context.Background(), pending, registry.StatusPublished, "by hand", audit.Event{ActorKind: audit.ActorSystem, OrgID: uuid.MustParse(orgID)})
	if !errors.Is(err, registry.ErrUnscannedOnPublic) {
		t.Fatalf("submitted → published of a skipped version on a public agent: %v, want ErrUnscannedOnPublic", err)
	}
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE agent_versions SET status = 'quarantined' WHERE id = $1`, pending); err != nil {
		t.Fatal(err)
	}
	err = reg.Transition(context.Background(), pending, registry.StatusPublished, "reinstate", audit.Event{ActorKind: audit.ActorSystem, OrgID: uuid.MustParse(orgID)})
	if !errors.Is(err, registry.ErrUnscannedOnPublic) {
		t.Fatalf("quarantined → published of a skipped version on a public agent: %v, want ErrUnscannedOnPublic", err)
	}

	// Nor on a private agent whose flag was cleared after the version
	// was submitted, nor on one that is not an organization's.
	stage := func(ns, name, status string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := env.st.Pool().QueryRow(context.Background(),
			`INSERT INTO agent_versions (id, agent_id, version, manifest, capabilities, channel, submitted_by, source, status, scan_status)
			 SELECT gen_random_uuid(), a.id, '1.0.0', '{}', '{}', 'stable', (SELECT id FROM handles WHERE handle = $4), 'cli-upload', $3, 'skipped'
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $1 AND a.name = $2 RETURNING id`, ns, name, status, adminH).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "flag-cleared", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	cleared := stage(orgH, "flag-cleared", "submitted")
	err = reg.Transition(context.Background(), cleared, registry.StatusPublished, "by hand", audit.Event{ActorKind: audit.ActorSystem, OrgID: uuid.MustParse(orgID)})
	if !errors.Is(err, registry.ErrUnscannedOnPublic) {
		t.Fatalf("submitted → published of a skipped version after the flag was cleared: %v, want ErrUnscannedOnPublic", err)
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": adminH, "name": "personal-held", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	personal := stage(adminH, "personal-held", "quarantined")
	err = reg.Transition(context.Background(), personal, registry.StatusPublished, "reinstate", audit.Event{ActorKind: audit.ActorSystem})
	if !errors.Is(err, registry.ErrUnscannedOnPublic) {
		t.Fatalf("quarantined → published of a skipped version on a personal agent: %v, want ErrUnscannedOnPublic", err)
	}
}

// The flag and public never meet in a row: the handler refuses each
// under the agent's row lock, and the table's CHECK is the wall behind
// it — a writer that bypassed the handler is refused by the database.
func TestTheFlagAndPublicNeverMeetInARow(t *testing.T) {
	env := newTestEnvWith(t, onTier(unscannedOn(true)))
	adminH := env.register("ul-admin")
	env.verifyEmail(adminH)
	admin := env.login(adminH)
	orgH := "ulorg" + env.sfx
	env.createOrg(admin, orgH)
	env.doJSON(admin, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": orgH, "name": "racy", "modes": []string{"autonomous"}, "visibility": "private"}, nil, http.StatusCreated)
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/racy", map[string]any{"pipelineSkip": true}, nil, http.StatusOK)
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE agents SET visibility = 'public' WHERE name = 'racy' AND pipeline_skip`); err == nil {
		t.Fatal("the table let the flag and public meet in a row")
	} else if !strings.Contains(err.Error(), "agents_pipeline_skip_private") {
		t.Fatalf("the table refused the flag and public in a row with %v, want its agents_pipeline_skip_private check", err)
	}
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE agents SET pipeline_skip = true WHERE name = 'racy' AND visibility = 'public'`); err != nil {
		t.Fatalf("an update that matched no row: %v", err)
	}
}

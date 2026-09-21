package api_test

// Unscanned private agents (plan organization-subscriptions.md §4, §5.10;
// D16; M21, agentry#368): an organization's administrator may take a
// private agent of the organization's off the pipeline, behind the tier's
// switch; a submission to it is published as submitted — no scan run, no
// findings, no attestation — and served everywhere as unscanned; and the
// agent cannot become public while the flag is set or a version published
// unscanned stands, so the §7 property holds for public content as it
// always did.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

func probeFiles(ns, name, version string) map[string]string {
	return map[string]string{
		"agent.yaml": skillYAML(ns, name, version),
		"README.md":  "# " + name + "\n",
		"SKILL.md":   "Summarize politely.\n",
		"LICENSE":    "Apache-2.0\n",
	}
}

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
	slug := func(res *http.Response) string {
		var p struct {
			Type string `json:"type"`
		}
		_ = json.NewDecoder(res.Body).Decode(&p)
		return p.Type[strings.LastIndex(p.Type, "/")+1:]
	}
	patch := func(c caller, ns, name string, body map[string]any) (int, string) {
		res := env.do(c, http.MethodPatch, "/api/v1/agents/"+ns+"/"+name, body)
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode == http.StatusOK {
			return res.StatusCode, ""
		}
		return res.StatusCode, slug(res)
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
	status, body := env.uploadVersionCLI(orgH, "internal", pat, probeFiles(orgH, "internal", "1.0.0"))
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

	// Public is refused while a version published unscanned stands, even
	// after the flag is cleared; yanked, it stands no more.
	env.doJSON(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/internal", map[string]any{"pipelineSkip": false}, nil, http.StatusOK)
	res := env.do(admin, http.MethodPatch, "/api/v1/agents/"+orgH+"/internal", map[string]any{"visibility": "public"})
	var p struct {
		Type, Detail string
	}
	_ = json.NewDecoder(res.Body).Decode(&p)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusConflict || !strings.HasSuffix(p.Type, "/agent-unscanned") || !strings.Contains(p.Detail, "1 published version of this BriefAgent was never scanned") {
		t.Fatalf("public with an unscanned version standing: %d %+v", res.StatusCode, p)
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/agents/"+orgH+"/internal/versions/1.0.0/yank", map[string]any{"reason": "unscanned"}, nil, http.StatusNoContent)

	// With the flag cleared the next submission goes through the pipeline
	// like any other: scanning, a run, a scanned verdict.
	status, body = env.uploadVersionCLI(orgH, "internal", pat, probeFiles(orgH, "internal", "1.1.0"))
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
}

package api_test

// The matrix extension for the SelfAuthorized routes. The twelve routes
// below opt out of the chokepoint because
// their rule — "platform staff, or an org security_reviewer who is not
// the version's author" — needs the resource in hand. That made them the
// one part of the trust & safety surface no enumeration covered. This
// test drives each of them over a fixed caller grid and asserts the
// authorization outcome, matrix-style: an expected-allowed case asserts
// the response is NOT 401/403 (domain statuses like 404/422 are fine and
// deliberately used so allowed probes never mutate fixtures).
//
// Caller grid:
//   anonymous     — refused everywhere (401)
//   plain         — signed-in, no roles anywhere (403 on all staff surfaces)
//   staff         — platform_staff
//   author+staff  — the review item's author, ALSO staff: staff may
//                   decide their own versions, so this caller is
//                   allowed like any staff
//   orgOwner      — owner of an unrelated org (an org reviewer for ITS queue,
//                   nothing on the platform surface)
//   patScoped     — the staff user's PAT WITH review:act
//   patUnscoped   — the staff user's PAT WITHOUT review:act (the
//                   scope gate of authz_scope_routes.go)

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
)

// matrixDraft is a draft package the check route reads: an agent.yaml
// and the instruction it names.
var matrixDraft = map[string]any{"description": "matrix", "files": []map[string]string{
	{"path": "agent.yaml", "content": "schemaVersion: \"2\"\nname: matrix\nnamespace: draft\nversion: 0.1.0\nsummary: m\nlicense: Apache-2.0\nmodes: [autonomous]\nentrypoints:\n  instruction: AGENT.md\n"},
	{"path": "AGENT.md", "content": "# m\n"},
}}

func TestSelfAuthorizedMatrix(t *testing.T) {
	env := newTestEnv(t)

	// A pending platform review item with findings, its author, and a
	// staff session (m8 console fixture; cleans its queue rows up after).
	author, itemID, staffSess := setupReviewItem(t, env, "sam")
	authorSess := env.login(author)
	// The author is staff, and staff may decide their own
	// version (a non-staff author is refused: review_staff_test.go).
	env.makePlatformStaff(t, author)

	plainH := env.register("sam-plain")
	env.verifyEmail(plainH)
	plain := env.login(plainH)

	// An org whose owner is an org reviewer for its (empty) queue.
	orgOwnerH := env.register("sam-orgown")
	env.verifyEmail(orgOwnerH)
	orgOwner := env.login(orgOwnerH)
	orgH := "samorg" + env.sfx
	env.doJSON(orgOwner, http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": orgH, "displayName": "SelfAuthz Org"}, nil, http.StatusCreated)

	// An invitation the org's admin sent to `plain`: the token is the
	// authorization, and who may use it is the per-invitation rule.
	// A token nobody holds is 404, which is a PASS for the
	// matrix — the point is that it is never 401/403 for a session.
	var invited struct {
		Token string `json:"token"`
	}
	env.doJSON(orgOwner, http.MethodPost, "/api/v1/orgs/"+orgH+"/invitations",
		map[string]any{"email": plainH + "@example.test", "role": "member"}, &invited, http.StatusCreated)

	// PATs of the STAFF user: role identical, scope differing — isolates
	// the review:act gate from the role check.
	_, patScopedTok := env.mintPAT(staffSess, "sam-scoped", "review:act", "user:profile", "agent:read")
	_, patUnscopedTok := env.mintPAT(staffSess, "sam-unscoped", "user:profile", "agent:read")
	_, patKnowledgeTok := env.mintPAT(staffSess, "sam-knowledge", "knowledge:read")
	patKnowledge := caller{name: "staff-pat-knowledge", pat: patKnowledgeTok}
	patScoped := caller{name: "patScoped", pat: patScopedTok}
	patUnscoped := caller{name: "patUnscoped", pat: patUnscopedTok}

	// A finding id on the item, for the verdict route.
	var bundle struct {
		Findings []struct {
			Id string `json:"id"`
		} `json:"findings"`
	}
	env.doJSON(staffSess, http.MethodGet, "/api/v1/review-items/"+itemID, nil, &bundle, http.StatusOK)
	if len(bundle.Findings) == 0 {
		t.Fatal("fixture review item carries no findings")
	}
	findingID := bundle.Findings[0].Id

	const (
		pass  = 0 // asserted as NOT 401/403; 2xx/404/409/422 all fine
		deny1 = http.StatusUnauthorized
		deny3 = http.StatusForbidden
	)

	type sCase struct {
		op     string
		method string
		path   string
		body   any
		caller caller
		want   int
	}
	emptyDecision := map[string]any{} // authorized callers stop at 422 (rationale required) — no mutation
	cases := []sCase{
		// listReviewQueue — platform queue is staff-only; the org queue
		// belongs to that org's reviewers and to platform staff, who may
		// also list every org's at once.
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, anonymous, deny1},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, plain, deny3},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, staffSess, pass},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, patScoped, pass},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, patUnscoped, deny3},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=org&org=" + orgH + "&limit=1", nil, orgOwner, pass},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=org&org=" + orgH + "&limit=1", nil, plain, deny3},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=org&org=" + orgH + "&limit=1", nil, staffSess, pass},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=org&limit=1", nil, staffSess, pass},

		// getReviewItem / listReviewFiles / getReviewFile — read surface of
		// a PLATFORM item: staff only (org reviewers of other orgs and the
		// author's plain view included in "not staff").
		{"getReviewItem", "GET", "/api/v1/review-items/" + itemID, nil, anonymous, deny1},
		{"getReviewItem", "GET", "/api/v1/review-items/" + itemID, nil, plain, deny3},
		{"getReviewItem", "GET", "/api/v1/review-items/" + itemID, nil, orgOwner, deny3},
		{"getReviewItem", "GET", "/api/v1/review-items/" + itemID, nil, staffSess, pass},
		{"getReviewItem", "GET", "/api/v1/review-items/" + itemID, nil, patScoped, pass},
		{"getReviewItem", "GET", "/api/v1/review-items/" + itemID, nil, patUnscoped, deny3},
		{"listReviewFiles", "GET", "/api/v1/review-items/" + itemID + "/files", nil, anonymous, deny1},
		{"listReviewFiles", "GET", "/api/v1/review-items/" + itemID + "/files", nil, plain, deny3},
		{"listReviewFiles", "GET", "/api/v1/review-items/" + itemID + "/files", nil, staffSess, pass},
		{"getReviewFile", "GET", "/api/v1/review-items/" + itemID + "/file?path=SKILL.md", nil, anonymous, deny1},
		{"getReviewFile", "GET", "/api/v1/review-items/" + itemID + "/file?path=SKILL.md", nil, plain, deny3},
		{"getReviewFile", "GET", "/api/v1/review-items/" + itemID + "/file?path=SKILL.md", nil, staffSess, pass},

		// decideReviewItem — the empty body stops authorized callers at 422
		// (rationale required) BEFORE any state change; the author case
		// is staff, and reaches the same 422 as any staff.
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, anonymous, deny1},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, plain, deny3},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, patUnscoped, deny3},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, staffSess, pass},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, patScoped, pass},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, authorSess, pass},

		// setFindingVerdict — authorized via the finding's review item; the
		// scope gate covers /findings/ by path prefix.
		{"setFindingVerdict", "POST", "/api/v1/findings/" + findingID + "/verdict",
			map[string]any{"verdict": "confirmed", "reason": "matrix"}, anonymous, deny1},
		{"setFindingVerdict", "POST", "/api/v1/findings/" + findingID + "/verdict",
			map[string]any{"verdict": "confirmed", "reason": "matrix"}, plain, deny3},
		{"setFindingVerdict", "POST", "/api/v1/findings/" + findingID + "/verdict",
			map[string]any{"verdict": "confirmed", "reason": "matrix"}, patUnscoped, deny3},
		{"setFindingVerdict", "POST", "/api/v1/findings/" + findingID + "/verdict",
			map[string]any{"verdict": "confirmed", "reason": "matrix"}, staffSess, pass},

		// platformAgentAction — staff-only; a nonexistent agent turns every
		// authorized probe into a 404 with nothing mutated.
		{"platformAgentAction", "POST", "/api/v1/platform/agents/nobody" + env.sfx + "/ghost/quarantine",
			map[string]any{"reason": "matrix"}, anonymous, deny1},
		{"platformAgentAction", "POST", "/api/v1/platform/agents/nobody" + env.sfx + "/ghost/quarantine",
			map[string]any{"reason": "matrix"}, plain, deny3},
		{"platformAgentAction", "POST", "/api/v1/platform/agents/nobody" + env.sfx + "/ghost/quarantine",
			map[string]any{"reason": "matrix"}, staffSess, pass},

		// suspendOrg / reinstateOrg — staff-only; an absent
		// organization turns every authorized probe into a 404, nothing
		// suspended.
		{"suspendOrg", "POST", "/api/v1/orgs/nobody" + env.sfx + "/suspend", map[string]any{"reason": "matrix"}, anonymous, deny1},
		{"suspendOrg", "POST", "/api/v1/orgs/nobody" + env.sfx + "/suspend", map[string]any{"reason": "matrix"}, plain, deny3},
		{"suspendOrg", "POST", "/api/v1/orgs/" + orgH + "/suspend", map[string]any{"reason": "matrix"}, orgOwner, deny3},
		{"suspendOrg", "POST", "/api/v1/orgs/nobody" + env.sfx + "/suspend", map[string]any{"reason": "matrix"}, staffSess, pass},
		{"reinstateOrg", "POST", "/api/v1/orgs/nobody" + env.sfx + "/reinstate", nil, anonymous, deny1},
		{"reinstateOrg", "POST", "/api/v1/orgs/nobody" + env.sfx + "/reinstate", nil, plain, deny3},
		{"reinstateOrg", "POST", "/api/v1/orgs/" + orgH + "/reinstate", nil, orgOwner, deny3},
		{"reinstateOrg", "POST", "/api/v1/orgs/nobody" + env.sfx + "/reinstate", nil, staffSess, pass},

		// listPlatformAudit — staff-only read.
		{"listPlatformAudit", "GET", "/api/v1/platform/audit?limit=1", nil, anonymous, deny1},
		{"listPlatformAudit", "GET", "/api/v1/platform/audit?limit=1", nil, plain, deny3},
		{"listPlatformAudit", "GET", "/api/v1/platform/audit?limit=1", nil, orgOwner, deny3},
		{"listPlatformAudit", "GET", "/api/v1/platform/audit?limit=1", nil, staffSess, pass},

		// createRulesetRelease — staff-only; the type-invalid body stops
		// authorized callers at 400 before any release is registered.
		{"createRulesetRelease", "POST", "/api/v1/platform/ruleset-releases", "not-an-object", anonymous, deny1},
		{"createRulesetRelease", "POST", "/api/v1/platform/ruleset-releases", "not-an-object", plain, deny3},
		{"createRulesetRelease", "POST", "/api/v1/platform/ruleset-releases", "not-an-object", staffSess, pass},
		// listRulesetReleases — the staff console's history.
		{"listRulesetReleases", "GET", "/api/v1/platform/ruleset-releases", nil, anonymous, deny1},
		{"listRulesetReleases", "GET", "/api/v1/platform/ruleset-releases", nil, plain, deny3},
		{"listRulesetReleases", "GET", "/api/v1/platform/ruleset-releases", nil, staffSess, pass},

		// listRedTeamReports — red-team reports, staff-only.
		{"listRedTeamReports", "GET", "/api/v1/platform/redteam/reports", nil, anonymous, deny1},
		{"listRedTeamReports", "GET", "/api/v1/platform/redteam/reports", nil, plain, deny3},
		{"listRedTeamReports", "GET", "/api/v1/platform/redteam/reports", nil, staffSess, pass},

		// reportAbuse — any signed-in caller may report a visible agent;
		// anonymous may not (follow-up needs an account).
		{"reportAbuse", "POST", "/api/v1/agents/" + author + "/risky/abuse-reports",
			map[string]any{"category": "spam", "detail": "matrix self-authz abuse fixture"}, anonymous, deny1},
		{"reportAbuse", "POST", "/api/v1/agents/" + author + "/risky/abuse-reports",
			map[string]any{"category": "spam", "detail": "matrix self-authz abuse fixture"}, plain, pass},

		// listKnowledgePackSizes — staff-only, and a staff
		// token needs knowledge:read; an owner with no packs lists empty.
		{"listKnowledgePackSizes", "GET", "/api/v1/platform/knowledge?owner=" + plainH, nil, anonymous, deny1},
		{"listKnowledgePackSizes", "GET", "/api/v1/platform/knowledge?owner=" + plainH, nil, plain, deny3},
		{"listKnowledgePackSizes", "GET", "/api/v1/platform/knowledge?owner=" + plainH, nil, staffSess, pass},
		{"listKnowledgePackSizes", "GET", "/api/v1/platform/knowledge?owner=" + plainH, nil, patUnscoped, deny3},
		{"listKnowledgePackSizes", "GET", "/api/v1/platform/knowledge?owner=" + plainH, nil, patKnowledge, pass},

		// scanModelInput / searchModelInput — platform staff
		// by session, never a token whatever its scopes (the staff PATs
		// here carry review:act and knowledge:read), and a hosted job's
		// credential only where an extension admits it (the model-input
		// tests). This server has no Jev judge and no search provider, so
		// staff stop at 503 with nothing spent.
		{"scanModelInput", "POST", "/api/v1/model-input/scan", map[string]any{"source": "page", "text": "matrix"}, anonymous, deny1},
		{"scanModelInput", "POST", "/api/v1/model-input/scan", map[string]any{"source": "page", "text": "matrix"}, plain, deny3},
		{"scanModelInput", "POST", "/api/v1/model-input/scan", map[string]any{"source": "page", "text": "matrix"}, orgOwner, deny3},
		{"scanModelInput", "POST", "/api/v1/model-input/scan", map[string]any{"source": "page", "text": "matrix"}, staffSess, pass},
		{"scanModelInput", "POST", "/api/v1/model-input/scan", map[string]any{"source": "page", "text": "matrix"}, patScoped, deny3},
		{"scanModelInput", "POST", "/api/v1/model-input/scan", map[string]any{"source": "page", "text": "matrix"}, patKnowledge, deny3},
		{"searchModelInput", "POST", "/api/v1/model-input/search", map[string]any{"query": "matrix"}, anonymous, deny1},
		{"searchModelInput", "POST", "/api/v1/model-input/search", map[string]any{"query": "matrix"}, plain, deny3},
		{"searchModelInput", "POST", "/api/v1/model-input/search", map[string]any{"query": "matrix"}, staffSess, pass},
		{"searchModelInput", "POST", "/api/v1/model-input/search", map[string]any{"query": "matrix"}, patScoped, deny3},
		{"searchModelInput", "POST", "/api/v1/model-input/search", map[string]any{"query": "matrix"}, patUnscoped, deny3},
		// checkDraft — the same callers: the draft's check
		// spends the deployment's own judge key.
		{"checkDraft", "POST", "/api/v1/model-input/check", matrixDraft, anonymous, deny1},
		{"checkDraft", "POST", "/api/v1/model-input/check", matrixDraft, plain, deny3},
		{"checkDraft", "POST", "/api/v1/model-input/check", matrixDraft, orgOwner, deny3},
		{"checkDraft", "POST", "/api/v1/model-input/check", matrixDraft, staffSess, pass},
		{"checkDraft", "POST", "/api/v1/model-input/check", matrixDraft, patScoped, deny3},
		{"checkDraft", "POST", "/api/v1/model-input/check", matrixDraft, patKnowledge, deny3},
		{"checkDraft", "POST", "/api/v1/model-input/check", matrixDraft, patUnscoped, deny3},

		// listAbuseReports / triageAbuseReport — staff-only; triage of a
		// random id gives authorized callers 404, nothing mutated.
		{"listAbuseReports", "GET", "/api/v1/platform/abuse-reports?limit=1", nil, anonymous, deny1},
		{"listAbuseReports", "GET", "/api/v1/platform/abuse-reports?limit=1", nil, plain, deny3},
		{"listAbuseReports", "GET", "/api/v1/platform/abuse-reports?limit=1", nil, staffSess, pass},
		{"triageAbuseReport", "POST", "/api/v1/platform/abuse-reports/" + uuid.NewString(),
			map[string]any{"state": "resolved"}, anonymous, deny1},
		{"triageAbuseReport", "POST", "/api/v1/platform/abuse-reports/" + uuid.NewString(),
			map[string]any{"state": "resolved"}, plain, deny3},
		{"triageAbuseReport", "POST", "/api/v1/platform/abuse-reports/" + uuid.NewString(),
			map[string]any{"state": "resolved"}, staffSess, pass},
	}

	covered := map[string]bool{}
	// getInvitation / acceptInvitation: session-only, and the token plus
	// the session's verified address is the whole rule. Anonymous is 401;
	// a PAT is 403 however it is scoped, because answering an invitation is
	// a person's act; a session that is not the invited address is 403 on
	// accept and may still read the offer (it says why it cannot take it).
	// `plain` accepts last, so the single-use token is spent only after
	// every other case has run.
	cases = append(cases,
		sCase{"getInvitation", "GET", "/api/v1/invitations/" + invited.Token, nil, anonymous, deny1},
		sCase{"getInvitation", "GET", "/api/v1/invitations/" + invited.Token, nil, patScoped, deny3},
		sCase{"getInvitation", "GET", "/api/v1/invitations/" + invited.Token, nil, staffSess, pass},
		sCase{"getInvitation", "GET", "/api/v1/invitations/" + invited.Token, nil, plain, pass},
		sCase{"acceptInvitation", "POST", "/api/v1/invitations/" + invited.Token, nil, anonymous, deny1},
		sCase{"acceptInvitation", "POST", "/api/v1/invitations/" + invited.Token, nil, patUnscoped, deny3},
		sCase{"acceptInvitation", "POST", "/api/v1/invitations/" + invited.Token, nil, staffSess, deny3},
		sCase{"acceptInvitation", "POST", "/api/v1/invitations/" + invited.Token, nil, plain, pass},
	)

	for i, c := range cases {
		covered[c.op] = true
		name := fmt.Sprintf("%s/%s", c.op, c.caller.name)
		t.Run(name, func(t *testing.T) {
			res := env.do(c.caller, c.method, c.path, c.body)
			defer func() { _ = res.Body.Close() }()
			denied := res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden
			switch c.want {
			case pass:
				if denied {
					t.Fatalf("case %d %s %s as %s: expected authz PASS, got %d", i, c.method, c.path, c.caller.name, res.StatusCode)
				}
			default:
				if res.StatusCode != c.want {
					t.Fatalf("case %d %s %s as %s: expected %d, got %d", i, c.method, c.path, c.caller.name, c.want, res.StatusCode)
				}
			}
		})
	}

	// Completeness: every SelfAuthorized declaration must appear above, so a
	// thirteenth route cannot ship outside this matrix (mirror of
	// TestRouteDeclarationsComplete for the bespoke regime).
	for id, decl := range api.AllRouteAuthzDecls() {
		if decl.SelfAuthorized && !covered[id] {
			t.Errorf("SelfAuthorized route %q has no cases in TestSelfAuthorizedMatrix — add its truth table", id)
		}
	}
	t.Logf("self-authz matrix: %d cases over %d routes", len(cases), len(covered))
}

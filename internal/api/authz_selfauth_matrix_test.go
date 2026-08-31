package api_test

// The §17.4 matrix extension for the SelfAuthorized routes (DEV-033
// closure). The twelve routes below opt out of the chokepoint because
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
//   author+staff  — the review item's author, ALSO staff: proves the
//                   author-cannot-self-approve rule outranks the staff flag
//   orgOwner      — owner of an unrelated org (an org reviewer for ITS queue,
//                   nothing on the platform surface)
//   patScoped     — the staff user's PAT WITH review:act
//   patUnscoped   — the staff user's PAT WITHOUT review:act (the §12.3
//                   scope gate of authz_scope_routes.go)

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
)

func TestSelfAuthorizedMatrix(t *testing.T) {
	env := newTestEnv(t)

	// A pending platform review item with findings, its author, and a
	// staff session (m8 console fixture; cleans its queue rows up after).
	author, itemID, staffSess := setupReviewItem(t, env, "sam")
	authorSess := env.login(author)
	// The author-beats-staff case: the author IS staff and still may not
	// decide their own version.
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

	// PATs of the STAFF user: role identical, scope differing — isolates
	// the §12.3 review:act gate from the role check.
	_, patScopedTok := env.mintPAT(staffSess, "sam-scoped", "review:act", "user:profile", "agent:read")
	_, patUnscopedTok := env.mintPAT(staffSess, "sam-unscoped", "user:profile", "agent:read")
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
	validDecision := map[string]any{"decision": "reject", "rationale": "matrix self-authz case"}
	emptyDecision := map[string]any{} // authorized callers stop at 422 (rationale required) — no mutation
	cases := []sCase{
		// listReviewQueue — platform queue is staff-only; the org queue
		// belongs to that org's reviewers, and the staff flag is NOT an
		// org role (documented boundary, asserted here).
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, anonymous, deny1},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, plain, deny3},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, staffSess, pass},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, patScoped, pass},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=platform&limit=1", nil, patUnscoped, deny3},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=org&org=" + orgH + "&limit=1", nil, orgOwner, pass},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=org&org=" + orgH + "&limit=1", nil, plain, deny3},
		{"listReviewQueue", "GET", "/api/v1/review-queue?queue=org&org=" + orgH + "&limit=1", nil, staffSess, deny3},

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
		// carries a valid body so it reaches, and is refused by, the
		// author-cannot-self-approve check despite the staff flag.
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, anonymous, deny1},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, plain, deny3},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, patUnscoped, deny3},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, staffSess, pass},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", emptyDecision, patScoped, pass},
		{"decideReviewItem", "POST", "/api/v1/review-items/" + itemID + "/decision", validDecision, authorSess, deny3},

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

		// reportAbuse — any signed-in caller may report a visible agent;
		// anonymous may not (follow-up needs an account).
		{"reportAbuse", "POST", "/api/v1/agents/" + author + "/risky/abuse-reports",
			map[string]any{"category": "spam", "detail": "matrix self-authz abuse fixture"}, anonymous, deny1},
		{"reportAbuse", "POST", "/api/v1/agents/" + author + "/risky/abuse-reports",
			map[string]any{"category": "spam", "detail": "matrix self-authz abuse fixture"}, plain, pass},

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

package api_test

// The authorization matrix: every declared route × every role ×
// anonymous/role/PAT-scope combination, executed as real HTTP requests
// against one organization. Private and foreign-resource evidence stays in
// the resource tests (docs/testing-authorization.md).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

// rateClasses is the set of rate-limit bucket names the code emits, catalogued in
// docs/logging.md's http.rate_limited row, plus the two sentinels a
// declaration uses when no single bucket applies. A declaration naming
// anything else is a typo that reads as a claim about enforcement.
var rateClasses = map[string]bool{
	"login": true, "anon": true, "authed": true, "abuse_reports": true,
	"push": true, "ssh-key-offer": true, "git-concurrent": true,
	api.RateNone: true, api.RatePerPrincipal: true,
}

// TestRouteDeclarationsComplete is the completeness gate: every
// pattern the public mux was actually given declares its authorization, and
// every declaration names a pattern the mux serves. The generated surface
// declares through RouteDecl, keyed by operationId; a root mount declares
// through MountDecl, keyed by its pattern. The gate walks the mux rather
// than the spec, because the root mounts — the image proxy, git smart
// HTTP, the probes, /metrics, the .well-known documents —
// are not in the spec, and a new one would otherwise ship with no
// declaration and no failure.
func TestRouteDeclarationsComplete(t *testing.T) {
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	// The spec's operations, keyed by the pattern the generated handler
	// registers: the method, then BaseURL, then the spec's path.
	const baseURL = "/api/v1"
	specOps := make(map[string]string)
	for path, item := range spec.Paths.Map() {
		for method, op := range item.Operations() {
			if op.OperationID == "" {
				t.Errorf("%s %s: missing operationId", method, path)
				continue
			}
			id := api.NormalizeOpID(op.OperationID)
			specOps[method+" "+baseURL+path] = id
			// Declared from the spec, not from the recording: an operation
			// the spec promises and the generated handler never registered
			// would otherwise pass unseen.
			if _, ok := api.RouteAuthzDecl(id); !ok {
				t.Errorf("%s %s (%s): no RouteDecl — declare it in authz_routes.go", method, path, id)
			}
		}
	}

	// What the mux was given. Git's routes arrive through gitsrv's own Mount
	// rather than a copy of its patterns here, so a route added there enters
	// this gate the moment it exists; the handlers are registered and never
	// called.
	cfg := config.Default()
	cfg.DevMode = true // a fixture has no sealing key
	srv := api.New(cfg, nil, nil)
	// An extension's callback mount is declared by the extension, so one is
	// registered here for the gate to read: the core build has none.
	srv.RegisterExtensionCallbacks("probe", api.ExtensionCallbacks{
		Class: api.RateNone, Why: "a probe the gate reads; its secret is unset, so it answers 404",
		Routes: func(m *http.ServeMux) { m.HandleFunc("POST /check", func(http.ResponseWriter, *http.Request) {}) },
	})
	api.NewHandlerWithGit(srv, (&gitsrv.Handler{}).Mount)
	mounted := srv.MountedRoutes()
	recorded := make(map[string]bool, len(mounted))
	for _, pattern := range mounted {
		recorded[pattern] = true
	}
	for pattern := range specOps {
		if !recorded[pattern] {
			t.Errorf("%s: the spec declares it and the public mux does not serve it", pattern)
		}
	}

	seenSpec := map[string]bool{}
	seenMount := map[string]bool{}
	for _, pattern := range mounted {
		if opID, ok := specOps[pattern]; ok {
			seenSpec[opID] = true // declared from the spec side, above
			continue
		}
		decl, ok := srv.MountAuthzDecl(pattern)
		if !ok {
			t.Errorf("%s: registered on the public mux and undeclared — name its gate and its rate class in authz_routes.go", pattern)
			continue
		}
		seenMount[pattern] = true
		if decl.Gate == "" {
			t.Errorf("%s: declares no gate", pattern)
		}
		if !rateClasses[decl.Class] {
			t.Errorf("%s: declares rate class %q, which no bucket uses (docs/logging.md catalogues the set)", pattern, decl.Class)
		}
		// Naming no gate and naming no fixed bucket are the two claims that
		// go stale silently, so each carries its reason.
		if (decl.Gate == api.GatePublic || decl.Class == api.RateNone || decl.Class == api.RatePerPrincipal) && decl.Why == "" {
			t.Errorf("%s: gate %q, class %q — a declaration with no gate or no fixed bucket has to say why", pattern, decl.Gate, decl.Class)
		}
	}

	// And the reverse, for both tables: no declaration names a route that
	// nothing serves.
	for id := range api.AllRouteAuthzDecls() {
		if !seenSpec[id] {
			t.Errorf("RouteDecl %q has no matching OpenAPI operation", id)
		}
	}
	for pattern := range api.AllMountAuthzDecls() {
		if !seenMount[pattern] {
			t.Errorf("MountDecl %q names a route the public mux does not serve", pattern)
		}
	}
}

// TestExtensionMountIsDeclaredByPrefix covers the one declaration made at
// run time: an extension's routes are registered under /api/v1/x/<name>/
// behind the principal middleware, and the extension's own matrix test
// declares each route behind it. The core build loads no
// extensions, so without this the prefix rule is dead code here that the
// closed build depends on.
func TestExtensionMountIsDeclaredByPrefix(t *testing.T) {
	decl, ok := api.MountAuthzDecl("/api/v1/x/billing/")
	if !ok {
		t.Fatal("an extension's mount point has no declaration")
	}
	if decl.Gate != api.GatePrincipal {
		t.Errorf("an extension's mount point: gate %q, want %q", decl.Gate, api.GatePrincipal)
	}
	if decl.Why == "" {
		t.Error("an extension's mount point declares no reason")
	}
	if _, ok := api.MountAuthzDecl("/api/v1/x/billing/status"); !ok {
		t.Error("a route under an extension's mount point has no declaration")
	}
	if _, ok := api.MountAuthzDecl("GET /healthzx"); ok {
		t.Error("a pattern no mount serves is declared")
	}
}

// matrixSeed builds one org with every role plus an outsider, sessions for
// all, and PATs for the admin (right-scope and wrong-scope). The admin is
// the org's creator (there is no owner). The security
// reviewer row is seeded in the database, not through the API: the role
// exists only inside a first-party organization and the API refuses to
// assign it here, but a row can exist (the `agentry` org) and every route
// must rank it as a member.
type matrixSeed struct {
	env      *testEnv
	orgH     string
	pawnH    string            // plain member used as a non-destructive PUT target
	sessions map[string]caller // by role name
	patOK    func(scope string) caller
	patWrong caller
	// patSignIn is the admin's token with the sign-in grant's scopes
	// (auth.SignInGrantScopes), as the desktop and the CLI mint it: every
	// route decides it as the chokepoint predicts, so what the grant
	// reaches is proven route by route.
	patSignIn caller
	orgID     uuid.UUID
}

func seedMatrix(t *testing.T, env *testEnv) *matrixSeed {
	t.Helper()
	roles := []string{"admin", "security_reviewer", "member", "pending", "outsider"}
	sessions := map[string]caller{}
	for _, role := range roles {
		sessions[role] = env.seedCaller("mx-" + role[:3])
	}
	orgH := "mxorg" + env.sfx
	var org struct {
		Id uuid.UUID `json:"id"`
	}
	env.doJSON(sessions["admin"], http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": orgH, "displayName": "Matrix Org"}, &org, http.StatusCreated)
	env.joinOrg(sessions["admin"], orgH, sessions["member"].name)
	env.seedMembership(orgH, sessions["security_reviewer"].name, "security_reviewer", "active")
	// A member the IdP provisioned and no admin has approved. They hold
	// nothing, and the matrix proves it route by
	// route rather than only where someone thought to look.
	env.seedMembership(orgH, sessions["pending"].name, "member", "pending")
	// A pawn member for non-destructive member-set targets.
	pawnH := env.register("mx-pawn")
	env.joinOrg(sessions["admin"], orgH, pawnH)
	// A standing team for read routes.
	env.doJSON(sessions["admin"], http.MethodPost, "/api/v1/orgs/"+orgH+"/teams",
		map[string]any{"slug": "mx-team"}, nil, http.StatusCreated)
	env.doJSON(sessions["admin"], http.MethodPut,
		"/api/v1/orgs/"+orgH+"/teams/mx-team/members/"+pawnH, nil, nil, http.StatusNoContent)

	// A public agent in the org for agent-scoped routes.
	env.doJSON(sessions["admin"], http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "mx-agent", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)

	// A second public agent that deleteAgent targets. An abuse report pins it
	// in place: every authorized caller gets 409 instead of actually deleting
	// it, so the matrix (whose case order is map-random) cannot destroy the
	// fixture for later cases. The real delete path is covered by
	// TestDeleteAgent* in the handler tests.
	env.doJSON(sessions["admin"], http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "mx-undeletable", "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(sessions["member"], http.MethodPost,
		"/api/v1/agents/"+orgH+"/mx-undeletable/abuse-reports",
		map[string]any{"category": "spam", "detail": "matrix fixture: keeps this agent undeletable"},
		nil, http.StatusAccepted)

	_, patAll := env.mintPAT(sessions["admin"], "matrix-ok",
		"org:admin", "audit:read", "user:profile", "agent:read")
	_, patNone := env.mintPAT(sessions["admin"], "matrix-wrong", "repo:read")
	_, patGrant := env.mintPAT(sessions["admin"], "matrix-sign-in", auth.SignInGrantScopes()...)

	return &matrixSeed{
		env: env, orgH: orgH, pawnH: pawnH, sessions: sessions, orgID: org.Id,
		patOK: func(string) caller {
			return caller{name: "pat-ok", pat: patAll}
		},
		patWrong:  caller{name: "pat-wrong", pat: patNone},
		patSignIn: caller{name: "pat-sign-in", pat: patGrant},
	}
}

// opRequest builds a request for an operation. prep runs per-case for
// destructive routes so state mutations never leak across cases.
type opRequest struct {
	method string
	path   func(seed *matrixSeed, caseID string) string
	body   func(seed *matrixSeed, caseID string) any
	// prep creates disposable state and may return a path suffix.
	prep func(seed *matrixSeed, caseID string) string
	// skipCallers names callers that cannot meaningfully run this op.
	skipCallers map[string]bool
}

// requestFactories: one per declared, chokepoint-guarded operation.
func requestFactories(env *testEnv) map[string]opRequest {
	uniq := 0
	nextUniq := func() string { uniq++; return fmt.Sprintf("%s%d", env.sfx, uniq) }

	return map[string]opRequest{
		"getMeta":        {method: "GET", path: sPath("/api/v1/meta")},
		"getAdvisory":    {method: "GET", path: sPath("/api/v1/advisories/00000000-0000-0000-0000-000000000000")},
		"getOrg":         {method: "GET", path: orgPath("")},
		"getUserProfile": {method: "GET", path: func(s *matrixSeed, _ string) string { return "/api/v1/users/" + s.pawnH }},
		"getCurrentUser": {method: "GET", path: sPath("/api/v1/user")},
		"updateCurrentUser": {
			method: "PATCH", path: sPath("/api/v1/user"),
			body: func(*matrixSeed, string) any { return map[string]any{"displayName": "Matrix Caller"} },
		},
		// A new activation link: the matrix's callers are
		// confirmed, so past the gate it is a 409, which is a PASS here;
		// activation_db_test.go covers the mail, the limit and the link.
		"sendEmailVerification": {method: "POST", path: sPath("/api/v1/user/email-verification")},
		"listTokens":            {method: "GET", path: sPath("/api/v1/user/tokens")},
		"createToken": {
			method: "POST", path: sPath("/api/v1/user/tokens"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"name": "t-" + nextUniq(), "scopes": []string{"user:profile"}}
			},
		},
		"listSshKeys": {method: "GET", path: sPath("/api/v1/user/ssh-keys")},
		"addSshKey": {
			method: "POST", path: sPath("/api/v1/user/ssh-keys"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"title": "k-" + nextUniq(), "publicKey": matrixSSHKey()}
			},
		},
		"removeSshKey": {
			method: "DELETE",
			path: func(s *matrixSeed, caseID string) string {
				return "/api/v1/user/ssh-keys/" + uuid.NewString()
			},
		},
		"createDesktopGrant": {
			method: "POST", path: sPath("/api/v1/user/tokens/desktop-grant"),
			body: func(*matrixSeed, string) any { return map[string]any{"state": "matrix-state-" + nextUniq()} },
		},
		"revokeToken": {
			method: "DELETE",
			// Each session caller revokes a token they mint in prep; PAT and
			// anonymous callers are denied before lookup, any UUID works.
			prep: func(s *matrixSeed, caseID string) string {
				return "" // path handles it via closure below
			},
			path: func(s *matrixSeed, caseID string) string {
				return "/api/v1/user/tokens/" + uuid.NewString()
			},
		},
		"listUserSessions":            {method: "GET", path: sPath("/api/v1/user/sessions")},
		"listUserDependencyAlerts":    {method: "GET", path: sPath("/api/v1/user/dependency-alerts")},
		"listUserActivity":            {method: "GET", path: sPath("/api/v1/user/activity")},
		"getUserNotificationSettings": {method: "GET", path: sPath("/api/v1/user/notifications")},
		"updateUserNotificationSettings": {
			method: "PUT", path: sPath("/api/v1/user/notifications"),
			body: func(*matrixSeed, string) any {
				return map[string]any{
					"email": map[string]any{"dependencyAlerts": true, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true},
					"web":   map[string]any{"dependencyAlerts": true},
				}
			},
		},
		"getUserReportSettings": {method: "GET", path: sPath("/api/v1/user/report-settings")},
		"updateUserReportSettings": {
			method: "PUT", path: sPath("/api/v1/user/report-settings"),
			body: func(*matrixSeed, string) any {
				doc, _ := reportdesign.BuiltinDocument("classic")
				return map[string]any{"design": json.RawMessage(doc)}
			},
		},
		// A JSON body is not the multipart the route reads: an authorized
		// caller gets 400, and the matrix judges only who reaches it.
		"putUserReportLogo":    {method: "PUT", path: sPath("/api/v1/user/report-settings/logo"), body: func(*matrixSeed, string) any { return map[string]any{} }},
		"deleteUserReportLogo": {method: "DELETE", path: sPath("/api/v1/user/report-settings/logo")},
		// Public read; the registry has never seen this version, so 404.
		"getMcpServerScan": {method: "GET", path: sPath("/api/v1/mcp-servers/scan?ecosystem=npm&package=nobody&version=0.0.0")},
		// Non-destructive by construction: the query spares the calling
		// session, and every matrix caller holds exactly one.
		"revokeOtherUserSessions": {method: "DELETE", path: sPath("/api/v1/user/sessions")},
		"countTrustedDevices":     {method: "GET", path: sPath("/api/v1/user/trusted-devices")},
		"clearTrustedDevices":     {method: "DELETE", path: sPath("/api/v1/user/trusted-devices")},
		"revokeUserSession": {
			// A random id belongs to nobody, so an authorized caller gets 404
			// (not denied) and no fixture session is destroyed.
			method: "DELETE",
			path: func(*matrixSeed, string) string {
				return "/api/v1/user/sessions/" + uuid.NewString()
			},
		},
		"createOrg": {
			method: "POST", path: sPath("/api/v1/orgs"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"handle": "mo" + nextUniq(), "displayName": "M"}
			},
		},
		// The lifecycle. A wrong confirmation stops an
		// authorized caller at 422 before the fixture organization is
		// touched; the domain routes read, or answer 404 for a caller at a
		// shared domain, which every matrix caller is.
		"decommissionOrg": {
			method: "POST", path: orgPath("/decommission"),
			body: func(*matrixSeed, string) any { return map[string]any{"confirm": "not-the-handle"} },
		},
		"getDomainOrg":           {method: "GET", path: sPath("/api/v1/user/domain-org")},
		"requestDomainOrgAccess": {method: "POST", path: sPath("/api/v1/user/domain-org/request-access")},
		"updateOrg": {
			method: "PATCH", path: orgPath(""),
			body: func(*matrixSeed, string) any { return map[string]any{"displayName": "Matrix Org"} },
		},
		"listOrgMembers": {method: "GET", path: orgPath("/members")},
		"setOrgMember": {
			method: "PUT",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/orgs/" + s.orgH + "/members/" + s.pawnH },
			body:   func(*matrixSeed, string) any { return map[string]any{"role": "member"} },
		},
		"removeOrgMember": {
			method: "DELETE",
			path: func(s *matrixSeed, caseID string) string {
				// Disposable member per case: seeded by the admin in prep.
				return "/api/v1/orgs/" + s.orgH + "/members/" + caseID
			},
			prep: func(s *matrixSeed, caseID string) string {
				// A disposable member per case. Seeded directly: the
				// invitation door is exercised by its own tests, and one
				// organization per person would refuse a second
				// active membership for a matrix caller anyway.
				s.env.createAccount(caseID, caseID+"@example.test", true)
				s.env.seedMembership(s.orgH, caseID, "member", "active")
				return ""
			},
		},
		"listTeams": {method: "GET", path: orgPath("/teams")},
		"createTeam": {
			method: "POST", path: orgPath("/teams"),
			body: func(*matrixSeed, string) any { return map[string]any{"slug": "t" + nextUniq()} },
		},
		"deleteTeam": {
			method: "DELETE",
			path: func(s *matrixSeed, caseID string) string {
				return "/api/v1/orgs/" + s.orgH + "/teams/" + caseID
			},
			prep: func(s *matrixSeed, caseID string) string {
				s.env.doJSON(s.sessions["admin"], http.MethodPost, "/api/v1/orgs/"+s.orgH+"/teams",
					map[string]any{"slug": caseID}, nil, http.StatusCreated)
				return ""
			},
		},
		"listTeamMembers": {method: "GET", path: orgPath("/teams/mx-team/members")},
		"addTeamMember": {
			method: "PUT",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/teams/mx-team/members/" + s.pawnH
			},
		},
		"removeTeamMember": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/teams/mx-team/members/" + s.pawnH
			},
			prep: func(s *matrixSeed, _ string) string {
				// (Re-)add so removal always has a target.
				s.env.doJSON(s.sessions["admin"], http.MethodPut,
					"/api/v1/orgs/"+s.orgH+"/teams/mx-team/members/"+s.pawnH, nil, nil, http.StatusNoContent)
				return ""
			},
		},
		"listOrgAudit": {method: "GET", path: orgPath("/audit")},
		"submitVersion": {
			method: "POST", path: agentPath("/versions"),
			body: func(*matrixSeed, string) any { return map[string]any{"tag": "v9.9.9"} },
		},
		"listVersions":        {method: "GET", path: agentPath("/versions")},
		"getVersionInfo":      {method: "GET", path: agentPath("/versions/9.9.9")},
		"streamVersionEvents": {method: "GET", path: agentPath("/versions/9.9.9/events")},
		"getVersionManifest":  {method: "GET", path: agentPath("/versions/9.9.9/manifest")},
		"yankVersion": {
			method: "POST", path: agentPath("/versions/9.9.9/yank"),
			body: func(*matrixSeed, string) any { return map[string]any{"reason": "matrix"} },
		},
		"downloadVersion":  {method: "GET", path: agentPath("/versions/9.9.9/download")},
		"listVersionFiles": {method: "GET", path: agentPath("/versions/9.9.9/files")},
		"getVersionFile":   {method: "GET", path: agentPath("/versions/9.9.9/file?path=agent.yaml")},
		"resolveRef": {
			method: "GET",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/resolve?ref=" + s.orgH + "/mx-agent" },
		},
		"searchAgents": {method: "GET", path: sPath("/api/v1/search?q=matrix")},
		// deleteCurrentUser is destructive: the flow test covers sessions;
		// the matrix only checks that anonymous and PAT callers are refused.
		"deleteCurrentUser": {
			method: "POST", path: sPath("/api/v1/user/delete"),
			skipCallers: map[string]bool{"admin": true, "security_reviewer": true, "member": true, "pending": true, "outsider": true},
		},
		// clearCurrentUserData is destructive in the same way: the flow test
		// covers sessions; the matrix checks anonymous and PAT callers.
		"clearCurrentUserData": {
			method: "POST", path: sPath("/api/v1/user/clear-data"),
			skipCallers: map[string]bool{"admin": true, "security_reviewer": true, "member": true, "pending": true, "outsider": true},
		},
		"getAgentReadme":        {method: "GET", path: agentPath("/readme")},
		"getVersionReport":      {method: "GET", path: agentPath("/versions/9.9.9/report")},
		"getVersionAttestation": {method: "GET", path: agentPath("/versions/9.9.9/attestation")},
		"getPlatformPolicy":     {method: "GET", path: sPath("/api/v1/platform/policy")},
		"getOrgPolicy":          {method: "GET", path: orgPath("/policy")},
		// The logo. The matrix judges authorization, not the
		// upload: an admin's JSON body is a 400 past the gate, which is a
		// PASS; the multipart path is org_logo_test.go's.
		"getOrgLogo":    {method: "GET", path: orgPath("/logo")},
		"putOrgLogo":    {method: "PUT", path: orgPath("/logo"), body: func(*matrixSeed, string) any { return map[string]any{} }},
		"deleteOrgLogo": {method: "DELETE", path: orgPath("/logo")},
		"setOrgPolicy": {
			method: "PUT", path: orgPath("/policy"),
			body: func(*matrixSeed, string) any { return map[string]any{"maxAutoPublishSeverity": "info"} },
		},
		"listAdvisories": {
			method: "GET",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/advisories?affecting=" + s.orgH + "/mx-agent" },
		},
		"createAgent": {
			method: "POST", path: sPath("/api/v1/agents"),
			body: func(s *matrixSeed, _ string) any {
				return map[string]any{"namespace": s.orgH, "name": "ag" + nextUniq(), "modes": []string{"autonomous"}}
			},
		},
		"listAgents": {
			method: "GET",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/agents?namespace=" + s.orgH },
		},
		"getAgent":          {method: "GET", path: agentPath("")},
		"updateAgent":       {method: "PATCH", path: agentPath(""), body: func(*matrixSeed, string) any { return map[string]any{"summary": "matrix"} }},
		"listAgentGrants":   {method: "GET", path: agentPath("/grants")},
		"listAgentActivity": {method: "GET", path: agentPath("/activity")},
		"getAgentStats":     {method: "GET", path: agentPath("/stats")},
		"starAgent": {
			method: "PUT",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/user/stars/" + s.orgH + "/mx-agent" },
		},
		"unstarAgent": {
			method: "DELETE",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/user/stars/" + s.orgH + "/mx-agent" },
		},
		"listAccountInstalls": {method: "GET", path: sPath("/api/v1/user/installs")},
		// Knowledge packs: an authorized caller meets a pack
		// that is not theirs (404), a key that does not open for them (404)
		// or a short key (422) — never a denial — and nothing is stored.
		"listKnowledgePacks": {method: "GET", path: sPath("/api/v1/knowledge/packs")},
		"createKnowledgePack": {
			method: "POST", path: sPath("/api/v1/knowledge/packs"),
			body: func(_ *matrixSeed, id string) any {
				return map[string]any{"name": "mx" + id, "wrappedKey": map[string]any{"kind": "deployment", "recipient": "deployment:0", "key": "eA=="}}
			},
		},
		"getKnowledgePack":      {method: "GET", path: sPath("/api/v1/knowledge/packs/00000000-0000-0000-0000-000000000000")},
		"deleteKnowledgePack":   {method: "DELETE", path: sPath("/api/v1/knowledge/packs/00000000-0000-0000-0000-000000000000")},
		"uploadKnowledgeTree":   {method: "PUT", path: sPath("/api/v1/knowledge/packs/00000000-0000-0000-0000-000000000000/tree"), body: func(*matrixSeed, string) any { return "not a sealed tree" }},
		"downloadKnowledgeTree": {method: "GET", path: sPath("/api/v1/knowledge/packs/00000000-0000-0000-0000-000000000000/tree")},
		"exportKnowledgePack":   {method: "GET", path: sPath("/api/v1/knowledge/packs/00000000-0000-0000-0000-000000000000/export")},
		"wrapKnowledgeKey": {
			method: "POST", path: sPath("/api/v1/knowledge/keys/wrap"),
			body: func(*matrixSeed, string) any { return map[string]any{"key": "c2hvcnQ="} },
		},
		"unwrapKnowledgeKey": {
			method: "POST", path: sPath("/api/v1/knowledge/keys/unwrap"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"kind": "deployment", "recipient": "deployment:0", "key": "eA=="}
			},
		},
		"getKnowledgeUsage": {method: "GET", path: sPath("/api/v1/knowledge/usage")},
		// The Writing Voice: the caller's own. The matrix's
		// server has no voice judge, so an authorized call meets the store
		// off (503) or a refused body (422) past the gate; nothing is stored.
		"getVoice":            {method: "GET", path: sPath("/api/v1/voice")},
		"putVoice":            {method: "PUT", path: sPath("/api/v1/voice"), body: func(*matrixSeed, string) any { return map[string]any{"text": "x", "source": "build"} }},
		"deleteVoice":         {method: "DELETE", path: sPath("/api/v1/voice")},
		"discardVoicePending": {method: "DELETE", path: sPath("/api/v1/voice/pending")},
		"restoreVoice":        {method: "POST", path: sPath("/api/v1/voice/restore")},
		"updateVoiceSettings": {method: "PUT", path: sPath("/api/v1/voice/settings"), body: func(*matrixSeed, string) any { return map[string]any{} }},
		// An organization's shared knowledge: the same shapes
		// under the fixture organization, every pack id a stranger's and
		// every key short or foreign, so an authorized caller meets a 404 or
		// a 422 past the gate and nothing is stored.
		"listOrgKnowledgePacks": {method: "GET", path: orgPath("/knowledge/packs")},
		"createOrgKnowledgePack": {
			method: "POST", path: orgPath("/knowledge/packs"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"name": "mx-pack", "wrappedKey": map[string]any{"kind": "deployment", "recipient": "deployment:none", "key": "AAAA"}}
			},
		},
		"getOrgKnowledgePack": {method: "GET", path: orgPath("/knowledge/packs/00000000-0000-0000-0000-000000000000")},
		"updateOrgKnowledgePack": {
			method: "PATCH", path: orgPath("/knowledge/packs/00000000-0000-0000-0000-000000000000"),
			body: func(*matrixSeed, string) any { return map[string]any{"exportable": true} },
		},
		"deleteOrgKnowledgePack":   {method: "DELETE", path: orgPath("/knowledge/packs/00000000-0000-0000-0000-000000000000")},
		"uploadOrgKnowledgeTree":   {method: "PUT", path: orgPath("/knowledge/packs/00000000-0000-0000-0000-000000000000/tree"), body: func(*matrixSeed, string) any { return "not a sealed tree" }},
		"downloadOrgKnowledgeTree": {method: "GET", path: orgPath("/knowledge/packs/00000000-0000-0000-0000-000000000000/tree")},
		"exportOrgKnowledgePack":   {method: "GET", path: orgPath("/knowledge/packs/00000000-0000-0000-0000-000000000000/export")},
		"wrapOrgKnowledgeKey": {
			method: "POST", path: orgPath("/knowledge/keys/wrap"),
			body: func(*matrixSeed, string) any { return map[string]any{"key": "c2hvcnQ="} },
		},
		"unwrapOrgKnowledgeKey": {
			method: "POST", path: orgPath("/knowledge/keys/unwrap"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"kind": "deployment", "recipient": "deployment:none", "key": "AAAA"}
			},
		},
		"getOrgKnowledgeUsage": {method: "GET", path: orgPath("/knowledge/usage")},
		// The fixture agent has no published version, so an authorized
		// caller gets 404 (not denied) and nothing is recorded.
		"putAccountInstall": {
			method: "PUT",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/user/installs/" + s.orgH + "/mx-agent" },
			body:   func(*matrixSeed, string) any { return map[string]any{"version": "1.0.0", "acceptCapabilities": true} },
		},
		"deleteAccountInstall": {
			method: "DELETE",
			path:   func(s *matrixSeed, _ string) string { return "/api/v1/user/installs/" + s.orgH + "/mx-agent" },
		},
		"deleteAgent": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/agents/" + s.orgH + "/mx-undeletable"
			},
		},
		// Retire changes the agent it touches, so each case retires a
		// public agent of its own, made in the path (prep runs only for
		// allowed callers, and a refused caller must meet a public agent to
		// be refused with a 403 rather than a missing name's 404).
		"retireAgent": {
			method: "POST",
			path: func(s *matrixSeed, caseID string) string {
				s.env.doJSON(s.sessions["admin"], http.MethodPost, "/api/v1/agents", map[string]any{
					"namespace": s.orgH, "name": caseID, "modes": []string{"autonomous"}, "visibility": "public",
				}, nil, http.StatusCreated)
				return "/api/v1/agents/" + s.orgH + "/" + caseID + "/retire"
			},
		},
		// The fixture agent has no published version: an allowed caller
		// gets 409 nothing-to-fork, a refused one its 401 or 403, and no
		// fork is made. A session forks into its own
		// namespace, as createAgent's does below.
		"forkAgent": {
			method: "POST",
			path:   agentPath("/fork"),
			body: func(s *matrixSeed, caseID string) any {
				return map[string]any{"namespace": s.orgH, "name": "fk" + caseID}
			},
		},
		// The fixture agent is not retired: an allowed caller gets 409
		// agent-not-retired, a refused one its 403, and nothing changes.
		"restoreAgent": {
			method: "POST",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/agents/" + s.orgH + "/mx-agent/restore"
			},
		},
		"listAgentsByTag": {method: "GET", path: sPath("/api/v1/tags/matrix")},
		"setAgentUserGrant": {
			method: "PUT",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/agents/" + s.orgH + "/mx-agent/grants/user/" + s.pawnH
			},
			body: func(*matrixSeed, string) any { return map[string]any{"role": "read"} },
		},
		"removeAgentUserGrant": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/agents/" + s.orgH + "/mx-agent/grants/user/" + s.pawnH
			},
			prep: func(s *matrixSeed, _ string) string {
				s.env.doJSON(s.sessions["admin"], http.MethodPut,
					"/api/v1/agents/"+s.orgH+"/mx-agent/grants/user/"+s.pawnH,
					map[string]any{"role": "read"}, nil, http.StatusNoContent)
				return ""
			},
		},
		"setAgentTeamGrant": {
			method: "PUT",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/agents/" + s.orgH + "/mx-agent/grants/team/mx-team"
			},
			body: func(*matrixSeed, string) any { return map[string]any{"role": "read"} },
		},
		"removeAgentTeamGrant": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/agents/" + s.orgH + "/mx-agent/grants/team/mx-team"
			},
			prep: func(s *matrixSeed, _ string) string {
				s.env.doJSON(s.sessions["admin"], http.MethodPut,
					"/api/v1/agents/"+s.orgH+"/mx-agent/grants/team/mx-team",
					map[string]any{"role": "read"}, nil, http.StatusNoContent)
				return ""
			},
		},
		"logout": {method: "POST", path: sPath("/api/v1/auth/logout"), skipCallers: map[string]bool{"admin": true, "security_reviewer": true, "member": true, "pending": true, "outsider": true}},

		// Enterprise: webhooks/domains = admin+; audit export = admin+
		// (audit:read). Allowed callers may still get 404/422 (missing
		// target / invalid config) — the matrix only asserts the authz
		// outcome (not 401/403), so these are fine.
		"listWebhooks": {method: "GET", path: orgPath("/webhooks")},
		"createWebhook": {
			method: "POST", path: orgPath("/webhooks"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"url": "https://example.com/hook", "events": []string{"member.added"}}
			},
		},
		"getWebhook": {
			method: "GET",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/webhooks/" + uuid.NewString()
			},
		},
		"updateWebhook": {
			method: "PATCH",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/webhooks/" + uuid.NewString()
			},
			body: func(*matrixSeed, string) any { return map[string]any{"active": false} },
		},
		"deleteWebhook": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/webhooks/" + uuid.NewString()
			},
		},
		"listWebhookDeliveries": {
			method: "GET",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/webhooks/" + uuid.NewString() + "/deliveries"
			},
		},
		"pingWebhook": {
			method: "POST",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/webhooks/" + uuid.NewString() + "/ping"
			},
		},
		// Invitations and approvals. The approve/decline
		// targets are the pawn, an ACTIVE member: an authorized caller gets
		// 409 rather than changing the fixture, which the matrix counts as
		// a pass.
		"listInvitations": {method: "GET", path: orgPath("/invitations")},
		"createInvitation": {
			method: "POST", path: orgPath("/invitations"),
			body: func(s *matrixSeed, caseID string) any {
				return map[string]any{"email": caseID + "@invite.example", "role": "member"}
			},
		},
		"revokeInvitation": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/invitations/" + uuid.NewString()
			},
		},
		"approveOrgMember": {
			method: "POST",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/members/" + s.pawnH + "/approve"
			},
		},
		"declineOrgMember": {
			method: "POST",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/members/" + s.pawnH + "/decline"
			},
		},
		"listDomainClaims": {method: "GET", path: orgPath("/domain-claims")},
		"createDomainClaim": {
			method: "POST", path: orgPath("/domain-claims"),
			body: func(s *matrixSeed, _ string) any { return map[string]any{"domain": "mx-" + s.env.sfx + ".example.com"} },
		},
		"verifyDomainClaim": {
			method: "POST", path: orgPath("/domain-claims/verify"),
			body: func(*matrixSeed, string) any { return map[string]any{"domain": "absent.example.com"} },
		},
		"createAuditExport": {
			method: "POST", path: orgPath("/audit/exports"),
			body: func(*matrixSeed, string) any { return map[string]any{} },
		},
		"getAuditExport": {
			method: "GET",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/audit/exports/" + uuid.NewString()
			},
		},
	}
}

func sPath(p string) func(*matrixSeed, string) string {
	return func(*matrixSeed, string) string { return p }
}

func orgPath(suffix string) func(*matrixSeed, string) string {
	return func(s *matrixSeed, _ string) string { return "/api/v1/orgs/" + s.orgH + suffix }
}

func agentPath(suffix string) func(*matrixSeed, string) string {
	return func(s *matrixSeed, _ string) string { return "/api/v1/agents/" + s.orgH + "/mx-agent" + suffix }
}

// TestAuthzMatrix executes the full matrix. Expected outcomes derive from
// the declaration + auth.Check (the chokepoint), whose own truth table is
// pinned separately in internal/auth. "Allowed" asserts the response is NOT
// 401/403; handlers may still return domain statuses (404/422) afterwards.
func TestAuthzMatrix(t *testing.T) {
	env := newTestEnv(t)
	seed := seedMatrix(t, env)
	factories := requestFactories(env)

	// What the server will resolve for each caller. A pending membership
	// never reaches Principal.OrgRoles, so the expectation for "pending" is
	// an outsider's — which is the assertion.
	roleFor := map[string]auth.OrgRole{
		"admin":             auth.RoleAdmin,
		"security_reviewer": auth.RoleSecurityReviewer,
		"member":            auth.RoleMember,
		"pending":           auth.RoleNone,
		"outsider":          auth.RoleNone,
	}

	caseN := 0
	for opID, decl := range api.AllRouteAuthzDecls() {
		if decl.NoAuthz && opID != "getMeta" {
			continue // register/login/verifyEmail: separate flow tests
		}
		if decl.SelfAuthorized {
			continue // bespoke platform-staff/reviewer/author authz; handler tests cover these
		}
		fac, ok := factories[opID]
		if !ok {
			t.Errorf("no request factory for operation %q — matrix incomplete", opID)
			continue
		}

		type mcase struct {
			caller    caller
			principal *auth.Principal
		}
		cases := []mcase{{anonymous, &auth.Principal{Anonymous: true}}}
		for roleName, sess := range seed.sessions {
			if fac.skipCallers[roleName] {
				continue // state-destroying ops cover sessions in flow tests
			}
			p := &auth.Principal{UserID: uuid.New(), Via: "session", OrgRoles: map[uuid.UUID]auth.OrgRole{}}
			if r := roleFor[roleName]; r != auth.RoleNone {
				p.OrgRoles[seed.orgID] = r
			}
			cases = append(cases, mcase{sess, p})
		}
		// PAT callers (admin role, right scope vs wrong scope).
		patP := func(scopes ...string) *auth.Principal {
			return &auth.Principal{
				UserID: uuid.New(), Via: "pat", Scopes: scopes,
				OrgRoles: map[uuid.UUID]auth.OrgRole{seed.orgID: auth.RoleAdmin},
			}
		}
		cases = append(cases,
			mcase{seed.patOK(""), patP("org:admin", "audit:read", "user:profile", "agent:read")},
			mcase{seed.patWrong, patP("repo:read")},
			mcase{seed.patSignIn, patP(auth.SignInGrantScopes()...)},
		)

		for _, mc := range cases {
			caseN++
			caseID := fmt.Sprintf("mxc%s%d", env.sfx, caseN)
			name := fmt.Sprintf("%s/%s", opID, mc.caller.name)
			t.Run(name, func(t *testing.T) {
				// Session-only routes: revokeToken/createToken etc. need per
				// caller setup for the allowed path.
				if fac.prep != nil && expectAllowed(decl, mc.principal, seed.orgID) {
					fac.prep(seed, caseID)
				}
				path := fac.path(seed, caseID)
				var bodyOverride any
				if opID == "createAgent" && mc.caller.session != "" {
					// Personal namespace: the chokepoint admits any authed
					// caller; org-namespace policy is registry-level and
					// tested separately.
					bodyOverride = map[string]any{
						"namespace": mc.caller.name, "name": "ag" + caseID, "modes": []string{"autonomous"},
					}
				}
				if opID == "forkAgent" && mc.caller.session != "" {
					bodyOverride = map[string]any{"namespace": mc.caller.name, "name": "fk" + caseID}
				}
				if opID == "revokeToken" && mc.caller.session != "" {
					// Mint a disposable token as this caller to revoke.
					id, _ := env.mintPAT(mc.caller, "rv-"+caseID, "user:profile")
					path = "/api/v1/user/tokens/" + id
				}
				var body any
				if fac.body != nil {
					body = fac.body(seed, caseID)
				}
				if bodyOverride != nil {
					body = bodyOverride
				}
				res := env.do(mc.caller, fac.method, path, body)
				defer func() { _ = res.Body.Close() }()

				allowed := expectAllowed(decl, mc.principal, seed.orgID)
				gotDenied := res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden
				if decl.HiddenFromOutsiders && !mc.principal.Anonymous && mc.principal.Role(seed.orgID) == auth.RoleNone {
					// An outsider is refused as a 404, and only as a 404.
					if res.StatusCode != http.StatusNotFound {
						t.Fatalf("%s %s as %s: expected 404 for a caller outside the organization, got %d", fac.method, path, mc.caller.name, res.StatusCode)
					}
					return
				}
				if allowed && gotDenied {
					t.Fatalf("%s %s as %s: expected authz PASS, got %d", fac.method, path, mc.caller.name, res.StatusCode)
				}
				if !allowed && !gotDenied {
					t.Fatalf("%s %s as %s: expected authz DENY, got %d", fac.method, path, mc.caller.name, res.StatusCode)
				}
			})
		}
	}
	t.Logf("authz matrix: %d cases executed", caseN)
}

// expectAllowed mirrors what the route must enforce: the declared action
// through the chokepoint (plus the Anonymous flag for credential-less reads).
func expectAllowed(decl api.RouteDecl, p *auth.Principal, orgID uuid.UUID) bool {
	if p.Anonymous {
		return decl.Anonymous
	}
	if decl.NoAuthz {
		return true
	}
	if decl.AgentScoped {
		// The fixture agent is PUBLIC and org-owned with no explicit grants
		// for matrix callers: effective role = namespace-derived,
		// pinned separately in internal/auth tests.
		role := auth.NamespaceDerivedAgentRole(p, "org", orgID, p.OrgRoles[orgID])
		return auth.CheckAgent(p, auth.AgentResource{Public: true, EffectiveRole: role}, decl.Action) == nil
	}
	res := auth.Resource{}
	if decl.OrgScoped {
		res.OrgID = orgID
	}
	return auth.Check(p, res, decl.Action) == nil
}

// matrixSSHKey mints a fresh ed25519 public key line per call, so addSshKey
// never collides on the fingerprint uniqueness index across matrix cases.
func matrixSSHKey() string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " matrix"
}

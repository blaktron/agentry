package api_test

// The §17.4 authorization matrix: every declared route × every role ×
// own-org/other-org/anonymous/PAT-scope combination, executed as real HTTP
// requests. This is the tenant-isolation control (D-24, T-11).

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
)

// TestRouteDeclarationsComplete fails when an OpenAPI operation lacks a
// RouteDecl — a new route cannot ship without an authorization declaration.
func TestRouteDeclarationsComplete(t *testing.T) {
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	for path, item := range spec.Paths.Map() {
		for method, op := range item.Operations() {
			if op.OperationID == "" {
				t.Errorf("%s %s: missing operationId", method, path)
				continue
			}
			if _, ok := api.RouteAuthzDecl(op.OperationID); !ok {
				t.Errorf("%s %s (%s): no RouteDecl — declare it in authz_routes.go", method, path, op.OperationID)
			}
		}
	}
	// And the reverse: no stale declarations.
	ops := map[string]bool{}
	for _, item := range spec.Paths.Map() {
		for _, op := range item.Operations() {
			ops[api.NormalizeOpID(op.OperationID)] = true
		}
	}
	for id := range api.AllRouteAuthzDecls() {
		if !ops[id] {
			t.Errorf("RouteDecl %q has no matching OpenAPI operation", id)
		}
	}
}

// matrixSeed builds one org with every role plus an outsider, sessions for
// all, and PATs for the owner (right-scope and wrong-scope).
type matrixSeed struct {
	env      *testEnv
	orgH     string
	pawnH    string            // plain member used as a non-destructive PUT target
	sessions map[string]caller // by role name
	patOK    func(scope string) caller
	patWrong caller
	orgID    uuid.UUID
}

func seedMatrix(t *testing.T, env *testEnv) *matrixSeed {
	t.Helper()
	roles := []string{"owner", "admin", "security_reviewer", "member", "outsider"}
	sessions := map[string]caller{}
	for _, role := range roles {
		h := env.register("mx-" + role[:3])
		env.verifyEmail(h)
		sessions[role] = env.login(h)
	}
	orgH := "mxorg" + env.sfx
	env.doJSON(sessions["owner"], http.MethodPost, "/api/v1/orgs",
		map[string]any{"handle": orgH, "displayName": "Matrix Org"}, nil, http.StatusCreated)
	for _, role := range []string{"admin", "security_reviewer", "member"} {
		env.doJSON(sessions["owner"], http.MethodPut,
			"/api/v1/orgs/"+orgH+"/members/"+sessions[role].name,
			map[string]any{"role": role}, nil, http.StatusOK)
	}
	// A pawn member for non-destructive member-set targets.
	pawnH := env.register("mx-pawn")
	env.doJSON(sessions["owner"], http.MethodPut,
		"/api/v1/orgs/"+orgH+"/members/"+pawnH,
		map[string]any{"role": "member"}, nil, http.StatusOK)
	// A standing team for read routes.
	env.doJSON(sessions["owner"], http.MethodPost, "/api/v1/orgs/"+orgH+"/teams",
		map[string]any{"slug": "mx-team"}, nil, http.StatusCreated)
	env.doJSON(sessions["owner"], http.MethodPut,
		"/api/v1/orgs/"+orgH+"/teams/mx-team/members/"+pawnH, nil, nil, http.StatusNoContent)

	// A public agent in the org for agent-scoped routes.
	env.doJSON(sessions["owner"], http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "mx-agent", "kind": "skill", "visibility": "public",
	}, nil, http.StatusCreated)

	// A second public agent that deleteAgent targets. An abuse report pins it
	// in place: every authorized caller gets 409 instead of actually deleting
	// it, so the matrix (whose case order is map-random) cannot destroy the
	// fixture for later cases. The real delete path is covered by
	// TestDeleteAgent* in the M-10 handler tests.
	env.doJSON(sessions["owner"], http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": "mx-undeletable", "kind": "skill", "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(sessions["member"], http.MethodPost,
		"/api/v1/agents/"+orgH+"/mx-undeletable/abuse-reports",
		map[string]any{"category": "spam", "detail": "matrix fixture: keeps this agent undeletable"},
		nil, http.StatusAccepted)

	_, patAll := env.mintPAT(sessions["owner"], "matrix-ok",
		"org:admin", "audit:read", "user:profile", "agent:read")
	_, patNone := env.mintPAT(sessions["owner"], "matrix-wrong", "repo:read")

	var orgID uuid.UUID
	var out struct {
		Id uuid.UUID `json:"id"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH, nil, &out, http.StatusOK)
	orgID = out.Id

	return &matrixSeed{
		env: env, orgH: orgH, pawnH: pawnH, sessions: sessions, orgID: orgID,
		patOK: func(string) caller {
			return caller{name: "pat-ok", pat: patAll}
		},
		patWrong: caller{name: "pat-wrong", pat: patNone},
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
		"listTokens": {method: "GET", path: sPath("/api/v1/user/tokens")},
		"createToken": {
			method: "POST", path: sPath("/api/v1/user/tokens"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"name": "t-" + nextUniq(), "scopes": []string{"user:profile"}}
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
		"listUserSessions": {method: "GET", path: sPath("/api/v1/user/sessions")},
		"getUserDirectory": {method: "GET", path: sPath("/api/v1/user/directory")},
		// Non-destructive by construction: the query spares the calling
		// session, and every matrix caller holds exactly one.
		"revokeOtherUserSessions": {method: "DELETE", path: sPath("/api/v1/user/sessions")},
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
				// Disposable member per case: seeded by owner in prep.
				return "/api/v1/orgs/" + s.orgH + "/members/" + caseID
			},
			prep: func(s *matrixSeed, caseID string) string {
				// Register a disposable user, then add as a plain member.
				s.env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/register", map[string]any{
					"handle": caseID, "email": caseID + "@example.test", "password": "hunter2hunter2",
				}, nil, http.StatusCreated)
				s.env.doJSON(s.sessions["owner"], http.MethodPut,
					"/api/v1/orgs/"+s.orgH+"/members/"+caseID,
					map[string]any{"role": "member"}, nil, http.StatusOK)
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
				s.env.doJSON(s.sessions["owner"], http.MethodPost, "/api/v1/orgs/"+s.orgH+"/teams",
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
				s.env.doJSON(s.sessions["owner"], http.MethodPut,
					"/api/v1/orgs/"+s.orgH+"/teams/mx-team/members/"+s.pawnH, nil, nil, http.StatusNoContent)
				return ""
			},
		},
		"listOrgAudit": {method: "GET", path: orgPath("/audit")},
		"submitVersion": {
			method: "POST", path: agentPath("/versions"),
			body: func(*matrixSeed, string) any { return map[string]any{"tag": "v9.9.9"} },
		},
		"listVersions":       {method: "GET", path: agentPath("/versions")},
		"getVersionInfo":     {method: "GET", path: agentPath("/versions/9.9.9")},
		"getVersionManifest": {method: "GET", path: agentPath("/versions/9.9.9/manifest")},
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
			skipCallers: map[string]bool{"owner": true, "admin": true, "security_reviewer": true, "member": true, "outsider": true},
		},
		"getAgentReadme":        {method: "GET", path: agentPath("/readme")},
		"getVersionReport":      {method: "GET", path: agentPath("/versions/9.9.9/report")},
		"getVersionAttestation": {method: "GET", path: agentPath("/versions/9.9.9/attestation")},
		"getPlatformPolicy":     {method: "GET", path: sPath("/api/v1/platform/policy")},
		"getOrgPolicy":          {method: "GET", path: orgPath("/policy")},
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
				return map[string]any{"namespace": s.orgH, "name": "ag" + nextUniq(), "kind": "skill"}
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
		"deleteAgent": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/agents/" + s.orgH + "/mx-undeletable"
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
				s.env.doJSON(s.sessions["owner"], http.MethodPut,
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
				s.env.doJSON(s.sessions["owner"], http.MethodPut,
					"/api/v1/agents/"+s.orgH+"/mx-agent/grants/team/mx-team",
					map[string]any{"role": "read"}, nil, http.StatusNoContent)
				return ""
			},
		},
		"logout":    {method: "POST", path: sPath("/api/v1/auth/logout"), skipCallers: map[string]bool{"owner": true, "admin": true, "security_reviewer": true, "member": true, "outsider": true}},
		"totpSetup": {method: "POST", path: sPath("/api/v1/auth/2fa/totp/setup")},
		"totpVerify": {
			method: "POST", path: sPath("/api/v1/auth/2fa/totp/verify"),
			body: func(*matrixSeed, string) any { return map[string]any{"code": "000000"} },
		},

		// Enterprise (M6/WG-J). SSO/SCIM config = owner; webhooks/domains =
		// admin+; audit export = admin+ (audit:read). Allowed callers may still
		// get 404/422 (missing target / invalid config) — the matrix only
		// asserts the authz outcome (not 401/403), so these are fine.
		"listSsoConnections": {method: "GET", path: orgPath("/sso/connections")},
		"putSsoConnection": {
			method: "PUT", path: orgPath("/sso/connections/oidc"),
			body: func(*matrixSeed, string) any {
				return map[string]any{"enabled": false, "config": map[string]any{"issuer": "https://idp.example", "clientId": "x"}}
			},
		},
		"deleteSsoConnection": {method: "DELETE", path: orgPath("/sso/connections/oidc")},
		"listScimTokens":      {method: "GET", path: orgPath("/scim/tokens")},
		"createScimToken": {
			method: "POST", path: orgPath("/scim/tokens"),
			body: func(*matrixSeed, string) any { return map[string]any{} },
		},
		"revokeScimToken": {
			method: "DELETE",
			path: func(s *matrixSeed, _ string) string {
				return "/api/v1/orgs/" + s.orgH + "/scim/tokens/" + uuid.NewString()
			},
		},
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

	roleFor := map[string]auth.OrgRole{
		"owner": auth.RoleOwner, "admin": auth.RoleAdmin,
		"security_reviewer": auth.RoleSecurityReviewer,
		"member":            auth.RoleMember, "outsider": auth.RoleNone,
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
		// PAT callers (owner role, right scope vs wrong scope).
		patP := func(scopes ...string) *auth.Principal {
			return &auth.Principal{
				UserID: uuid.New(), Via: "pat", Scopes: scopes,
				OrgRoles: map[uuid.UUID]auth.OrgRole{seed.orgID: auth.RoleOwner},
			}
		}
		cases = append(cases,
			mcase{seed.patOK(""), patP("org:admin", "audit:read", "user:profile", "agent:read")},
			mcase{seed.patWrong, patP("repo:read")},
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
						"namespace": mc.caller.name, "name": "ag" + caseID, "kind": "skill",
					}
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
		// for matrix callers: effective role = namespace-derived (§12.2),
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

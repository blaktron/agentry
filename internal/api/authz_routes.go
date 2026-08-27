package api

import (
	"strings"

	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
)

// RouteDecl declares the authorization contract of one API operation
// (§12.2 "every route declares (resource, action)"). The declaration table
// drives the §17.4 authz matrix test; the completeness test fails CI when an
// OpenAPI operation lacks an entry, so a new route cannot ship undeclared.
type RouteDecl struct {
	// Action is the chokepoint action the handler enforces via authorize().
	Action auth.Action
	// OrgScoped routes resolve {org} and check the caller's role there.
	OrgScoped bool
	// Anonymous routes are readable without credentials.
	Anonymous bool
	// SessionOnly routes reject PATs regardless of scope (token minting,
	// 2FA, logout) — enforced by the action's absence from auth scope map.
	SessionOnly bool
	// NoAuthz marks routes outside the chokepoint: credential-establishing
	// endpoints (register/login/verify) that are rate-limited instead.
	NoAuthz bool
}

// NormalizeOpID canonicalizes an operationId: the generator capitalizes ids
// in the embedded spec, while the table uses the YAML's camelCase.
func NormalizeOpID(id string) string {
	if id == "" {
		return id
	}
	return strings.ToLower(id[:1]) + id[1:]
}

// RouteAuthzDecl returns the declaration for an operationId (any casing).
func RouteAuthzDecl(operationID string) (RouteDecl, bool) {
	d, ok := routeAuthz[NormalizeOpID(operationID)]
	return d, ok
}

// AllRouteAuthzDecls returns a copy of the declaration table (tests, docs).
func AllRouteAuthzDecls() map[string]RouteDecl {
	out := make(map[string]RouteDecl, len(routeAuthz))
	for k, v := range routeAuthz {
		out[k] = v
	}
	return out
}

// routeAuthz maps OpenAPI operationId → declaration. Keep alphabetical.
var routeAuthz = map[string]RouteDecl{
	"addTeamMember":     {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createOrg":         {Action: auth.ActOrgCreate},
	"createTeam":        {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createToken":       {Action: auth.ActUserTokensManage, SessionOnly: true},
	"deleteTeam":        {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"getCurrentUser":    {Action: auth.ActUserSelfRead},
	"getMeta":           {Action: auth.ActPublicRead, Anonymous: true, NoAuthz: true},
	"getOrg":            {Action: auth.ActOrgRead, OrgScoped: true, Anonymous: true},
	"getUserProfile":    {Action: auth.ActPublicRead, Anonymous: true},
	"listOrgAudit":      {Action: auth.ActOrgAuditRead, OrgScoped: true},
	"listOrgMembers":    {Action: auth.ActOrgMembersRead, OrgScoped: true},
	"listTeamMembers":   {Action: auth.ActOrgTeamsRead, OrgScoped: true},
	"listTeams":         {Action: auth.ActOrgTeamsRead, OrgScoped: true},
	"listTokens":        {Action: auth.ActUserTokensRead},
	"login":             {NoAuthz: true, Anonymous: true},
	"logout":            {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"register":          {NoAuthz: true, Anonymous: true},
	"removeOrgMember":   {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for owner/admin targets
	"removeTeamMember":  {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"revokeToken":       {Action: auth.ActUserTokensManage, SessionOnly: true},
	"setOrgMember":      {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for owner/admin roles
	"totpSetup":         {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"totpVerify":        {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"updateCurrentUser": {Action: auth.ActUserSelfUpdate},
	"updateOrg":         {Action: auth.ActOrgUpdate, OrgScoped: true},
	"verifyEmail":       {NoAuthz: true, Anonymous: true},
}

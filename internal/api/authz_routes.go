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
	// AgentScoped routes resolve {ns}/{name} and check the caller's
	// effective agent role via auth.CheckAgent.
	AgentScoped bool
	// SelfAuthorized routes perform their own bespoke authorization inside
	// the handler (platform-staff / org-reviewer / author checks that the
	// generic chokepoint cannot express). The matrix test skips outcome
	// prediction for these; the handlers' own tests cover them.
	SelfAuthorized bool
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
	"addTeamMember":         {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createAgent":           {Action: auth.ActAgentCreate, AgentScoped: false},
	"getAgent":              {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"listAgents":            {Action: auth.ActPublicRead, Anonymous: true},
	"updateAgent":           {Action: auth.ActAgentMaintain, AgentScoped: true},
	"listAgentGrants":       {Action: auth.ActAgentMaintain, AgentScoped: true},
	"setAgentUserGrant":     {Action: auth.ActAgentMaintain, AgentScoped: true},
	"removeAgentUserGrant":  {Action: auth.ActAgentMaintain, AgentScoped: true},
	"setAgentTeamGrant":     {Action: auth.ActAgentMaintain, AgentScoped: true},
	"removeAgentTeamGrant":  {Action: auth.ActAgentMaintain, AgentScoped: true},
	"submitVersion":         {Action: auth.ActAgentPublish, AgentScoped: true},
	"listVersions":          {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionInfo":        {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionManifest":    {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"yankVersion":           {Action: auth.ActAgentPublish, AgentScoped: true},
	"downloadVersion":       {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"resolveRef":            {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionReport":      {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionAttestation": {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"listReviewQueue":       {Action: auth.ActPublicRead, SelfAuthorized: true},
	"getReviewItem":         {Action: auth.ActPublicRead, SelfAuthorized: true},
	"decideReviewItem":      {Action: auth.ActPublicRead, SelfAuthorized: true},
	"setFindingVerdict":     {Action: auth.ActPublicRead, SelfAuthorized: true},
	"getPlatformPolicy":     {Action: auth.ActPublicRead, Anonymous: true},
	"getOrgPolicy":          {Action: auth.ActOrgUpdate, OrgScoped: true},
	"setOrgPolicy":          {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"platformAgentAction":   {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listAdvisories":        {Action: auth.ActPublicRead, Anonymous: true},
	"createOrg":             {Action: auth.ActOrgCreate},
	"createTeam":            {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createToken":           {Action: auth.ActUserTokensManage, SessionOnly: true},
	"deleteTeam":            {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"getCurrentUser":        {Action: auth.ActUserSelfRead},
	"getMeta":               {Action: auth.ActPublicRead, Anonymous: true, NoAuthz: true},
	"getOrg":                {Action: auth.ActOrgRead, OrgScoped: true, Anonymous: true},
	"getUserProfile":        {Action: auth.ActPublicRead, Anonymous: true},
	"listOrgAudit":          {Action: auth.ActOrgAuditRead, OrgScoped: true},
	"listOrgMembers":        {Action: auth.ActOrgMembersRead, OrgScoped: true},
	"listTeamMembers":       {Action: auth.ActOrgTeamsRead, OrgScoped: true},
	"listTeams":             {Action: auth.ActOrgTeamsRead, OrgScoped: true},
	"listTokens":            {Action: auth.ActUserTokensRead},
	"login":                 {NoAuthz: true, Anonymous: true},
	"logout":                {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"register":              {NoAuthz: true, Anonymous: true},
	"removeOrgMember":       {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for owner/admin targets
	"removeTeamMember":      {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"revokeToken":           {Action: auth.ActUserTokensManage, SessionOnly: true},
	"setOrgMember":          {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for owner/admin roles
	"totpSetup":             {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"totpVerify":            {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"updateCurrentUser":     {Action: auth.ActUserSelfUpdate},
	"updateOrg":             {Action: auth.ActOrgUpdate, OrgScoped: true},
	"verifyEmail":           {NoAuthz: true, Anonymous: true},
}

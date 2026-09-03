package api

import (
	"strings"

	"github.com/blaktron/agentry/internal/auth"
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
	"addTeamMember":     {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createAgent":       {Action: auth.ActAgentCreate, AgentScoped: false},
	"getAgent":          {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"listAgents":        {Action: auth.ActPublicRead, Anonymous: true},
	"getAdvisory":       {Action: auth.ActPublicRead, Anonymous: true},
	"updateAgent":       {Action: auth.ActAgentMaintain, AgentScoped: true},
	"deleteAgent":       {Action: auth.ActAgentMaintain, AgentScoped: true},
	"listAgentActivity": {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getAgentStats":     {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	// Stars are per-agent reads that mutate the CALLER's list, so they carry
	// the agent read action (you cannot star what you cannot see) and refuse
	// anonymous callers in the handler — there is no anonymous star list.
	"starAgent":             {Action: auth.ActAgentRead, AgentScoped: true},
	"unstarAgent":           {Action: auth.ActAgentRead, AgentScoped: true},
	"listAgentGrants":       {Action: auth.ActAgentMaintain, AgentScoped: true},
	"setAgentUserGrant":     {Action: auth.ActAgentMaintain, AgentScoped: true},
	"removeAgentUserGrant":  {Action: auth.ActAgentMaintain, AgentScoped: true},
	"setAgentTeamGrant":     {Action: auth.ActAgentMaintain, AgentScoped: true},
	"removeAgentTeamGrant":  {Action: auth.ActAgentMaintain, AgentScoped: true},
	"submitVersion":         {Action: auth.ActAgentPublish, AgentScoped: true},
	"listVersions":          {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionInfo":        {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"streamVersionEvents":   {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionManifest":    {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"yankVersion":           {Action: auth.ActAgentPublish, AgentScoped: true},
	"downloadVersion":       {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"listVersionFiles":      {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionFile":        {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"resolveRef":            {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionReport":      {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getVersionAttestation": {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"listReviewQueue":       {Action: auth.ActPublicRead, SelfAuthorized: true},
	"getReviewItem":         {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listReviewFiles":       {Action: auth.ActPublicRead, SelfAuthorized: true},
	"getReviewFile":         {Action: auth.ActPublicRead, SelfAuthorized: true},
	"decideReviewItem":      {Action: auth.ActPublicRead, SelfAuthorized: true},
	"setFindingVerdict":     {Action: auth.ActPublicRead, SelfAuthorized: true},
	"getPlatformPolicy":     {Action: auth.ActPublicRead, Anonymous: true},
	"getOrgPolicy":          {Action: auth.ActOrgUpdate, OrgScoped: true},
	"setOrgPolicy":          {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"platformAgentAction":   {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listAdvisories":        {Action: auth.ActPublicRead, Anonymous: true},
	"searchAgents":          {Action: auth.ActPublicRead, Anonymous: true},
	"listAgentsByTag":       {Action: auth.ActPublicRead, Anonymous: true},
	// Platform-staff surfaces: the staff flag is not an org role, so the
	// generic chokepoint cannot express them (requireStaff does).
	"createRulesetRelease": {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listPlatformAudit":    {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listRedTeamReports":   {Action: auth.ActPublicRead, SelfAuthorized: true},
	// Social login establishes a credential (like login/register), so it sits
	// outside the chokepoint and is rate-limited instead (§12.1).
	"socialOidcStart":    {NoAuthz: true, Anonymous: true},
	"socialOidcCallback": {NoAuthz: true, Anonymous: true},
	"totpChallenge":      {NoAuthz: true, Anonymous: true},
	"getAgentReadme":     {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"deleteCurrentUser":  {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"reportAbuse":        {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listAbuseReports":   {Action: auth.ActPublicRead, SelfAuthorized: true},
	"triageAbuseReport":  {Action: auth.ActPublicRead, SelfAuthorized: true},
	// Enterprise (M6/WG-J). SSO/SCIM config = owner (ActOrgSettingsManage,
	// session-only for PATs); webhooks/domains = admin+ (ActOrgUpdate);
	// audit export = admin+ (ActOrgAuditRead). The SSO login-flow endpoints
	// establish credentials (like login/register) so they are NoAuthz. The
	// SCIM data plane (/scim/v2) is mounted outside the generated handler and
	// authenticates by SCIM token — no RouteDecl (see handlers_scim.go).
	"listSsoConnections":    {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"putSsoConnection":      {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"deleteSsoConnection":   {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"testSsoConnection":     {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"getSamlMetadata":       {NoAuthz: true, Anonymous: true},
	"samlAcs":               {NoAuthz: true, Anonymous: true},
	"oidcStart":             {NoAuthz: true, Anonymous: true},
	"oidcCallback":          {NoAuthz: true, Anonymous: true},
	"listScimTokens":        {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"createScimToken":       {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"revokeScimToken":       {Action: auth.ActOrgSettingsManage, OrgScoped: true},
	"listWebhooks":          {Action: auth.ActOrgUpdate, OrgScoped: true},
	"createWebhook":         {Action: auth.ActOrgUpdate, OrgScoped: true},
	"getWebhook":            {Action: auth.ActOrgUpdate, OrgScoped: true},
	"updateWebhook":         {Action: auth.ActOrgUpdate, OrgScoped: true},
	"deleteWebhook":         {Action: auth.ActOrgUpdate, OrgScoped: true},
	"listWebhookDeliveries": {Action: auth.ActOrgUpdate, OrgScoped: true},
	"pingWebhook":           {Action: auth.ActOrgUpdate, OrgScoped: true},
	"listDomainClaims":      {Action: auth.ActOrgUpdate, OrgScoped: true},
	"createDomainClaim":     {Action: auth.ActOrgUpdate, OrgScoped: true},
	"verifyDomainClaim":     {Action: auth.ActOrgUpdate, OrgScoped: true},
	"createAuditExport":     {Action: auth.ActOrgAuditRead, OrgScoped: true},
	"getAuditExport":        {Action: auth.ActOrgAuditRead, OrgScoped: true},
	"createOrg":             {Action: auth.ActOrgCreate},
	"createTeam":            {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createToken":           {Action: auth.ActUserTokensManage, SessionOnly: true},
	"createDesktopGrant":    {Action: auth.ActUserTokensManage, SessionOnly: true},
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
	// Sessions: listing rides the self-read action so a `user:profile` PAT is
	// admitted and answered with an empty list (a PAT has no sessions of its
	// own); revoking is session-only, like logout — a token must not be able
	// to sign its holder's browsers out.
	"listUserSessions":        {Action: auth.ActUserSelfRead},
	"revokeUserSession":       {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"revokeOtherUserSessions": {Action: auth.ActUserSecurityManage, SessionOnly: true},
	// The rule bundle is the same artifact the CLI already embeds; serving it
	// discloses nothing that shipping the binary did not.
	"getLatestRulesetBundle":      {Action: auth.ActPublicRead, Anonymous: true, NoAuthz: true},
	"getLatestRulesetAttestation": {Action: auth.ActPublicRead, Anonymous: true, NoAuthz: true},
	"login":                       {NoAuthz: true, Anonymous: true},
	"exchangeDesktopCode":         {NoAuthz: true, Anonymous: true},
	"logout":                      {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"register":                    {NoAuthz: true, Anonymous: true},
	"removeOrgMember":             {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for owner/admin targets
	"removeTeamMember":            {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"revokeToken":                 {Action: auth.ActUserTokensManage, SessionOnly: true},
	"setOrgMember":                {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for owner/admin roles
	"totpSetup":                   {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"totpVerify":                  {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"updateCurrentUser":           {Action: auth.ActUserSelfUpdate},
	"updateOrg":                   {Action: auth.ActOrgUpdate, OrgScoped: true},
	"verifyEmail":                 {NoAuthz: true, Anonymous: true},
}

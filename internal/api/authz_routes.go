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
	"addTeamMember": {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createAgent":   {Action: auth.ActAgentCreate, AgentScoped: false},
	"getAgent":      {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"listAgents":    {Action: auth.ActPublicRead, Anonymous: true},
	"getAdvisory":   {Action: auth.ActPublicRead, Anonymous: true},
	// updateAgent stays at maintain: its fields are the agent's settings,
	// which a publisher may change. The one field that is not — visibility
	// — is checked against ActAgentAdminister in the handler, the way
	// ssoRequired is inside updateOrg.
	"updateAgent":       {Action: auth.ActAgentMaintain, AgentScoped: true},
	"deleteAgent":       {Action: auth.ActAgentAdminister, AgentScoped: true},
	"listAgentActivity": {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"getAgentStats":     {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	// Stars are per-agent reads that mutate the CALLER's list, so they carry
	// the agent read action (you cannot star what you cannot see) and refuse
	// anonymous callers in the handler — there is no anonymous star list.
	"starAgent":   {Action: auth.ActAgentRead, AgentScoped: true},
	"unstarAgent": {Action: auth.ActAgentRead, AgentScoped: true},
	// Account installs (agentry#448) are the CALLER's own record, so they
	// carry the self actions — a PAT needs user:profile, as it does for
	// the notification settings — and the handler resolves the BriefAgent
	// for read first, so a non-reader gets the missing name's 404 and a
	// PAT recording a private BriefAgent needs agent:read as well.
	"listAccountInstalls":  {Action: auth.ActUserSelfRead},
	"putAccountInstall":    {Action: auth.ActUserSelfUpdate},
	"deleteAccountInstall": {Action: auth.ActUserSelfUpdate},
	// The grants are administrative: handing someone access to an
	// organization's private agent is a disclosure, so it belongs with the
	// admins rather than with everyone who may publish (agentry#362).
	"listAgentGrants":       {Action: auth.ActAgentAdminister, AgentScoped: true},
	"setAgentUserGrant":     {Action: auth.ActAgentAdminister, AgentScoped: true},
	"removeAgentUserGrant":  {Action: auth.ActAgentAdminister, AgentScoped: true},
	"setAgentTeamGrant":     {Action: auth.ActAgentAdminister, AgentScoped: true},
	"removeAgentTeamGrant":  {Action: auth.ActAgentAdminister, AgentScoped: true},
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
	// The logo (agentry#367): readable by anyone who may see the
	// organization, set and removed by its admins behind Features.Branding.
	"getOrgLogo":          {Action: auth.ActPublicRead, Anonymous: true},
	"putOrgLogo":          {Action: auth.ActOrgBrandingManage, OrgScoped: true},
	"deleteOrgLogo":       {Action: auth.ActOrgBrandingManage, OrgScoped: true},
	"platformAgentAction": {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listAdvisories":      {Action: auth.ActPublicRead, Anonymous: true},
	"getMcpServerScan":    {Action: auth.ActPublicRead, Anonymous: true},
	"searchAgents":        {Action: auth.ActPublicRead, Anonymous: true},
	"listAgentsByTag":     {Action: auth.ActPublicRead, Anonymous: true},
	// Platform-staff surfaces: the staff flag is not an org role, so the
	// generic chokepoint cannot express them (requireStaff does).
	"createRulesetRelease": {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listRulesetReleases":  {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listPlatformAudit":    {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listRedTeamReports":   {Action: auth.ActPublicRead, SelfAuthorized: true},
	// Social login establishes a credential (like login/register), so it sits
	// outside the chokepoint and is rate-limited instead (§12.1).
	"socialOidcStart":      {NoAuthz: true, Anonymous: true},
	"socialOidcCallback":   {NoAuthz: true, Anonymous: true},
	"totpChallenge":        {NoAuthz: true, Anonymous: true},
	"getAgentReadme":       {Action: auth.ActAgentRead, AgentScoped: true, Anonymous: true},
	"deleteCurrentUser":    {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"clearCurrentUserData": {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"reportAbuse":          {Action: auth.ActPublicRead, SelfAuthorized: true},
	"listAbuseReports":     {Action: auth.ActPublicRead, SelfAuthorized: true},
	// Staff see an account's knowledge packs by name and size, nothing of
	// their content (agentry#593): requireStaff, and knowledge:read on a
	// token, inside the handler.
	"listKnowledgePackSizes": {Action: auth.ActPublicRead, SelfAuthorized: true},
	"triageAbuseReport":      {Action: auth.ActPublicRead, SelfAuthorized: true},
	// Enterprise (M6/WG-J). SSO/SCIM config = admin (ActOrgSettingsManage,
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
	"samlSloRedirect":       {NoAuthz: true, Anonymous: true},
	"samlSloPost":           {NoAuthz: true, Anonymous: true},
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
	// The lifecycle (agentry#363). Decommissioning is the admins' and a
	// session's; suspending and reinstating are platform staff's, which
	// the chokepoint cannot express (requireStaff does).
	"decommissionOrg":    {Action: auth.ActOrgDecommission, OrgScoped: true, SessionOnly: true},
	"suspendOrg":         {Action: auth.ActPublicRead, SelfAuthorized: true},
	"reinstateOrg":       {Action: auth.ActPublicRead, SelfAuthorized: true},
	"createTeam":         {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"createToken":        {Action: auth.ActUserTokensManage, SessionOnly: true},
	"createDesktopGrant": {Action: auth.ActUserTokensManage, SessionOnly: true},
	"deleteTeam":         {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"getCurrentUser":     {Action: auth.ActUserSelfRead},
	// Knowledge packs (agentry#593) are the CALLER's own: self-scoped, each
	// looked up by its owner, so another account's pack is a 404.
	"listKnowledgePacks":    {Action: auth.ActKnowledgeRead},
	"createKnowledgePack":   {Action: auth.ActKnowledgeWrite},
	"getKnowledgePack":      {Action: auth.ActKnowledgeRead},
	"deleteKnowledgePack":   {Action: auth.ActKnowledgeWrite},
	"uploadKnowledgeTree":   {Action: auth.ActKnowledgeWrite},
	"downloadKnowledgeTree": {Action: auth.ActKnowledgeRead},
	"exportKnowledgePack":   {Action: auth.ActKnowledgeRead},
	"wrapKnowledgeKey":      {Action: auth.ActKnowledgeWrite},
	"unwrapKnowledgeKey":    {Action: auth.ActKnowledgeRead},
	"getKnowledgeUsage":     {Action: auth.ActKnowledgeRead},
	"getMeta":               {Action: auth.ActPublicRead, Anonymous: true, NoAuthz: true},
	"getOrg":                {Action: auth.ActOrgRead, OrgScoped: true, Anonymous: true},
	"getUserProfile":        {Action: auth.ActPublicRead, Anonymous: true},
	"listOrgAudit":          {Action: auth.ActOrgAuditRead, OrgScoped: true},
	"listOrgMembers":        {Action: auth.ActOrgMembersRead, OrgScoped: true},
	"listTeamMembers":       {Action: auth.ActOrgTeamsRead, OrgScoped: true},
	"listTeams":             {Action: auth.ActOrgTeamsRead, OrgScoped: true},
	"listTokens":            {Action: auth.ActUserTokensRead},
	"listSshKeys":           {Action: auth.ActUserTokensRead},
	"addSshKey":             {Action: auth.ActUserTokensManage, SessionOnly: true},
	"removeSshKey":          {Action: auth.ActUserTokensManage, SessionOnly: true},
	// Sessions: listing rides the self-read action so a `user:profile` PAT is
	// admitted and answered with an empty list (a PAT has no sessions of its
	// own); revoking is session-only, like logout — a token must not be able
	// to sign its holder's browsers out.
	"listUserSessions":               {Action: auth.ActUserSelfRead},
	"getDomainOrg":                   {Action: auth.ActUserSelfRead},
	"requestDomainOrgAccess":         {Action: auth.ActUserOrgRequest, SessionOnly: true},
	"getUserDirectory":               {Action: auth.ActUserSelfRead},
	"listUserDependencyAlerts":       {Action: auth.ActUserSelfRead},
	"listUserActivity":               {Action: auth.ActUserSelfRead},
	"getUserNotificationSettings":    {Action: auth.ActUserSelfRead},
	"updateUserNotificationSettings": {Action: auth.ActUserSelfUpdate},
	"deleteUserDirectoryDevice":      {Action: auth.ActUserSelfUpdate},
	"revokeUserSession":              {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"revokeOtherUserSessions":        {Action: auth.ActUserSecurityManage, SessionOnly: true},
	// The rule bundle is the same artifact the CLI already embeds; serving it
	// discloses nothing that shipping the binary did not.
	"getLatestRulesetBundle":      {Action: auth.ActPublicRead, Anonymous: true, NoAuthz: true},
	"getLatestRulesetAttestation": {Action: auth.ActPublicRead, Anonymous: true, NoAuthz: true},
	"login":                       {NoAuthz: true, Anonymous: true},
	"exchangeDesktopCode":         {NoAuthz: true, Anonymous: true},
	"logout":                      {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"register":                    {NoAuthz: true, Anonymous: true},
	"removeOrgMember":             {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for admin targets
	"removeTeamMember":            {Action: auth.ActOrgTeamsManage, OrgScoped: true},
	"revokeToken":                 {Action: auth.ActUserTokensManage, SessionOnly: true},
	"setOrgMember":                {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates to ActOrgMembersElevate for the admin role
	"approveOrgMember":            {Action: auth.ActOrgMembersManage, OrgScoped: true}, // elevates when the approval grants admin
	"declineOrgMember":            {Action: auth.ActOrgMembersManage, OrgScoped: true},
	"listInvitations":             {Action: auth.ActOrgInvitationsManage, OrgScoped: true},
	"createInvitation":            {Action: auth.ActOrgInvitationsManage, OrgScoped: true},
	"revokeInvitation":            {Action: auth.ActOrgInvitationsManage, OrgScoped: true},
	// The two sides of an invitation the invited person holds: the token is
	// the authorization, and who may use it — the session whose verified
	// address is the invited one — is a per-invitation judgement the
	// handler makes with the row in hand, like the review surface's.
	"getInvitation":     {SelfAuthorized: true},
	"acceptInvitation":  {SelfAuthorized: true},
	"totpSetup":         {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"totpVerify":        {Action: auth.ActUserSecurityManage, SessionOnly: true},
	"updateCurrentUser": {Action: auth.ActUserSelfUpdate},
	"updateOrg":         {Action: auth.ActOrgUpdate, OrgScoped: true},
	"verifyEmail":       {NoAuthz: true, Anonymous: true},
}

// MountGate is what stands between a caller and a root mount. A route on the
// generated surface states its gate through RouteDecl's action and flags; a
// root mount has no operationId to key a RouteDecl on, so it states it here
// (§12.2, agentry#415).
type MountGate string

const (
	// GatePublic takes no credential: the handler's own checks are all
	// there is.
	GatePublic MountGate = "public"
	// GateSignature's only gate is an HMAC over the request.
	GateSignature MountGate = "signature"
	// GateSCIMToken is gated by a SCIM bearer token, hashed at rest, bound
	// to an active organization that holds the entitlement.
	GateSCIMToken MountGate = "scim-token"
	// GateGit is gated by git's own authorization: a PAT over Basic auth,
	// then the effective agent role, existence privacy and the org-state
	// gate.
	GateGit MountGate = "git"
	// GatePrincipal is behind the principal middleware, as the generated
	// surface is.
	GatePrincipal MountGate = "principal"
)

// RateNone says a mount draws from no §19 bucket. It is a claim rather than
// an omission: Why has to say what stands in for one, and the completeness
// gate fails without it.
const RateNone = "none"

// RatePerPrincipal says the bucket is the principal middleware's choice per
// request rather than a class the mount fixes: `anon` for a caller with no
// credential, `authed` for one with. An extension's mount point is the only
// route that declares it, being the only one whose handler is a sub-mux of
// routes the middleware classifies one by one.
const RatePerPrincipal = "per-principal"

// MountDecl declares one root mount: what gates it, and which §19 rate class
// it draws from. Why is required when the gate is public or the class is one
// of the two sentinels — the declaration is where a reviewer looks for the
// reason, and both are choices that go stale silently.
type MountDecl struct {
	Gate MountGate
	// Class is the §19 bucket the mount's own code applies, or one of the
	// two sentinels. The gate checks the name against the catalogued set, so
	// a typo fails; it cannot check the wiring. That the handler really
	// draws from the bucket named here is the handler's own tests' job, and
	// a declaration that lies about it passes.
	Class string
	Why   string
}

// extensionMountPrefix is the one prefix whose mounts are declared at run
// time instead of in the table below: an extension's routes are registered
// under it behind the principal middleware, and the extension's own matrix
// test declares each of them (DEV-091). The completeness gate treats a
// recorded pattern under this prefix as declared, and asserts the gate.
const extensionMountPrefix = "/api/v1/x/"

// MountAuthzDecl returns the declaration for a root mount's pattern, falling
// back to the extension prefix's for a pattern under it.
func MountAuthzDecl(pattern string) (MountDecl, bool) {
	if d, ok := mountAuthz[pattern]; ok {
		return d, true
	}
	if strings.HasPrefix(pattern, extensionMountPrefix) {
		return MountDecl{
			Gate:  GatePrincipal,
			Class: RatePerPrincipal,
			Why:   "the principal middleware picks the bucket per request, and an extension's route opts out of the anonymous one exactly by method and path (DEV-091)",
		}, true
	}
	return MountDecl{}, false
}

// AllMountAuthzDecls returns a copy of the root-mount table (tests, docs).
func AllMountAuthzDecls() map[string]MountDecl {
	out := make(map[string]MountDecl, len(mountAuthz))
	for k, v := range mountAuthz {
		out[k] = v
	}
	return out
}

// scimDataPlane is what every SCIM route declares: the SCIM bearer token,
// and the `scim` bucket scimAuth spends per organization (limits.scimPerMin;
// agentry#453, DEV-140). Its burst is sized for a directory's initial sync,
// which is legitimate traffic; past it an IdP is refused with Retry-After.
var scimDataPlane = MountDecl{Gate: GateSCIMToken, Class: "scim"}

// mountAuthz maps a root mount's pattern → declaration. These are the
// registrations that are not part of the generated surface. A pattern here
// that nothing registers fails the completeness gate, and a registration
// with no entry here panics at start-up.
var mountAuthz = map[string]MountDecl{
	// Git smart HTTP, registered by internal/gitsrv's own Mount. The gate is
	// git's: a PAT over Basic auth, then the effective agent role. Pushes
	// draw from the `push` bucket inside admitPush, which is the code that
	// says so. The read side draws from `git-concurrent`, acquireGit's
	// budget of concurrent operations per trusted client address (§19's 20,
	// agentry#454), beside its caps of 4 per repository and 32
	// instance-wide. A push draws from it too, before `push` — one class
	// per declaration, so the push route names the bucket that is its own.
	"GET /{ns}/{repo}/info/refs":         {Gate: GateGit, Class: "git-concurrent"},
	"POST /{ns}/{repo}/git-upload-pack":  {Gate: GateGit, Class: "git-concurrent"},
	"POST /{ns}/{repo}/git-receive-pack": {Gate: GateGit, Class: "push"},

	// The image proxy: the signature is the route's only gate (agentry#64).
	"GET /api/v1/img/{sig}/{ref}": {
		Gate: GateSignature, Class: RateNone,
		Why: "the HMAC bounds what can be asked for; its key is never a public constant and the fetch is https only (agentry#403)",
	},

	// The probes: infrastructure, not a principal. The access log skips
	// them, and the RBAC chokepoint has no way to express one.
	"GET /healthz": {Gate: GatePublic, Class: RateNone, Why: "a liveness probe answers whoever asks, by design"},
	"GET /readyz":  {Gate: GatePublic, Class: RateNone, Why: "a readiness probe answers whoever asks, by design"},

	// Prometheus exposition (D-25). server.go carries the reasoning; the
	// compose edge answers /metrics with 404 (agentry#408), so there only a
	// scraper on the private network reaches it. The Helm chart's ingress
	// routes the whole host to the api and does not exclude it. This is the
	// declaration's own claim.
	"GET /metrics": {
		Gate: GatePublic, Class: RateNone,
		Why: "a scraper is infrastructure, not a principal; the compose edge 404s it (agentry#408); a Helm ingress must exclude it",
	},

	// The discovery documents are what a client reads before it holds
	// anything to authenticate with; the signing keys are public by
	// construction, since verification needs them.
	"GET /.well-known/agentry/registry.json":     {Gate: GatePublic, Class: RateNone, Why: "discovery: read before a caller holds a credential"},
	"GET /.well-known/agentry/signing-keys.json": {Gate: GatePublic, Class: RateNone, Why: "the keys are public by construction; a verifier needs them"},

	// SCIM 2.0's data plane (§12.5): its own base path, media type and
	// credential, so it is deliberately not part of the OpenAPI surface.
	"POST /scim/v2/Users":         scimDataPlane,
	"GET /scim/v2/Users":          scimDataPlane,
	"GET /scim/v2/Users/{id}":     scimDataPlane,
	"PATCH /scim/v2/Users/{id}":   scimDataPlane,
	"PUT /scim/v2/Users/{id}":     scimDataPlane,
	"DELETE /scim/v2/Users/{id}":  scimDataPlane,
	"POST /scim/v2/Groups":        scimDataPlane,
	"GET /scim/v2/Groups":         scimDataPlane,
	"GET /scim/v2/Groups/{id}":    scimDataPlane,
	"PATCH /scim/v2/Groups/{id}":  scimDataPlane,
	"DELETE /scim/v2/Groups/{id}": scimDataPlane,

	// The org SSO landing (§12.4) is a browser destination, reachable by
	// definition without a session: it is the door to making one. It draws
	// from the `login` bucket, which the handler applies.
	"GET /sso/{org}": {
		Gate: GatePublic, Class: "login",
		Why: "the door to a session cannot require one; the handler checks that login is allowed at all, that the organization exists and holds the entitlement, and the `login` bucket bounds how often",
	},
}

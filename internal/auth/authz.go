package auth

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// OrgRole is an organization role, ordered owner > admin >
// security_reviewer | member (§12.2). The empty string means "not a member".
type OrgRole string

// Org roles (§12.2).
const (
	RoleOwner            OrgRole = "owner"
	RoleAdmin            OrgRole = "admin"
	RoleSecurityReviewer OrgRole = "security_reviewer"
	RoleMember           OrgRole = "member"
	RoleNone             OrgRole = ""
)

// roleRank orders roles for threshold checks. security_reviewer and member
// are siblings (§12.2); reviewer-only powers use explicit checks, not rank.
func roleRank(r OrgRole) int {
	switch r {
	case RoleOwner:
		return 4
	case RoleAdmin:
		return 3
	case RoleSecurityReviewer, RoleMember:
		return 1
	default:
		return 0
	}
}

// Action is a declared (resource, action) pair the chokepoint understands.
// Every API route declares exactly one (§12.2 enforcement note); the §17.4
// matrix test enumerates this list against every role.
type Action string

// M1 actions. Later milestones append; never reuse an id.
const (
	// Org-scoped.
	ActOrgRead           Action = "org.read"            // public profile: anonymous ok
	ActOrgUpdate         Action = "org.update"          // admin+
	ActOrgMembersRead    Action = "org.members.read"    // member+ (any role)
	ActOrgMembersManage  Action = "org.members.manage"  // admin+: member/security_reviewer roles
	ActOrgMembersElevate Action = "org.members.elevate" // owner: grant/revoke owner or admin
	ActOrgTeamsRead      Action = "org.teams.read"      // member+
	ActOrgTeamsManage    Action = "org.teams.manage"    // admin+
	ActOrgAuditRead      Action = "org.audit.read"      // admin+ (§12.2)
	ActOrgSettingsManage Action = "org.settings.manage" // owner (SSO/SCIM, M6)
	// Self-scoped (resource is the caller's own account).
	ActUserSelfRead       Action = "user.self.read"
	ActUserSelfUpdate     Action = "user.self.update"
	ActUserTokensRead     Action = "user.tokens.read"
	ActUserTokensManage   Action = "user.tokens.manage"   // session-only (a PAT cannot mint or revoke PATs)
	ActUserSecurityManage Action = "user.security.manage" // session-only: logout, 2FA enrollment
	// Org creation (no target org yet).
	ActOrgCreate Action = "org.create"
	// Anonymous-capable reads.
	ActPublicRead Action = "public.read"
	// ActReviewAct is the review surface (§12.3 review:act). Check only
	// enforces the PAT scope gate for it: WHO may review — platform staff or
	// an org security_reviewer who is not the version's author (§12.2) — is a
	// per-item judgement the handler makes with the review item in hand.
	ActReviewAct Action = "review.act"
)

// Principal is the resolved caller identity for one request.
type Principal struct {
	// Anonymous is true when no credential was presented.
	Anonymous bool
	UserID    uuid.UUID
	Handle    string
	// Via is "session", "pat" or "ssh" (git over SSH, agentry#70).
	Via string
	// Scopes holds PAT scopes; nil for sessions.
	Scopes []string
	// OrgRoles maps org id → role for the caller's memberships.
	OrgRoles map[uuid.UUID]OrgRole
	// EmailVerified gates publishing flows (§19).
	EmailVerified bool
	// PlatformStaff marks trust & safety operators (SaaS platform roles;
	// self-host: the instance admin). Gates the platform review queue and
	// quarantine/block actions (§12.2 last row).
	PlatformStaff bool
	// SessionID / PATID / SSHKeyID identify the credential for audit.
	SessionID uuid.UUID
	PATID     uuid.UUID
	SSHKeyID  uuid.UUID
	// SSOFresh maps org id → the moment SSO was last asserted for this
	// session (§12.4 enforced SSO; from sessions.sso_tags). Sessions only.
	SSOFresh map[uuid.UUID]time.Time
	// PATOrgID is the org a PAT is bound to (pats.org_id): a PAT minted under
	// an SSO-fresh session (§12.4). uuid.Nil for personal PATs and sessions.
	PATOrgID uuid.UUID
}

// SSOSatisfied reports whether the caller meets an org's enforced-SSO
// requirement (§12.4): a session must carry an sso tag for the org refreshed
// within maxAge; a PAT must be bound to the org. Anonymous callers and
// non-enforcing orgs are decided by the RBAC chokepoint, not here.
func (p *Principal) SSOSatisfied(orgID uuid.UUID, maxAge time.Duration) bool {
	if p == nil {
		return false
	}
	switch p.Via {
	case "pat":
		return p.PATOrgID == orgID
	case "session":
		ts, ok := p.SSOFresh[orgID]
		return ok && time.Since(ts) <= maxAge
	default:
		return false
	}
}

// Role returns the caller's role in org (RoleNone when absent).
func (p *Principal) Role(orgID uuid.UUID) OrgRole {
	if p == nil || p.OrgRoles == nil {
		return RoleNone
	}
	return p.OrgRoles[orgID]
}

// Resource identifies what an action targets. OrgID is set for org-scoped
// actions; self-scoped actions carry nothing (the principal is the target).
type Resource struct {
	OrgID uuid.UUID
}

// ErrUnauthorized means "no valid credential" (401); ErrForbidden means
// "credential valid, permission denied" (403). Handlers map them to problems.
var (
	ErrUnauthorized = errors.New("authentication required")
	ErrForbidden    = errors.New("forbidden")
)

// scopeFor maps each action to the PAT scope that unlocks it (§12.3).
// Actions absent here are session-only for PATs (minting PATs, org
// settings) — a deliberate least-privilege default.
var scopeFor = map[Action]Scope{
	ActOrgRead:           ScopeUserProfile, // public anyway; scope moot
	ActPublicRead:        ScopeUserProfile,
	ActOrgCreate:         ScopeOrgAdmin,
	ActOrgMembersRead:    ScopeOrgAdmin,
	ActOrgMembersManage:  ScopeOrgAdmin,
	ActOrgMembersElevate: ScopeOrgAdmin,
	ActOrgTeamsRead:      ScopeOrgAdmin,
	ActOrgTeamsManage:    ScopeOrgAdmin,
	ActOrgUpdate:         ScopeOrgAdmin,
	ActOrgAuditRead:      ScopeAuditRead,
	ActAgentCreate:       ScopeAgentPublish,
	ActUserSelfRead:      ScopeUserProfile,
	ActUserSelfUpdate:    ScopeUserProfile,
	ActUserTokensRead:    ScopeUserProfile,
	ActReviewAct:         ScopeReviewAct,
}

// minRole is the role threshold per org-scoped action.
var minRole = map[Action]OrgRole{
	ActOrgUpdate:         RoleAdmin,
	ActOrgMembersRead:    RoleMember,
	ActOrgMembersManage:  RoleAdmin,
	ActOrgMembersElevate: RoleOwner,
	ActOrgTeamsRead:      RoleMember,
	ActOrgTeamsManage:    RoleAdmin,
	ActOrgAuditRead:      RoleAdmin,
	ActOrgSettingsManage: RoleOwner,
}

// Check is the single authorization chokepoint (§12.2): every handler calls
// it with its declared action. It never consults anything but the principal
// and the resource — no ambient state.
func Check(p *Principal, res Resource, act Action) error {
	// Anonymous-permitted actions.
	if act == ActOrgRead || act == ActPublicRead {
		return nil
	}
	if p == nil || p.Anonymous {
		return ErrUnauthorized
	}

	// PAT scope gate (sessions bypass scopes; CSRF covers them in transport).
	if p.Via == "pat" {
		sc, ok := scopeFor[act]
		if !ok {
			return ErrForbidden // session-only action
		}
		if !HasScope(p.Scopes, sc) {
			return ErrForbidden
		}
	}

	// Self-scoped actions and org creation need only authentication
	// (+scope gate above for PATs).
	switch act {
	case ActUserSelfRead, ActUserSelfUpdate, ActUserTokensRead,
		ActUserTokensManage, ActUserSecurityManage, ActOrgCreate,
		ActAgentCreate, ActReviewAct:
		// ActAgentCreate: namespace-level authorization (self vs org
		// admin+) happens in registry.CreateAgent with the target ns.
		// ActReviewAct: the scope gate above is the whole contribution here;
		// the reviewer/author checks need the review item (§12.2).
		return nil
	}

	// Org-scoped actions: role threshold in the target org.
	need, ok := minRole[act]
	if !ok {
		return ErrForbidden // undeclared action: fail closed
	}
	if roleRank(p.Role(res.OrgID)) < roleRank(need) {
		return ErrForbidden
	}
	return nil
}

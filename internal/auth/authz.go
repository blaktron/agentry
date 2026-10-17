package auth

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// OrgRole is an organization role, ordered admin > security_reviewer |
// member (there is no owner role and none above admin, and the last admin
// can only leave through a decommission). security_reviewer is a
// platform-internal role that exists only inside a first-party
// organization; in every other organization the admins hold its powers.
// The empty string means "not a member".
type OrgRole string

// Org roles.
const (
	RoleAdmin            OrgRole = "admin"
	RoleSecurityReviewer OrgRole = "security_reviewer"
	RoleMember           OrgRole = "member"
	RoleNone             OrgRole = ""
)

// roleRank orders roles for threshold checks. security_reviewer and member
// are siblings; reviewer-only powers use explicit checks, not rank.
// Any other value — "owner", which is not a role, or a typo — ranks as nobody.
func roleRank(r OrgRole) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleSecurityReviewer, RoleMember:
		return 1
	default:
		return 0
	}
}

// Action is a declared (resource, action) pair the chokepoint understands.
// Every API route declares exactly one; the authorization matrix test
// enumerates this list against every role.
type Action string

// Actions are only ever appended; an id is never reused.
const (
	// Org-scoped.
	ActOrgRead           Action = "org.read"            // public profile: anonymous ok
	ActOrgUpdate         Action = "org.update"          // admin+
	ActOrgMembersRead    Action = "org.members.read"    // member+ (any role)
	ActOrgMembersManage  Action = "org.members.manage"  // admin: member/security_reviewer roles
	ActOrgMembersElevate Action = "org.members.elevate" // admin: grant/revoke admin
	ActOrgTeamsRead      Action = "org.teams.read"      // member+
	ActOrgTeamsManage    Action = "org.teams.manage"    // admin+
	ActOrgAuditRead      Action = "org.audit.read"      // admin+
	ActOrgSettingsManage Action = "org.settings.manage" // admin (SSO/SCIM, policy)
	// ActOrgBrandingManage sets or removes the organization's logo.
	ActOrgBrandingManage Action = "org.branding.manage" // admin
	// ActOrgInvitationsManage is the invitation door: send,
	// list and revoke. Declared apart from members.manage because an
	// invitation reserves a seat before any membership exists.
	ActOrgInvitationsManage Action = "org.invitations.manage" // admin
	// ActOrgDecommission ends the organization: admin,
	// session only — a token never decides that an organization goes.
	ActOrgDecommission Action = "org.decommission"
	// ActOrgLeave is a member ending their own membership: a person
	// belongs to one organization at a time, so they must be able to leave
	// the one they hold. The last-admin guard applies.
	ActOrgLeave Action = "org.leave"
	// Self-scoped (resource is the caller's own account).
	ActUserSelfRead       Action = "user.self.read"
	ActUserSelfUpdate     Action = "user.self.update"
	ActUserTokensRead     Action = "user.tokens.read"
	ActUserTokensManage   Action = "user.tokens.manage"   // session-only (a PAT cannot mint or revoke PATs)
	ActUserSecurityManage Action = "user.security.manage" // session-only: logout, sessions, remembered browsers
	// ActUserOrgRequest asks the administrators of the organization at the
	// caller's email domain for access: session only, since
	// it mails people on the caller's behalf.
	ActUserOrgRequest Action = "user.org.request"
	// Org creation (no target org yet).
	ActOrgCreate Action = "org.create"
	// Anonymous-capable reads.
	ActPublicRead Action = "public.read"
	// The caller's own knowledge packs: self-scoped, since a pack is found
	// only by its owner.
	// Read covers the packs, their reports and trees, the export and
	// having a data key unwrapped; write covers the rest.
	ActKnowledgeRead  Action = "knowledge.read"
	ActKnowledgeWrite Action = "knowledge.write"
	// An organization's shared knowledge: org-scoped, so membership is
	// checked at every call through the roles the request resolved. Read covers the packs,
	// their trees, the meter and having a data key unwrapped, for any
	// active member; write covers the rest, for its admins. Exporting is
	// a read an admin may always make and a member only once the pack is
	// marked exportable, which the handler decides with the pack in hand.
	ActOrgKnowledgeRead  Action = "org.knowledge.read"
	ActOrgKnowledgeWrite Action = "org.knowledge.write" // admin
	// The caller's own Writing Voice: self-scoped, since a voice is found
	// only by its owner.
	// Read covers every version's text and review; write covers the rest.
	ActVoiceRead  Action = "voice.read"
	ActVoiceWrite Action = "voice.write"
	// ActReviewAct is the review surface (review:act). Check only
	// enforces the PAT scope gate for it: WHO may review — platform staff or
	// an org security_reviewer who is not the version's author — is a
	// per-item judgement the handler makes with the review item in hand.
	ActReviewAct Action = "review.act"
)

// Principal is the resolved caller identity for one request.
type Principal struct {
	// Anonymous is true when no credential was presented.
	Anonymous bool
	UserID    uuid.UUID
	Handle    string
	// Via is "session", "pat" or "ssh" (git over SSH), or
	// "user": a principal the core loaded for an account with no
	// credential, for an extension to ask about a user it holds by id. A
	// "user" principal carries the account's roles and no scopes; it
	// passes no session-only route and satisfies no enforced SSO.
	// "schedule" is the credential of a run a schedule starts on its
	// owner's behalf with no live request: the core mints it for an
	// extension (extension.ScheduleCredentials.ForSchedule), it carries
	// ScheduleScopes and the schedule's id, every scope gate reads it as
	// it reads a token's (ScopeBound), and it is never presented over
	// HTTP.
	Via string
	// Scopes holds a PAT's scopes, or a schedule's ScheduleScopes; nil
	// for sessions.
	Scopes []string
	// OrgRoles maps org id → role for the caller's memberships.
	OrgRoles map[uuid.UUID]OrgRole
	// EmailVerified gates publishing flows.
	EmailVerified bool
	// Unactivated marks an account whose address has not been confirmed
	// and can be: it may read, but every write outside a short list of
	// its own housekeeping is refused until it follows the activation
	// link. See Unactivated.
	Unactivated bool
	// PlatformStaff marks trust & safety operators (SaaS platform roles;
	// self-host: the instance admin). Gates the platform review queue and
	// quarantine/block actions.
	PlatformStaff bool
	// SessionID / PATID / SSHKeyID / ScheduleID identify the credential
	// for audit; ScheduleID is the schedule's id in the extension that
	// owns schedules, and the core holds no row for it.
	SessionID  uuid.UUID
	PATID      uuid.UUID
	SSHKeyID   uuid.UUID
	ScheduleID uuid.UUID
	// SSOFresh maps org id → the moment SSO was last asserted for this
	// session (enforced SSO; from sessions.sso_tags). Sessions only.
	SSOFresh map[uuid.UUID]time.Time
	// PATOrgID is the org a PAT is bound to (pats.org_id): a PAT minted under
	// an SSO-fresh session. uuid.Nil for personal PATs and sessions.
	PATOrgID uuid.UUID
}

// ScopeBound reports whether the principal acts only within its Scopes:
// a token, or a schedule's credential. A session carries the
// account's full authority instead, and a "user" principal is no caller at
// all. Every scope gate asks this rather than naming "pat", so a credential
// minted with a fixed scope set is never read as a session.
func (p *Principal) ScopeBound() bool {
	return p != nil && (p.Via == "pat" || p.Via == "schedule")
}

// SSOSatisfied reports whether the caller meets an org's enforced-SSO
// requirement: a session must carry an sso tag for the org refreshed
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

// scopeFor maps each action to the PAT scope that unlocks it.
// Actions absent here are session-only for PATs (minting PATs, org
// settings) — a deliberate least-privilege default.
var scopeFor = map[Action]Scope{
	ActOrgRead:              ScopeUserProfile, // public anyway; scope moot
	ActPublicRead:           ScopeUserProfile,
	ActOrgCreate:            ScopeOrgAdmin,
	ActOrgMembersRead:       ScopeOrgAdmin,
	ActOrgMembersManage:     ScopeOrgAdmin,
	ActOrgMembersElevate:    ScopeOrgAdmin,
	ActOrgInvitationsManage: ScopeOrgAdmin,
	ActOrgTeamsRead:         ScopeOrgAdmin,
	ActOrgTeamsManage:       ScopeOrgAdmin,
	ActOrgUpdate:            ScopeOrgAdmin,
	ActOrgBrandingManage:    ScopeOrgAdmin, // the logo is profile, not a secret: as ActOrgUpdate
	ActOrgAuditRead:         ScopeAuditRead,
	ActAgentCreate:          ScopeAgentPublish,
	ActUserSelfRead:         ScopeUserProfile,
	ActUserSelfUpdate:       ScopeUserProfile,
	ActUserTokensRead:       ScopeUserProfile,
	ActReviewAct:            ScopeReviewAct,
	ActKnowledgeRead:        ScopeKnowledgeRead,
	ActKnowledgeWrite:       ScopeKnowledgeWrite,
	ActOrgKnowledgeRead:     ScopeKnowledgeRead,
	ActOrgKnowledgeWrite:    ScopeKnowledgeWrite,
	ActVoiceRead:            ScopeVoiceRead,
	ActVoiceWrite:           ScopeVoiceWrite,
}

// minRole is the role threshold per org-scoped action.
var minRole = map[Action]OrgRole{
	ActOrgUpdate:            RoleAdmin,
	ActOrgMembersRead:       RoleMember,
	ActOrgMembersManage:     RoleAdmin,
	ActOrgMembersElevate:    RoleAdmin,
	ActOrgTeamsRead:         RoleMember,
	ActOrgTeamsManage:       RoleAdmin,
	ActOrgAuditRead:         RoleAdmin,
	ActOrgSettingsManage:    RoleAdmin,
	ActOrgBrandingManage:    RoleAdmin,
	ActOrgInvitationsManage: RoleAdmin,
	ActOrgDecommission:      RoleAdmin,
	ActOrgLeave:             RoleMember,
	ActOrgKnowledgeRead:     RoleMember,
	ActOrgKnowledgeWrite:    RoleAdmin,
}

// ReadOnly reports whether an action only reads. The audit export creates
// a job, but what it produces is the organization's own record.
func ReadOnly(act Action) bool {
	switch act {
	case ActOrgRead, ActOrgMembersRead, ActOrgTeamsRead, ActOrgAuditRead,
		ActPublicRead, ActUserSelfRead, ActUserTokensRead,
		ActAgentRead, ActAgentRepoRead, ActKnowledgeRead, ActOrgKnowledgeRead:
		return true
	}
	return false
}

// HoldPermits reports whether an organization in its decommission hold
// still permits the action (members keep read and export): the reads,
// and a member leaving, since a person belongs to one organization at a
// time and must not be held in one on its way out.
// Everything else changes something the hold has frozen.
func HoldPermits(act Action) bool {
	return ReadOnly(act) || act == ActOrgLeave
}

// Check is the single authorization chokepoint: every handler calls
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
	// A principal the core loaded for a user with no credential
	// is a question for the agent seams, never a caller: it authorizes no
	// route, should one ever reach here.
	if p.Via == "user" {
		return ErrForbidden
	}

	// PAT scope gate (sessions bypass scopes; CSRF covers them in transport).
	// A schedule's credential is gated the same way.
	if p.ScopeBound() {
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
		ActUserTokensManage, ActUserSecurityManage, ActUserOrgRequest, ActOrgCreate,
		ActAgentCreate, ActReviewAct, ActKnowledgeRead, ActKnowledgeWrite, ActVoiceRead, ActVoiceWrite:
		// ActAgentCreate: namespace-level authorization (self vs org
		// admin+) happens in registry.CreateAgent with the target ns.
		// ActReviewAct: the scope gate above is the whole contribution here;
		// the reviewer/author checks need the review item.
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

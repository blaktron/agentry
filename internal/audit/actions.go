// Package audit provides the append-only audit log (§12.6): a code-registered
// action catalog (so docs and events cannot drift) and a writer that lands
// every event in the partitioned audit_events table.
package audit

import "sync"

// Action identifies an auditable action. Every mutating API call, auth event,
// and state-machine transition writes exactly one (§12.6).
type Action string

// The v1 action catalog. Append-only: never rename or reuse an id.
const (
	// Auth & account.
	ActionUserRegister      Action = "user.register"
	ActionUserLogin         Action = "user.login"
	ActionUserLoginFailed   Action = "user.login_failed"
	ActionUserLogout        Action = "user.logout"
	ActionUserEmailVerified Action = "user.email_verified"
	ActionUserUpdate        Action = "user.update"
	ActionUserTOTPEnabled   Action = "user.totp_enabled"
	ActionPATCreate         Action = "pat.create"
	ActionPATRevoke         Action = "pat.revoke"
	// SSH keys for the git transport (agentry#70).
	ActionSSHKeyAdd          Action = "ssh_key.add"
	ActionSSHKeyRemove       Action = "ssh_key.remove"
	ActionUserDirectoryErase Action = "user.directory_erase"
	// ActionUserStaffSync records a platform_staff change driven by
	// directory group membership (agentry#51).
	ActionUserStaffSync Action = "user.staff_sync"
	ActionUserDelete    Action = "user.delete"

	// Orgs & teams.
	ActionOrgCreate       Action = "org.create"
	ActionOrgUpdate       Action = "org.update"
	ActionOrgMemberSet    Action = "org.member_set"
	ActionOrgMemberRemove Action = "org.member_remove"
	// Invitations and approvals (agentry#361): the only doors into an
	// organization, each audited where it is decided.
	ActionOrgInviteCreate  Action = "org.invite_create"
	ActionOrgInviteRevoke  Action = "org.invite_revoke"
	ActionOrgInviteAccept  Action = "org.invite_accept"
	ActionOrgMemberDecline Action = "org.member_decline"
	// The logo set or removed (agentry#367); the detail carries the object
	// key served, never the bytes.
	ActionOrgLogoSet     Action = "org.logo_set"
	ActionOrgLogoRemoved Action = "org.logo_removed"
	// The fold-in (agentry#364): an existing account at the organization's
	// domain became a pending member, at its sign-in or by the sweep.
	ActionOrgMemberPending Action = "org.member_pending"
	// The organization's lifecycle and its domain (agentry#363): a
	// decommission decided, the erasure that ends its hold, platform
	// staff's suspension and reinstatement, and a person's request to
	// join the organization at their email domain.
	ActionOrgDecommission  Action = "org.decommission"
	ActionOrgErase         Action = "org.erase"
	ActionOrgSuspend       Action = "org.suspend"
	ActionOrgReinstate     Action = "org.reinstate"
	ActionOrgAccessRequest Action = "org.access_request"
	ActionTeamCreate       Action = "team.create"
	ActionTeamDelete       Action = "team.delete"
	ActionTeamMemberAdd    Action = "team.member_add"
	ActionTeamMemberRemove Action = "team.member_remove"

	// Agents & repos (M2).
	ActionAgentCreate      Action = "agent.create"
	ActionAgentUpdate      Action = "agent.update"
	ActionAgentGrantSet    Action = "agent.grant_set"
	ActionAgentGrantRemove Action = "agent.grant_remove"
	ActionRepoPush         Action = "repo.push"

	// Versions & publication (M3).
	ActionVersionSubmit     Action = "version.submit"
	ActionVersionTransition Action = "version.transition"
	ActionVersionYank       Action = "version.yank"

	// Security pipeline (M4).
	ActionReviewDecision  Action = "review.decision"
	ActionFindingVerdict  Action = "finding.verdict"
	ActionPolicyUpdate    Action = "policy.update"
	ActionAgentQuarantine Action = "agent.quarantine"
	ActionAgentBlock      Action = "agent.block"
	ActionAgentReinstate  Action = "agent.reinstate"
	ActionAdvisoryPublish Action = "advisory.publish"
	// ActionAgentDependencyAlert records the daily MCP sweep opening a
	// dependency alert on a published version (agentry#177).
	ActionAgentDependencyAlert Action = "agent.dependency_alert"
	ActionRulesetRelease       Action = "ruleset.release"
	ActionAbuseReport          Action = "abuse.report"
	ActionAbuseTriage          Action = "abuse.triage"

	// Enterprise (M6): SSO, SCIM, webhooks, domain verification, audit export.
	ActionSSOConnectionSet    Action = "sso.connection_set"
	ActionSSOConnectionDelete Action = "sso.connection_delete"
	ActionSSOLogin            Action = "sso.login"
	ActionSCIMTokenCreate     Action = "scim.token_create"
	ActionSCIMTokenRevoke     Action = "scim.token_revoke"
	ActionSCIMUserProvision   Action = "scim.user_provision"
	ActionSCIMUserDeactivate  Action = "scim.user_deactivate"
	ActionSCIMGroupSync       Action = "scim.group_sync"
	ActionWebhookCreate       Action = "webhook.create"
	ActionWebhookUpdate       Action = "webhook.update"
	ActionWebhookDelete       Action = "webhook.delete"
	ActionDomainClaim         Action = "domain.claim"
	ActionDomainVerified      Action = "domain.verified"
	ActionAuditExport         Action = "audit.export"

	// Stars, agent lifecycle, and platform operations.
	ActionAgentStar   Action = "agent.star"
	ActionAgentUnstar Action = "agent.unstar"
	// An account install and its removal (plan web-dashboard-shell §5,
	// agentry#448): the caller's own record, beside the star.
	ActionAgentInstall      Action = "agent.install"
	ActionAgentUninstall    Action = "agent.uninstall"
	ActionAgentDelete       Action = "agent.delete"
	ActionAgentTransfer     Action = "agent.transfer"
	ActionWebhookPing       Action = "webhook.ping"
	ActionAuditPlatformRead Action = "audit.platform_read"
	ActionAuditPrune        Action = "audit.prune"
	ActionSocialLogin       Action = "user.social_login"
)

// registry is populated at init from the constants above.
var registry = map[Action]struct{}{}

func init() {
	for _, a := range []Action{
		ActionUserRegister, ActionUserLogin, ActionUserLoginFailed,
		ActionUserLogout, ActionUserEmailVerified, ActionUserUpdate,
		ActionUserTOTPEnabled, ActionPATCreate, ActionPATRevoke, ActionSSHKeyAdd, ActionSSHKeyRemove, ActionUserDelete, ActionUserDirectoryErase, ActionUserStaffSync,
		ActionOrgCreate, ActionOrgUpdate, ActionOrgMemberSet,
		ActionOrgMemberRemove, ActionOrgInviteCreate, ActionOrgInviteRevoke,
		ActionOrgInviteAccept, ActionOrgMemberDecline, ActionOrgMemberPending,
		ActionOrgLogoSet, ActionOrgLogoRemoved,
		ActionOrgDecommission, ActionOrgErase, ActionOrgSuspend, ActionOrgReinstate, ActionOrgAccessRequest,
		ActionTeamCreate, ActionTeamDelete,
		ActionTeamMemberAdd, ActionTeamMemberRemove,
		ActionAgentCreate, ActionAgentUpdate, ActionAgentGrantSet,
		ActionAgentGrantRemove, ActionRepoPush,
		ActionVersionSubmit, ActionVersionTransition, ActionVersionYank,
		ActionReviewDecision, ActionFindingVerdict, ActionPolicyUpdate,
		ActionAgentQuarantine, ActionAgentBlock, ActionAgentReinstate,
		ActionAdvisoryPublish, ActionAgentDependencyAlert, ActionRulesetRelease, ActionAbuseReport,
		ActionAbuseTriage,
		ActionSSOConnectionSet, ActionSSOConnectionDelete, ActionSSOLogin,
		ActionSCIMTokenCreate, ActionSCIMTokenRevoke, ActionSCIMUserProvision,
		ActionSCIMUserDeactivate, ActionSCIMGroupSync,
		ActionWebhookCreate, ActionWebhookUpdate, ActionWebhookDelete,
		ActionDomainClaim, ActionDomainVerified, ActionAuditExport,
		ActionAgentStar, ActionAgentUnstar, ActionAgentInstall, ActionAgentUninstall, ActionAgentDelete,
		ActionAgentTransfer, ActionWebhookPing, ActionAuditPlatformRead,
		ActionAuditPrune, ActionSocialLogin,
	} {
		registry[a] = struct{}{}
	}
}

// Registered reports whether a is in the catalog. The writer refuses
// unregistered actions so ad-hoc strings can't leak into the log.
func Registered(a Action) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[a]
	return ok
}

var registryMu sync.RWMutex

// Register adds an action to the catalog at start-up: an extension's own
// actions (pkg/extension.RegisterAuditAction). It reports false, and adds
// nothing, when the action is already in the catalog — an extension can
// never take over a core action.
func Register(a Action) bool {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[a]; exists {
		return false
	}
	registry[a] = struct{}{}
	return true
}

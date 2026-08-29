// Package audit provides the append-only audit log (§12.6): a code-registered
// action catalog (so docs and events cannot drift) and a writer that lands
// every event in the partitioned audit_events table.
package audit

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
	ActionUserDelete        Action = "user.delete"

	// Orgs & teams.
	ActionOrgCreate        Action = "org.create"
	ActionOrgUpdate        Action = "org.update"
	ActionOrgMemberSet     Action = "org.member_set"
	ActionOrgMemberRemove  Action = "org.member_remove"
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
	ActionRulesetRelease  Action = "ruleset.release"
	ActionAbuseReport     Action = "abuse.report"
	ActionAbuseTriage     Action = "abuse.triage"

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
	ActionAgentStar         Action = "agent.star"
	ActionAgentUnstar       Action = "agent.unstar"
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
		ActionUserTOTPEnabled, ActionPATCreate, ActionPATRevoke, ActionUserDelete,
		ActionOrgCreate, ActionOrgUpdate, ActionOrgMemberSet,
		ActionOrgMemberRemove, ActionTeamCreate, ActionTeamDelete,
		ActionTeamMemberAdd, ActionTeamMemberRemove,
		ActionAgentCreate, ActionAgentUpdate, ActionAgentGrantSet,
		ActionAgentGrantRemove, ActionRepoPush,
		ActionVersionSubmit, ActionVersionTransition, ActionVersionYank,
		ActionReviewDecision, ActionFindingVerdict, ActionPolicyUpdate,
		ActionAgentQuarantine, ActionAgentBlock, ActionAgentReinstate,
		ActionAdvisoryPublish, ActionRulesetRelease, ActionAbuseReport,
		ActionAbuseTriage,
		ActionSSOConnectionSet, ActionSSOConnectionDelete, ActionSSOLogin,
		ActionSCIMTokenCreate, ActionSCIMTokenRevoke, ActionSCIMUserProvision,
		ActionSCIMUserDeactivate, ActionSCIMGroupSync,
		ActionWebhookCreate, ActionWebhookUpdate, ActionWebhookDelete,
		ActionDomainClaim, ActionDomainVerified, ActionAuditExport,
		ActionAgentStar, ActionAgentUnstar, ActionAgentDelete,
		ActionAgentTransfer, ActionWebhookPing, ActionAuditPlatformRead,
		ActionAuditPrune, ActionSocialLogin,
	} {
		registry[a] = struct{}{}
	}
}

// Registered reports whether a is in the catalog. The writer refuses
// unregistered actions so ad-hoc strings can't leak into the log.
func Registered(a Action) bool {
	_, ok := registry[a]
	return ok
}

// All returns the catalog (docs page, tests).
func All() []Action {
	out := make([]Action, 0, len(registry))
	for a := range registry {
		out = append(out, a)
	}
	return out
}

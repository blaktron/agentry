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

	// Orgs & teams.
	ActionOrgCreate        Action = "org.create"
	ActionOrgUpdate        Action = "org.update"
	ActionOrgMemberSet     Action = "org.member_set"
	ActionOrgMemberRemove  Action = "org.member_remove"
	ActionTeamCreate       Action = "team.create"
	ActionTeamDelete       Action = "team.delete"
	ActionTeamMemberAdd    Action = "team.member_add"
	ActionTeamMemberRemove Action = "team.member_remove"
)

// registry is populated at init from the constants above.
var registry = map[Action]struct{}{}

func init() {
	for _, a := range []Action{
		ActionUserRegister, ActionUserLogin, ActionUserLoginFailed,
		ActionUserLogout, ActionUserEmailVerified, ActionUserUpdate,
		ActionUserTOTPEnabled, ActionPATCreate, ActionPATRevoke,
		ActionOrgCreate, ActionOrgUpdate, ActionOrgMemberSet,
		ActionOrgMemberRemove, ActionTeamCreate, ActionTeamDelete,
		ActionTeamMemberAdd, ActionTeamMemberRemove,
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

package auth

import "github.com/google/uuid"

// AgentRole is a per-agent level (§12.2): read < write < maintain <
// publish < admin. AgentRoleNone means no access (private agents deny by
// default).
//
// The top of the ladder is not grantable (ValidAgentRole): it is derived
// from the namespace alone. Everything below it is about an agent's
// *content* — reading it, pushing to it, releasing it — and can sensibly
// be handed to a collaborator. AgentRoleAdmin is about the agent's
// *existence and exposure*: deleting it, changing whether the world can
// see it, handing out access to it. Since agentry#362 an organization's
// members hold publish on its agents, so those acts needed a level above
// publish rather than below it, or every member would have inherited them
// (D19: only admins change visibility, transfer or delete).
type AgentRole string

// Agent roles in ascending order.
const (
	AgentRoleNone     AgentRole = ""
	AgentRoleRead     AgentRole = "read"
	AgentRoleWrite    AgentRole = "write"
	AgentRoleMaintain AgentRole = "maintain"
	AgentRolePublish  AgentRole = "publish"
	// AgentRoleAdmin is derived, never granted: the namespace's own people.
	AgentRoleAdmin AgentRole = "admin"
)

// agentRoleRank orders agent roles for threshold checks.
func agentRoleRank(r AgentRole) int {
	switch r {
	case AgentRoleAdmin:
		return 5
	case AgentRolePublish:
		return 4
	case AgentRoleMaintain:
		return 3
	case AgentRoleWrite:
		return 2
	case AgentRoleRead:
		return 1
	default:
		return 0
	}
}

// MaxAgentRole returns the higher of two agent roles.
func MaxAgentRole(a, b AgentRole) AgentRole {
	if agentRoleRank(a) >= agentRoleRank(b) {
		return a
	}
	return b
}

// ValidAgentRole reports whether r is a grantable role. AgentRoleAdmin is
// deliberately absent: an organization decides who administers its agents
// through its own roles, and a grant on one agent must not be a way to
// hand that out.
func ValidAgentRole(r AgentRole) bool {
	switch r {
	case AgentRoleRead, AgentRoleWrite, AgentRoleMaintain, AgentRolePublish:
		return true
	}
	return false
}

// NamespaceDerivedAgentRole computes the implicit role a caller holds on an
// agent from its namespace, before explicit grants (§12.2, D6, D19):
//   - personal namespace: the owning user administers their own agents;
//   - org namespace: an org admin administers them, and an org **member**
//     may release them (publish) — a seat buys a share of the
//     organization's agents, which is what an organization is for, while
//     what the agent *is* stays the admins' (agentry#362);
//   - everyone else: none (explicit grants only).
//
// A pending member holds nothing, and needs no case here: a membership
// that is not active never reaches Principal.OrgRoles (agentry#361), so
// they arrive as RoleNone like any outsider.
func NamespaceDerivedAgentRole(p *Principal, namespaceKind string, namespaceID uuid.UUID, orgRole OrgRole) AgentRole {
	if p == nil || p.Anonymous {
		return AgentRoleNone
	}
	if namespaceKind == "user" {
		if p.UserID == namespaceID {
			return AgentRoleAdmin
		}
		return AgentRoleNone
	}
	switch orgRole {
	case RoleAdmin:
		return AgentRoleAdmin
	case RoleMember:
		return AgentRolePublish
	default:
		// security_reviewer included: the review surface is its own
		// regime (§12.2), not a hold on the organization's agents.
		return AgentRoleNone
	}
}

// Agent-scoped actions (M2+). Declared like every other action. Transport
// (git) and registry surfaces are distinct actions because they map to
// different PAT scopes (§12.3: repo:* vs agent:*).
const (
	ActAgentCreate    Action = "agent.create"     // authed; org ns needs admin+
	ActAgentRead      Action = "agent.read"       // registry metadata/resolve; public agents anonymous
	ActAgentRepoRead  Action = "agent.repo.read"  // git clone/fetch (§6.4)
	ActAgentRepoWrite Action = "agent.repo.write" // git push (§6.4)
	ActAgentMaintain  Action = "agent.maintain"   // settings
	ActAgentPublish   Action = "agent.publish"    // v* tags, submit, yank
	// ActAgentAdminister is what only the namespace's own administrators
	// may do: delete the agent, change whether the world can see it, hand
	// out grants on it, and (M21) let it skip the pipeline. Separate from
	// maintain because an organization's members outrank maintain since
	// agentry#362 and must not inherit these (D19).
	ActAgentAdminister Action = "agent.administer"
)

// AgentResource describes the agent an action targets, resolved by the
// caller (API/gitsrv) from the database: the caller's effective role plus
// the agent's visibility.
type AgentResource struct {
	Public bool
	// EffectiveRole = max(namespace-derived, user grant, team grants),
	// computed by registry.EffectiveAgentRole.
	EffectiveRole AgentRole
}

// minAgentRole is the role threshold per agent action.
var minAgentRole = map[Action]AgentRole{
	ActAgentRead:       AgentRoleRead,
	ActAgentRepoRead:   AgentRoleRead,
	ActAgentRepoWrite:  AgentRoleWrite,
	ActAgentMaintain:   AgentRoleMaintain,
	ActAgentPublish:    AgentRolePublish,
	ActAgentAdminister: AgentRoleAdmin,
}

// agentScopeFor maps agent actions to PAT scopes (§12.3, §6.4).
var agentScopeFor = map[Action]Scope{
	ActAgentCreate:     ScopeAgentPublish,
	ActAgentRead:       ScopeAgentRead,
	ActAgentRepoRead:   ScopeRepoRead,
	ActAgentRepoWrite:  ScopeRepoWrite,
	ActAgentMaintain:   ScopeOrgAdmin,
	ActAgentPublish:    ScopeAgentPublish,
	ActAgentAdminister: ScopeOrgAdmin,
}

// CheckAgent is the chokepoint for agent-scoped actions. Public agents are
// readable by anyone (including anonymous); everything else needs the role
// threshold and, for PATs, the matching scope.
func CheckAgent(p *Principal, res AgentResource, act Action) error {
	if (act == ActAgentRead || act == ActAgentRepoRead) && res.Public {
		return nil
	}
	if p == nil || p.Anonymous {
		return ErrUnauthorized
	}
	if p.Via == "pat" {
		sc, ok := agentScopeFor[act]
		if !ok {
			return ErrForbidden
		}
		if !HasScope(p.Scopes, sc) {
			return ErrForbidden
		}
	}
	need, ok := minAgentRole[act]
	if !ok {
		return ErrForbidden // ActAgentCreate is namespace-gated by caller
	}
	if agentRoleRank(res.EffectiveRole) < agentRoleRank(need) {
		return ErrForbidden
	}
	return nil
}

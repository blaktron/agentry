package auth

import "github.com/google/uuid"

// AgentRole is a per-agent grant level (§12.2): read < write < maintain <
// publish. AgentRoleNone means no access (private agents deny by default).
type AgentRole string

// Agent roles in ascending order.
const (
	AgentRoleNone     AgentRole = ""
	AgentRoleRead     AgentRole = "read"
	AgentRoleWrite    AgentRole = "write"
	AgentRoleMaintain AgentRole = "maintain"
	AgentRolePublish  AgentRole = "publish"
)

// agentRoleRank orders agent roles for threshold checks.
func agentRoleRank(r AgentRole) int {
	switch r {
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

// ValidAgentRole reports whether r is a grantable role.
func ValidAgentRole(r AgentRole) bool {
	switch r {
	case AgentRoleRead, AgentRoleWrite, AgentRoleMaintain, AgentRolePublish:
		return true
	}
	return false
}

// NamespaceDerivedAgentRole computes the implicit role a caller holds on an
// agent from its namespace, before explicit grants (§12.2):
//   - personal namespace: the owning user has full rights (publish);
//   - org namespace: org owner ⇒ publish (bootstrap + accountability),
//     org admin ⇒ maintain (can manage settings/grants but NOT release —
//     enterprises separate "can edit" from "can release", §6.4);
//   - everyone else: none (explicit grants only).
func NamespaceDerivedAgentRole(p *Principal, namespaceKind string, namespaceID uuid.UUID, orgRole OrgRole) AgentRole {
	if p == nil || p.Anonymous {
		return AgentRoleNone
	}
	if namespaceKind == "user" {
		if p.UserID == namespaceID {
			return AgentRolePublish
		}
		return AgentRoleNone
	}
	switch orgRole {
	case RoleOwner:
		return AgentRolePublish
	case RoleAdmin:
		return AgentRoleMaintain
	default:
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
	ActAgentMaintain  Action = "agent.maintain"   // settings, grants
	ActAgentPublish   Action = "agent.publish"    // v* tags, submit, yank
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
	ActAgentRead:      AgentRoleRead,
	ActAgentRepoRead:  AgentRoleRead,
	ActAgentRepoWrite: AgentRoleWrite,
	ActAgentMaintain:  AgentRoleMaintain,
	ActAgentPublish:   AgentRolePublish,
}

// agentScopeFor maps agent actions to PAT scopes (§12.3, §6.4).
var agentScopeFor = map[Action]Scope{
	ActAgentCreate:    ScopeAgentPublish,
	ActAgentRead:      ScopeAgentRead,
	ActAgentRepoRead:  ScopeRepoRead,
	ActAgentRepoWrite: ScopeRepoWrite,
	ActAgentMaintain:  ScopeOrgAdmin,
	ActAgentPublish:   ScopeAgentPublish,
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

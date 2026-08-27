package auth

// Scope is a PAT permission scope (§12.3). Sessions carry no scopes: a
// browser session acts with the user's full authority (mutations gated by
// CSRF); PATs are least-privilege credentials.
type Scope string

// The closed v1 scope list (§12.3).
const (
	ScopeRepoRead     Scope = "repo:read"
	ScopeRepoWrite    Scope = "repo:write"
	ScopeAgentPublish Scope = "agent:publish"
	ScopeAgentRead    Scope = "agent:read"
	ScopeOrgAdmin     Scope = "org:admin"
	ScopeReviewAct    Scope = "review:act"
	ScopeAuditRead    Scope = "audit:read"
	ScopeUserProfile  Scope = "user:profile"
)

// AllScopes enumerates every valid scope (validation, docs, UI).
func AllScopes() []Scope {
	return []Scope{
		ScopeRepoRead, ScopeRepoWrite, ScopeAgentPublish, ScopeAgentRead,
		ScopeOrgAdmin, ScopeReviewAct, ScopeAuditRead, ScopeUserProfile,
	}
}

// ValidScope reports whether s is in the closed scope list.
func ValidScope(s Scope) bool {
	for _, v := range AllScopes() {
		if v == s {
			return true
		}
	}
	return false
}

// HasScope reports whether the scope set includes s. Broader scopes do not
// imply narrower ones in v1 — the list is flat by design (simple to audit).
func HasScope(scopes []string, s Scope) bool {
	for _, have := range scopes {
		if Scope(have) == s {
			return true
		}
	}
	return false
}

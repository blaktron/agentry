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
	// The hosted-run scopes (plans/hosted-runs.md §6, agentry#348): a
	// token that may start, cancel and feed a hosted run of a BriefAgent
	// (run:write) or read a run, its log and its artefacts (run:read).
	// No core route consumes them; the runs extension of the closed build
	// requires them through pkg/extension, so a registry without it treats
	// a token carrying only these as a token with no scope at all.
	ScopeRunRead  Scope = "run:read"
	ScopeRunWrite Scope = "run:write"
	// The knowledge scopes (plan knowledge.md §4.3, agentry#593): a token
	// that may read the caller's knowledge packs, their scan reports and
	// their trees and have a pack's data key unwrapped (knowledge:read), or
	// create, upload, delete and wrap (knowledge:write).
	ScopeKnowledgeRead  Scope = "knowledge:read"
	ScopeKnowledgeWrite Scope = "knowledge:write"
	// The vault scope (plan hosted-credentials-vault.md D13, agentry#676):
	// a token that may set and delete the caller's hosted-run secrets and
	// never list or read one. No core route consumes it; the enterprise
	// build's vault requires it through pkg/extension, and keeps its list
	// for a session alone.
	ScopeSecretWrite Scope = "secret:write"
)

// AllScopes enumerates every valid scope (validation, docs, UI).
func AllScopes() []Scope {
	return []Scope{
		ScopeRepoRead, ScopeRepoWrite, ScopeAgentPublish, ScopeAgentRead,
		ScopeOrgAdmin, ScopeReviewAct, ScopeAuditRead, ScopeUserProfile,
		ScopeRunRead, ScopeRunWrite, ScopeKnowledgeRead, ScopeKnowledgeWrite,
		ScopeSecretWrite,
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

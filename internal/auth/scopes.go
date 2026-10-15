package auth

// Scope is a PAT permission scope. Sessions carry no scopes: a
// browser session acts with the user's full authority (mutations gated by
// CSRF); PATs are least-privilege credentials.
type Scope string

// The closed v1 scope list.
const (
	ScopeRepoRead     Scope = "repo:read"
	ScopeRepoWrite    Scope = "repo:write"
	ScopeAgentPublish Scope = "agent:publish"
	ScopeAgentRead    Scope = "agent:read"
	// ScopeAgentManage lets a token take the owner actions on
	// a QuickAgent it administers: make it public or private, retire,
	// restore and delete it. It is narrower than org:admin, which also
	// covers these: it reaches no other setting of the agent, no grant on
	// it and no organization route. It changes no rung, so the caller must
	// still be the namespace itself or one of its organization's admins.
	ScopeAgentManage Scope = "agent:manage"
	ScopeOrgAdmin    Scope = "org:admin"
	ScopeReviewAct   Scope = "review:act"
	ScopeAuditRead   Scope = "audit:read"
	ScopeUserProfile Scope = "user:profile"
	// The hosted-run scopes: a token that may start, cancel and feed a
	// hosted run of a QuickAgent (run:write) or read a run, its log and
	// its artefacts (run:read). No core route consumes them; the hosted
	// runs extension requires them through pkg/extension, so a registry
	// without it treats a token carrying only these as a token with no
	// scope at all.
	ScopeRunRead  Scope = "run:read"
	ScopeRunWrite Scope = "run:write"
	// The knowledge scopes: a token that may read the caller's knowledge
	// packs, their scan reports and their trees and have a pack's data key
	// unwrapped (knowledge:read), or create, upload, delete and wrap
	// (knowledge:write).
	ScopeKnowledgeRead  Scope = "knowledge:read"
	ScopeKnowledgeWrite Scope = "knowledge:write"
	// The vault scope: a token that may set and delete the caller's
	// hosted-run secrets and never list or read one. No core route
	// consumes it; the hosted vault requires it through pkg/extension, and
	// keeps its list for a session alone.
	ScopeSecretWrite Scope = "secret:write"
	// The voice scopes: a token that may read the caller's Writing Voice,
	// every version's text and review (voice:read), or put, restore, set
	// and delete it (voice:write).
	ScopeVoiceRead  Scope = "voice:read"
	ScopeVoiceWrite Scope = "voice:write"
)

// ScheduleScopes are the scopes a schedule's credential carries:
// what one autonomous run of a QuickAgent needs and nothing more — read
// the agent, start and read the run, and attach the owner's knowledge and
// Writing Voice the schedule names. No write to knowledge, voice or the
// vault, no repository access and nothing administrative: a schedule
// starts a run, it does not change what the run reads. Fresh on every
// call, so no caller can widen another's set.
func ScheduleScopes() []string {
	return []string{
		string(ScopeAgentRead), string(ScopeRunRead), string(ScopeRunWrite),
		string(ScopeKnowledgeRead), string(ScopeVoiceRead),
	}
}

// AllScopes enumerates every valid scope (validation, docs, UI).
func AllScopes() []Scope {
	return []Scope{
		ScopeRepoRead, ScopeRepoWrite, ScopeAgentPublish, ScopeAgentRead,
		ScopeAgentManage, ScopeOrgAdmin, ScopeReviewAct, ScopeAuditRead, ScopeUserProfile,
		ScopeRunRead, ScopeRunWrite, ScopeKnowledgeRead, ScopeKnowledgeWrite,
		ScopeSecretWrite, ScopeVoiceRead, ScopeVoiceWrite,
	}
}

// SignInGrantScopes is the scope set the desktop app's and the CLI's
// sign-in grant mints: browse and install (agent:read, repo:read), Build →
// publish (agent:publish, repo:write), identity (user:profile), and hosted
// runs — In Agentry on RunPanel (run:read, run:write), the Knowledge
// panel's packs and their keys (knowledge:read, knowledge:write), and the
// hosted-run start's secrets, set and deleted, never read (secret:write),
// and the account's Writing Voice, read, uploaded and downloaded
// (voice:read, voice:write), and the owner actions on the person's own
// QuickAgents and their organizations' where they are an admin
// (agent:manage).
// Deliberately no review:act and no org scopes. Fixed server-side so a
// caller of the grant endpoint cannot widen it, and shown verbatim on the
// approval page.
func SignInGrantScopes() []string {
	return []string{
		string(ScopeAgentRead), string(ScopeAgentPublish), string(ScopeAgentManage),
		string(ScopeRepoRead), string(ScopeRepoWrite),
		string(ScopeUserProfile), string(ScopeRunRead), string(ScopeRunWrite),
		string(ScopeKnowledgeRead), string(ScopeKnowledgeWrite), string(ScopeSecretWrite),
		string(ScopeVoiceRead), string(ScopeVoiceWrite),
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

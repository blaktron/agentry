package extension

import (
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/registry"
)

// A fork's reference carries its origin, the agent and its publisher's
// namespace, for the earnings a fork's runs owe the origin; an agent
// that is no fork carries none.
func TestAgentRefCarriesAForksOrigin(t *testing.T) {
	origin, originNS, ns := uuid.New(), uuid.New(), uuid.New()
	kind := "org"
	fork := registry.Agent{ID: uuid.New(), NamespaceID: ns, NamespaceKind: "user", Visibility: "private",
		ForkedFromAgentID: &origin, OriginNamespaceID: &originNS, OriginNamespaceKind: &kind}
	ref := agentRefOf(fork)
	if ref.Public || ref.ForkedFrom == nil {
		t.Fatalf("fork ref = %+v", ref)
	}
	if got := *ref.ForkedFrom; got.AgentID != origin || got.NamespaceID != originNS || got.NamespaceKind != NamespaceOrg {
		t.Fatalf("origin = %+v", got)
	}
	plain := agentRefOf(registry.Agent{ID: uuid.New(), NamespaceID: ns, NamespaceKind: "user", Visibility: "public"})
	if !plain.Public || plain.ForkedFrom != nil {
		t.Fatalf("plain ref = %+v", plain)
	}

	// The reference names the agent and the namespace it lives in, and is
	// public only for the one visibility the core calls public: anything
	// else, a missing visibility included, reads as not public. A fork's
	// origin is all three facts or none: a row that lost one names no
	// origin rather than a half-filled one.
	id := uuid.New()
	for _, c := range []struct {
		name       string
		agent      registry.Agent
		kind       NamespaceKind
		public     bool
		wantOrigin bool
	}{
		{"a public user agent", registry.Agent{ID: id, NamespaceID: ns, NamespaceKind: "user", Visibility: "public"}, NamespaceUser, true, false},
		{"a private org agent", registry.Agent{ID: id, NamespaceID: ns, NamespaceKind: "org", Visibility: "private"}, NamespaceOrg, false, false},
		{"no visibility is not public", registry.Agent{ID: id, NamespaceID: ns, NamespaceKind: "user"}, NamespaceUser, false, false},
		{"a fork", registry.Agent{ID: id, NamespaceID: ns, NamespaceKind: "user", Visibility: "private",
			ForkedFromAgentID: &origin, OriginNamespaceID: &originNS, OriginNamespaceKind: &kind}, NamespaceUser, false, true},
		{"an origin without its agent", registry.Agent{ID: id, NamespaceID: ns, NamespaceKind: "user", Visibility: "private",
			OriginNamespaceID: &originNS, OriginNamespaceKind: &kind}, NamespaceUser, false, false},
		{"an origin without its namespace", registry.Agent{ID: id, NamespaceID: ns, NamespaceKind: "user", Visibility: "private",
			ForkedFromAgentID: &origin, OriginNamespaceKind: &kind}, NamespaceUser, false, false},
		{"an origin without its namespace kind", registry.Agent{ID: id, NamespaceID: ns, NamespaceKind: "user", Visibility: "private",
			ForkedFromAgentID: &origin, OriginNamespaceID: &originNS}, NamespaceUser, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ref := agentRefOf(c.agent)
			if ref.ID != id || ref.NamespaceID != ns || ref.NamespaceKind != c.kind || ref.Public != c.public {
				t.Fatalf("ref = %+v, want agent %s in %s namespace %s, public %v", ref, id, c.kind, ns, c.public)
			}
			if !c.wantOrigin {
				if ref.ForkedFrom != nil {
					t.Fatalf("origin = %+v, want none", *ref.ForkedFrom)
				}
				return
			}
			if ref.ForkedFrom == nil {
				t.Fatal("a fork carries no origin")
			}
			if got, want := *ref.ForkedFrom, (AgentOrigin{AgentID: origin, NamespaceID: originNS, NamespaceKind: NamespaceOrg}); got != want {
				t.Fatalf("origin = %+v, want %+v", got, want)
			}
		})
	}
}

package extension

import (
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/registry"
)

// A fork's reference carries its origin, the agent and its publisher's
// namespace, for the earnings a fork's runs owe the origin (agentry#943);
// an agent that is no fork carries none.
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
}

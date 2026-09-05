// Agent creation under DEV-088: the withdrawn kind is refused, run modes
// are derived from a v1 kind when none are given, and the mode facet
// counts what was created. DB-backed, like the rest of this package.
package scan_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/registry"
)

func (e *pipeEnv) ownerPrincipal(ctx context.Context) (*auth.Principal, string) {
	e.t.Helper()
	u, err := e.st.Queries().GetUserByID(ctx, e.owner)
	if err != nil {
		e.t.Fatal(err)
	}
	return &auth.Principal{UserID: e.owner, Handle: u.Handle, Via: "session", EmailVerified: true,
		OrgRoles: map[uuid.UUID]auth.OrgRole{}}, u.Handle
}

func TestCreateAgentModes(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	p, ns := e.ownerPrincipal(ctx)
	ev := audit.Event{Actor: e.owner, ActorKind: audit.ActorUser}

	t.Run("withdrawn kind refused", func(t *testing.T) {
		_, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{
			Namespace: ns, Name: "withdrawn-mcp", Kind: "mcp-server", Visibility: "private",
		}, ev)
		if err == nil || !strings.Contains(err.Error(), "withdrawn") {
			t.Fatalf("kind mcp-server must be refused as withdrawn, got %v", err)
		}
	})

	t.Run("v1 kind derives autonomous", func(t *testing.T) {
		a, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{
			Namespace: ns, Name: "modes-derived", Kind: "skill", Visibility: "public",
		}, ev)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(a.Modes, []string{"autonomous"}) {
			t.Fatalf("modes = %v, want [autonomous]", a.Modes)
		}
	})

	t.Run("explicit modes kept, deduplicated", func(t *testing.T) {
		a, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{
			Namespace: ns, Name: "modes-both", Kind: "prompt-agent", Visibility: "public",
			Modes: []string{"interactive", "autonomous", "interactive"},
		}, ev)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(a.Modes, []string{"interactive", "autonomous"}) {
			t.Fatalf("modes = %v, want [interactive autonomous]", a.Modes)
		}
	})

	t.Run("unknown mode refused", func(t *testing.T) {
		_, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{
			Namespace: ns, Name: "modes-bad", Kind: "skill", Visibility: "private",
			Modes: []string{"batch"},
		}, ev)
		if err == nil || !strings.Contains(err.Error(), "unknown mode") {
			t.Fatalf("unknown mode must be refused, got %v", err)
		}
	})

	t.Run("mode facet counts public agents per mode", func(t *testing.T) {
		rows, err := e.st.Queries().SearchFacetModes(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int64{}
		for _, r := range rows {
			counts[r.Mode] = r.N
		}
		// Two public agents above support autonomous; one supports interactive.
		if counts["autonomous"] < 2 || counts["interactive"] < 1 {
			t.Fatalf("facet counts %v: want autonomous ≥ 2 and interactive ≥ 1", counts)
		}
	})
}

// Agent creation: run modes default to autonomous, explicit
// ones are validated and deduplicated, and the mode facet counts what was
// created. (The withdrawn kind is the manifest validator's business.) DB-backed, like the rest of this package.
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

	t.Run("defaults to autonomous when none given", func(t *testing.T) {
		a, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{
			Namespace: ns, Name: "modes-derived", Visibility: "public",
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
			Namespace: ns, Name: "modes-both", Visibility: "public",
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
			Namespace: ns, Name: "modes-bad", Visibility: "private",
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

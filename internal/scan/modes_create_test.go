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
	storegen "github.com/blaktron/agentry/internal/store/gen"
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
	facet := func() map[string]int64 {
		t.Helper()
		rows, err := e.st.Queries().SearchFacetModes(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int64{}
		for _, r := range rows {
			counts[r.Mode] = r.N
		}
		return counts
	}
	// The database is shared with the rest of the package, so the facet is
	// read against what it held before this test created anything.
	before := facet()

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

	// The store's constraint takes the persistent mode as the registry does,
	// alone or beside the others, and still refuses an unknown one beside it.
	t.Run("persistent mode stored", func(t *testing.T) {
		a, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{
			Namespace: ns, Name: "modes-persistent", Visibility: "public",
			Modes: []string{"persistent"},
		}, ev)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(a.Modes, []string{"persistent"}) {
			t.Fatalf("modes = %v, want [persistent]", a.Modes)
		}
		b, err := e.reg.CreateAgent(ctx, p, registry.CreateAgentInput{
			Namespace: ns, Name: "modes-all-three", Visibility: "private",
			Modes: []string{"autonomous", "interactive", "persistent"},
		}, ev)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(b.Modes, []string{"autonomous", "interactive", "persistent"}) {
			t.Fatalf("modes = %v, want all three", b.Modes)
		}
		if _, err := e.st.Pool().Exec(ctx, `UPDATE agents SET modes = '{persistent,batch}' WHERE id = $1`, a.ID); err == nil {
			t.Fatal("the store took an unknown mode beside persistent")
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
		counts := facet()
		// Two public agents above support autonomous; one supports
		// interactive; one supports persistent. The private agent that
		// supports all three is not counted.
		for mode, want := range map[string]int64{"autonomous": 2, "interactive": 1, "persistent": 1} {
			if got := counts[mode] - before[mode]; got != want {
				t.Fatalf("facet count of %s grew by %d, want %d (before %v, now %v)", mode, got, want, before, counts)
			}
		}
	})

	t.Run("mode facet leaves out a blocked agent", func(t *testing.T) {
		a, err := e.reg.Resolve(ctx, ns, "modes-both")
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.Queries().SetAgentQuarantineState(ctx, storegen.SetAgentQuarantineStateParams{ID: a.ID, QuarantineState: "blocked"}); err != nil {
			t.Fatal(err)
		}
		counts := facet()
		for mode, want := range map[string]int64{"autonomous": 1, "interactive": 0, "persistent": 1} {
			if got := counts[mode] - before[mode]; got != want {
				t.Fatalf("with modes-both blocked, facet count of %s grew by %d, want %d", mode, got, want)
			}
		}
	})
}

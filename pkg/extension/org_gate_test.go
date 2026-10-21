package extension

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// TestOrgGateIsBoundAndAnswersByState: an extension that binds on a server
// with a database holds the organization gate, and what it answers for an
// organization follows the organization's state: active reads and writes,
// suspended is absent, its decommission hold reads and does not write, an
// erased one and one that never existed are absent with no error.
func TestOrgGateIsBoundAndAnswersByState(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	ext := &namedBinder{name: "gate-probe"}
	applyExtensions(srv, []Extension{ext})
	gate := ext.deps.OrgGate
	if gate == nil {
		t.Fatal("a server with a database handed out no organization gate")
	}

	ctx := context.Background()
	id := uuid.New()
	handle := "gate-" + strings.ReplaceAll(id.String(), "-", "")[:20]
	pool := st.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO handles (id, handle, kind) VALUES ($1, $2, 'org')`, id, handle); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, display_name) VALUES ($1, $2)`, id, handle); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		state            string
		readable, writes bool
	}{
		{"active", true, true},
		{"suspended", false, false},
		{"decommissioning", true, false},
		{"decommissioned", false, false},
	} {
		if _, err := pool.Exec(ctx, `UPDATE orgs SET state = $2, decommission_at = CASE WHEN $2 = 'decommissioning' THEN now() + interval '7 days' END WHERE id = $1`, id, c.state); err != nil {
			t.Fatal(err)
		}
		readable, err := gate.Readable(ctx, id)
		if err != nil || readable != c.readable {
			t.Errorf("%s: Readable = %v, %v; want %v", c.state, readable, err, c.readable)
		}
		writable, err := gate.Writable(ctx, id)
		if err != nil || writable != c.writes {
			t.Errorf("%s: Writable = %v, %v; want %v", c.state, writable, err, c.writes)
		}
	}
	if readable, err := gate.Readable(ctx, uuid.New()); err != nil || readable {
		t.Errorf("an organization that does not exist: Readable = %v, %v; want false with no error", readable, err)
	}
}

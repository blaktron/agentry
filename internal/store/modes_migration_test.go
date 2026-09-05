// 00023_agent_modes: the backfill, the block on the withdrawn kind, the
// advisory that explains it, and the constraints — proven on a scratch
// database driven stepwise, because the shared test database is already at
// the latest version by the time any package looks at it.
package store

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"
)

func TestAgentModesMigration(t *testing.T) {
	baseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := pgx.ParseConfig(baseURL)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	scratch := fmt.Sprintf("agentry_modes_%d", time.Now().UnixNano())
	scratchURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.User, url.PathEscape(cfg.Password), cfg.Host, cfg.Port, scratch)
	admin, err := Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect (admin): %v", err)
	}
	if _, err := admin.Pool().Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		admin.Close()
		t.Fatalf("create scratch database: %v", err)
	}
	admin.Close()
	defer func() {
		cleanup, err := Connect(context.WithoutCancel(ctx), baseURL)
		if err != nil {
			t.Errorf("connect (cleanup): %v", err)
			return
		}
		_, _ = cleanup.Pool().Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		cleanup.Close()
	}()

	db, err := connectStd(scratchURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustFail := func(what, q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err == nil {
			t.Fatalf("%s: expected the constraint to refuse", what)
		}
	}

	// The world before modes: one agent per v1 kind.
	if err := goose.UpToContext(ctx, db, "migrations", 22); err != nil {
		t.Fatalf("up to 22: %v", err)
	}
	const ns, repoSkill, repoPrompt, repoMCP = "a0000000-0000-7000-8000-000000000001", "b0000000-0000-7000-8000-000000000001", "b0000000-0000-7000-8000-000000000002", "b0000000-0000-7000-8000-000000000003"
	const skill, prompt, mcp = "c0000000-0000-7000-8000-000000000001", "c0000000-0000-7000-8000-000000000002", "c0000000-0000-7000-8000-000000000003"
	exec(`INSERT INTO handles (id, handle, kind) VALUES ($1, 'modesns', 'user')`, ns)
	exec(`INSERT INTO repos (id) VALUES ($1), ($2), ($3)`, repoSkill, repoPrompt, repoMCP)
	exec(`INSERT INTO agents (id, namespace_id, name, kind, visibility, repo_id, summary) VALUES
		($1, $4, 'a-skill', 'skill', 'public', $5, ''),
		($2, $4, 'a-prompt', 'prompt-agent', 'public', $6, ''),
		($3, $4, 'a-mcp', 'mcp-server', 'public', $7, '')`, skill, prompt, mcp, ns, repoSkill, repoPrompt, repoMCP)

	if err := goose.UpToContext(ctx, db, "migrations", 23); err != nil {
		t.Fatalf("up to 23: %v", err)
	}

	modesOf := func(id string) (modes []string, state string) {
		t.Helper()
		if err := db.QueryRowContext(ctx, `SELECT modes, quarantine_state FROM agents WHERE id = $1`, id).Scan(pqArray(&modes), &state); err != nil {
			t.Fatal(err)
		}
		return modes, state
	}
	for _, id := range []string{skill, prompt} {
		if modes, state := modesOf(id); fmt.Sprint(modes) != "[autonomous]" || state != "none" {
			t.Fatalf("v1 instruction kind after backfill: modes=%v state=%s, want [autonomous] none", modes, state)
		}
	}
	if modes, state := modesOf(mcp); len(modes) != 0 || state != "blocked" {
		t.Fatalf("mcp-server after backfill: modes=%v state=%s, want [] blocked", modes, state)
	}
	var advisories int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM advisories WHERE agent_id = $1 AND summary LIKE 'Package kind withdrawn%'`, mcp).Scan(&advisories); err != nil {
		t.Fatal(err)
	}
	if advisories != 1 {
		t.Fatalf("withdrawal advisory rows for the mcp-server = %d, want 1", advisories)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM advisories WHERE agent_id IN ($1, $2)`, skill, prompt).Scan(&advisories); err != nil {
		t.Fatal(err)
	}
	if advisories != 0 {
		t.Fatalf("instruction kinds must get no advisory, got %d", advisories)
	}

	// The constraints: values from the closed set, and no empty set unless blocked.
	mustFail("unknown mode", `UPDATE agents SET modes = '{batch}' WHERE id = $1`, skill)
	mustFail("empty modes on an unblocked agent", `UPDATE agents SET modes = '{}' WHERE id = $1`, skill)
	exec(`UPDATE agents SET modes = '{autonomous,interactive}' WHERE id = $1`, skill)
	// A new row without modes is an instruction package: autonomous by default.
	exec(`INSERT INTO repos (id) VALUES ('b0000000-0000-7000-8000-000000000004')`)
	exec(`INSERT INTO agents (id, namespace_id, name, kind, visibility, repo_id, summary)
		VALUES ('c0000000-0000-7000-8000-000000000004', $1, 'a-new', 'skill', 'private', 'b0000000-0000-7000-8000-000000000004', '')`, ns)
	if modes, _ := modesOf("c0000000-0000-7000-8000-000000000004"); fmt.Sprint(modes) != "[autonomous]" {
		t.Fatalf("default modes = %v, want [autonomous]", modes)
	}

	// Down removes the column and the advisory it wrote; the block stays.
	if err := goose.DownToContext(ctx, db, "migrations", 22); err != nil {
		t.Fatalf("down to 22: %v", err)
	}
	var cols int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'agents' AND column_name = 'modes'`).Scan(&cols); err != nil {
		t.Fatal(err)
	}
	if cols != 0 {
		t.Fatal("modes column survived the down migration")
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM advisories WHERE summary LIKE 'Package kind withdrawn%'`).Scan(&advisories); err != nil {
		t.Fatal(err)
	}
	if advisories != 0 {
		t.Fatalf("withdrawal advisories survived the down migration: %d", advisories)
	}
	var state string
	if err := db.QueryRowContext(ctx, `SELECT quarantine_state FROM agents WHERE id = $1`, mcp).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "blocked" {
		t.Fatalf("down must leave the block in place, got %s", state)
	}
	// And up again is clean.
	if err := goose.UpToContext(ctx, db, "migrations", 23); err != nil {
		t.Fatalf("up to 23 again: %v", err)
	}
}

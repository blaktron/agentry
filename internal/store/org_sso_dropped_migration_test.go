// 00063_org_sso_scim_dropped: the organization sign-in connections, the
// SCIM tokens and the SAML state go, and nothing a sign-in or a membership
// still rests on moves — proven on a scratch database driven stepwise,
// because the shared test database is already at the latest version by the
// time any package looks at it.
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

func TestOrgSSOAndSCIMDroppedMigration(t *testing.T) {
	baseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := pgx.ParseConfig(baseURL)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	scratch := fmt.Sprintf("agentry_orgsso_%d", time.Now().UnixNano())
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
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	tableExists := func(name string) bool {
		t.Helper()
		return count(`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1`, name) == 1
	}

	if err := goose.UpToContext(ctx, db, "migrations", 62); err != nil {
		t.Fatalf("up to 62: %v", err)
	}
	const (
		org        = "a0000000-0000-7000-8000-000000000001"
		alice      = "a0000000-0000-7000-8000-000000000002"
		bob        = "a0000000-0000-7000-8000-000000000003"
		conn       = "b0000000-0000-7000-8000-000000000001"
		aliceIdent = "c0000000-0000-7000-8000-000000000001"
		bobIdent   = "c0000000-0000-7000-8000-000000000002"
		orgIdent   = "c0000000-0000-7000-8000-000000000003"
		team       = "d0000000-0000-7000-8000-000000000001"
		session    = "e0000000-0000-7000-8000-000000000001"
	)
	exec(`INSERT INTO handles (id, handle, kind) VALUES ($1, 'ssoorg', 'org'), ($2, 'alice', 'user'), ($3, 'bob', 'user')`, org, alice, bob)
	exec(`INSERT INTO users (id, email) VALUES ($1, 'alice@example.test'), ($2, 'bob@example.test')`, alice, bob)
	exec(`INSERT INTO orgs (id, display_name, sso_required) VALUES ($1, 'SSO Org', true)`, org)
	exec(`INSERT INTO memberships (org_id, user_id, role, via_scim, state) VALUES ($1, $2, 'admin', false, 'active'), ($1, $3, 'member', true, 'pending')`, org, alice, bob)
	exec(`INSERT INTO sso_connections (id, org_id, kind, enabled) VALUES ($1, $2, 'saml', true)`, conn, org)
	exec(`INSERT INTO scim_tokens (id, org_id, token_sha256) VALUES (gen_random_uuid(), $1, '\x01')`, org)
	// The identities a sign-in uses: through the deployment's OpenID
	// provider, one of them bound to a directory account. And one linked
	// through the organization's own connection.
	exec(`INSERT INTO identities (id, user_id, provider_kind, sso_connection_id, subject, directory_account_id) VALUES
		($1, $4, 'social', NULL, 'authentik:alice', 7),
		($2, $5, 'social', NULL, 'google:bob', NULL),
		($3, $5, 'saml', $6, 'bob@example.test', NULL)`, aliceIdent, bobIdent, orgIdent, alice, bob, conn)
	exec(`INSERT INTO teams (id, org_id, slug, scim_group_id) VALUES ($1, $2, 'eng', 'group-1')`, team, org)
	exec(`INSERT INTO sessions (id, token_sha256, user_id, csrf_token, expires_at, sso_connection_id, saml_name_id, saml_session_index, sso_tags)
		VALUES ($1, '\x02', $2, 'csrf', now() + interval '1 day', $3, 'alice', 'idx', jsonb_build_object($4::text, now()::text))`, session, alice, conn, org)

	identitiesBefore := map[string]string{}
	rows, err := db.QueryContext(ctx, `SELECT subject, user_id FROM identities WHERE sso_connection_id IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var subject, user string
		if err := rows.Scan(&subject, &user); err != nil {
			t.Fatal(err)
		}
		identitiesBefore[subject] = user
	}
	_ = rows.Close()

	if err := goose.UpToContext(ctx, db, "migrations", 63); err != nil {
		t.Fatalf("up to 63: %v", err)
	}

	// Every identity a sign-in uses resolves to the same account.
	for subject, user := range identitiesBefore {
		var got string
		var account *int64
		if err := db.QueryRowContext(ctx, `SELECT user_id, directory_account_id FROM identities
			WHERE provider_kind = 'social' AND sso_connection_id IS NULL AND subject = $1`, subject).Scan(&got, &account); err != nil {
			t.Fatalf("identity %s after the migration: %v", subject, err)
		}
		if got != user {
			t.Fatalf("identity %s resolves to %s after the migration, want %s", subject, got, user)
		}
		if subject == "authentik:alice" && (account == nil || *account != 7) {
			t.Fatalf("the directory account of %s after the migration = %v, want 7", subject, account)
		}
	}
	if n := count(`SELECT count(*) FROM identities`); n != len(identitiesBefore) {
		t.Fatalf("identities after the migration = %d, want the %d a sign-in uses", n, len(identitiesBefore))
	}
	// Memberships, roles, pending state and the provisioned flag are as
	// they were, and so are the organization's enforced SSO and the
	// session's SSO tag.
	if n := count(`SELECT count(*) FROM memberships WHERE org_id = $1 AND user_id = $2 AND role = 'admin' AND state = 'active' AND NOT via_scim`, org, alice); n != 1 {
		t.Fatal("the admin's membership changed")
	}
	if n := count(`SELECT count(*) FROM memberships WHERE org_id = $1 AND user_id = $2 AND role = 'member' AND state = 'pending' AND via_scim`, org, bob); n != 1 {
		t.Fatal("the provisioned pending membership changed")
	}
	if n := count(`SELECT count(*) FROM orgs WHERE id = $1 AND sso_required`, org); n != 1 {
		t.Fatal("the organization's enforced SSO changed")
	}
	if n := count(`SELECT count(*) FROM sessions WHERE id = $1 AND sso_tags ? $2 AND revoked_at IS NULL`, session, org); n != 1 {
		t.Fatal("the session or its SSO tag changed")
	}
	if n := count(`SELECT count(*) FROM teams WHERE id = $1`, team); n != 1 {
		t.Fatal("the team went with its group id")
	}
	for _, table := range []string{"sso_connections", "scim_tokens", "saml_requests", "saml_consumed_assertions"} {
		if tableExists(table) {
			t.Fatalf("%s survived the migration", table)
		}
	}
	if n := count(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'sessions' AND column_name IN ('sso_connection_id', 'saml_name_id', 'saml_session_index')`); n != 0 {
		t.Fatalf("%d SAML logout column(s) survived on sessions", n)
	}
	// An identity may still be written without a connection, the only kind
	// there is now.
	exec(`INSERT INTO identities (id, user_id, provider_kind, subject) VALUES (gen_random_uuid(), $1, 'social', 'authentik:bob')`, bob)

	// Down and up again.
	if err := goose.DownToContext(ctx, db, "migrations", 62); err != nil {
		t.Fatalf("down to 62: %v", err)
	}
	if !tableExists("sso_connections") || !tableExists("scim_tokens") {
		t.Fatal("down did not restore the tables")
	}
	if err := goose.UpToContext(ctx, db, "migrations", 63); err != nil {
		t.Fatalf("up to 63 again: %v", err)
	}
}

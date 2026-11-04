// 00067_user_report_designs: every version-2 report design becomes the
// account's one default design of the same name, version 3, with the
// defaults that keep its look, its logo with it; a row that holds no
// version-2 document is dropped; the old table goes. Proven on a scratch
// database driven stepwise, because the shared test database is already at
// the latest version by the time any package looks at it.
package store

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/blaktron/agentry/pkg/reportdesign"
)

func TestReportDesignsMigration(t *testing.T) {
	baseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := pgx.ParseConfig(baseURL)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	scratch := fmt.Sprintf("agentry_rdesign_%d", time.Now().UnixNano())
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

	if err := goose.UpToContext(ctx, db, "migrations", 66); err != nil {
		t.Fatalf("up to 66: %v", err)
	}
	// Three accounts: one with a version-2 design under a band title block
	// and a footer line, with a logo; one with a ruled title block and no
	// footer line; one whose row holds no version-2 document.
	band, ruled, junk := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO handles (id, handle, kind) VALUES ($1, 'rdband', 'user'), ($2, 'rdruled', 'user'), ($3, 'rdjunk', 'user')`, band, ruled, junk)
	exec(`INSERT INTO users (id, email) VALUES ($1, 'band@example.test'), ($2, 'ruled@example.test'), ($3, 'junk@example.test')`, band, ruled, junk)
	const v2Band = `{"agentryTheme": 2, "name": "Acme band", "basedOn": "modern", "version": 4, "paper": "letter",
		"fonts": {"headings": "Inter", "body": "Inter", "code": "JetBrains Mono"}, "accent": "#1f6feb",
		"titleBlock": "band", "headings": "bar", "tables": {"tinted": true, "banded": true}, "quotes": "callout",
		"footer": {"pageNumbers": "nOfN", "text": "Acme Ltd — confidential {not a token}"}}`
	const v2Ruled = `{"agentryTheme": 2, "name": "Classic", "basedOn": "classic", "version": 1, "paper": "a4",
		"fonts": {"headings": "Source Serif 4", "body": "Source Serif 4", "code": "IBM Plex Mono"}, "accent": "#1f3a5f",
		"titleBlock": "ruled", "headings": "smallcaps", "tables": {"tinted": true, "banded": false}, "quotes": "callout",
		"footer": {"pageNumbers": "n", "text": ""}}`
	logo := []byte("\x89PNG\r\n\x1a\nnot really a png, but the bytes move as they are")
	exec(`INSERT INTO user_report_settings (user_id, design, logo) VALUES ($1, $2::jsonb, $3)`, band, v2Band, logo)
	exec(`INSERT INTO user_report_settings (user_id, design) VALUES ($1, $2::jsonb)`, ruled, v2Ruled)
	exec(`INSERT INTO user_report_settings (user_id, design) VALUES ($1, '{}'::jsonb)`, junk)

	if err := goose.UpToContext(ctx, db, "migrations", 67); err != nil {
		t.Fatalf("up to 67: %v", err)
	}
	if tableExists("user_report_settings") {
		t.Fatal("the old table is still there")
	}
	if n := count(`SELECT count(*) FROM user_report_designs`); n != 2 {
		t.Fatalf("%d designs after the migration, want 2", n)
	}
	if n := count(`SELECT count(*) FROM user_report_designs WHERE user_id = $1`, junk); n != 0 {
		t.Fatalf("a row with no version-2 document became %d designs", n)
	}
	read := func(user uuid.UUID) (reportdesign.Design, []byte, bool) {
		t.Helper()
		var doc, storedLogo []byte
		var isDefault bool
		if err := db.QueryRowContext(ctx, `SELECT document, logo, is_default FROM user_report_designs WHERE user_id = $1`, user).Scan(&doc, &storedLogo, &isDefault); err != nil {
			t.Fatalf("read %s: %v", user, err)
		}
		d, err := reportdesign.Parse(doc)
		if err != nil {
			t.Fatalf("the moved document does not validate: %v\n%s", err, doc)
		}
		return d, storedLogo, isDefault
	}
	// The band design: the same name, revision, paper, faces, accent,
	// title block, headings, tables, quotes and page numbers; no secondary,
	// no brand, no header; the footer line in the left slot, braces and
	// all; a band cover drawn when long; regular scale and margins; the
	// default; the logo moved.
	d, storedLogo, isDefault := read(band)
	want, _ := reportdesign.Builtin("modern")
	want.Name, want.Version, want.Paper, want.Header = "Acme band", 4, "letter", reportdesign.Header{Style: "none", Slots: [3]string{"", "", ""}}
	want.Footer.Slots = [3]string{"Acme Ltd — confidential {not a token}", "", ""}
	want.Cover = reportdesign.Cover{Style: "band", Shows: []string{"title", "subtitle", "author", "date"}, When: "long"}
	if !bytes.Equal(d.Canonical(), want.Canonical()) || !isDefault || !bytes.Equal(storedLogo, logo) {
		t.Fatalf("the band design moved as\n%s\nwant\n%s\n(default %v, logo moved %v)", d.Canonical(), want.Canonical(), isDefault, bytes.Equal(storedLogo, logo))
	}
	// Its version-2 projection is the row it came from, so a reader of
	// version 2 sees the same design.
	if v2 := d.Version2(); !bytes.Contains(v2, []byte(`"text": "Acme Ltd — confidential {not a token}"`)) || !bytes.Contains(v2, []byte(`"titleBlock": "band"`)) {
		t.Fatalf("the projection back: %s", v2)
	}
	// The ruled design: a framed cover, an empty left slot, no logo.
	d, storedLogo, isDefault = read(ruled)
	want, _ = reportdesign.Builtin("classic")
	want.Header = reportdesign.Header{Style: "none", Slots: [3]string{"", "", ""}}
	want.Footer.Slots = [3]string{"", "", ""}
	want.Cover = reportdesign.Cover{Style: "framed", Shows: []string{"title", "subtitle", "author", "date"}, When: "long"}
	if !bytes.Equal(d.Canonical(), want.Canonical()) || !isDefault || storedLogo != nil {
		t.Fatalf("the ruled design moved as\n%s\nwant\n%s\n(default %v, logo %v)", d.Canonical(), want.Canonical(), isDefault, storedLogo)
	}
	// One default per account holds as a constraint.
	if _, err := db.ExecContext(ctx, `INSERT INTO user_report_designs (user_id, document, is_default) VALUES ($1, '{}'::jsonb, true)`, band); err == nil {
		t.Fatal("a second default for one account was taken")
	}
	// The Down recreates the old table, empty.
	if err := goose.DownToContext(ctx, db, "migrations", 66); err != nil {
		t.Fatalf("down to 66: %v", err)
	}
	if !tableExists("user_report_settings") || tableExists("user_report_designs") || count(`SELECT count(*) FROM user_report_settings`) != 0 {
		t.Fatal("the Down did not restore the old table empty")
	}
}

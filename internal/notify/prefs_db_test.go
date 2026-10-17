package notify

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The two halves of AllowsEmail fail in opposite directions:
// a user that cannot be read gets no mail, a settings row that cannot be
// read gets the defaults. Both need a database because both are about what
// the queries return, not about the decision.
func TestAllowsEmailFailureDirections(t *testing.T) {
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	q := st.Queries()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	handle := "notify" + strings.ReplaceAll(id.String()[:8], "-", "")
	if err := q.CreateHandle(ctx, storegen.CreateHandleParams{ID: id, Handle: handle, Kind: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateUser(ctx, storegen.CreateUserParams{ID: id, Email: handle + "@example.test", DisplayName: handle}); err != nil {
		t.Fatal(err)
	}

	// Unknown user: fail closed.
	if AllowsEmail(ctx, q, nil, uuid.New(), KindQuarantine) {
		t.Fatal("a user that cannot be read must get no mail")
	}
	// Known but unverified: no mail; verified: mail.
	if AllowsEmail(ctx, q, nil, id, KindQuarantine) {
		t.Fatal("an unverified address must get no mail")
	}
	if err := q.MarkEmailVerified(ctx, id); err != nil {
		t.Fatal(err)
	}
	if !AllowsEmail(ctx, q, nil, id, KindQuarantine) {
		t.Fatal("a verified address with no settings row must get mail")
	}
	// Settings query broken: fail open — the verified address still gets mail.
	broken := storegen.New(failingDB{DBTX: st.Pool(), match: "user_notification_settings"})
	if !AllowsEmail(ctx, broken, nil, id, KindQuarantine) {
		t.Fatal("a settings read error must not silence a security mail")
	}
	// And the settings still bind when they can be read.
	if _, err := st.Pool().Exec(ctx, `INSERT INTO user_notification_settings (user_id, email_quarantine) VALUES ($1, false)`, id); err != nil {
		t.Fatal(err)
	}
	if AllowsEmail(ctx, q, nil, id, KindQuarantine) {
		t.Fatal("switched-off kind must be refused for a verified address")
	}
}

// failingDB is a DBTX whose queries mentioning match fail; everything else
// reaches the pool.
type failingDB struct {
	storegen.DBTX
	match string
}

var errBrokenQuery = errors.New("settings query broken for the test")

func (f failingDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if strings.Contains(sql, f.match) {
		return pgconn.CommandTag{}, errBrokenQuery
	}
	return f.DBTX.Exec(ctx, sql, args...)
}

func (f failingDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if strings.Contains(sql, f.match) {
		return nil, errBrokenQuery
	}
	return f.DBTX.Query(ctx, sql, args...)
}

func (f failingDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if strings.Contains(sql, f.match) {
		return errRow{err: errBrokenQuery}
	}
	return f.DBTX.QueryRow(ctx, sql, args...)
}

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

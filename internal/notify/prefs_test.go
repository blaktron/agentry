package notify

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

func TestEmailAllowedDefaultsAndKinds(t *testing.T) {
	row := Defaults(uuid.New())
	for _, k := range []Kind{KindDependencyAlert, KindQuarantine, KindReviewDecision, KindAdvisory, KindOrgInvite, KindBilling, KindSchedule, KindBugReport, Kind("something-new")} {
		if !EmailAllowed(row, k) {
			t.Fatalf("defaults must allow %s", k)
		}
	}
	row.EmailReviewDecisions = false
	row.EmailOrgInvites = false
	if EmailAllowed(row, KindReviewDecision) || EmailAllowed(row, KindOrgInvite) {
		t.Fatal("switched-off kinds must be refused")
	}
	if !EmailAllowed(row, KindQuarantine) || !EmailAllowed(row, KindDependencyAlert) {
		t.Fatal("other kinds stay on")
	}

	// A person with no row is the defaults: theirs by id, every mail kind on,
	// and the web dependency alert on.
	id := uuid.New()
	if d := Defaults(id); d.UserID != id || !d.WebDependencyAlerts {
		t.Fatalf("Defaults(%s) = %+v", id, d)
	}

	// Each switch governs its own kind and no other, for every kind there is.
	switches := map[Kind]func(*storegen.UserNotificationSetting){
		KindDependencyAlert: func(r *storegen.UserNotificationSetting) { r.EmailDependencyAlerts = false },
		KindQuarantine:      func(r *storegen.UserNotificationSetting) { r.EmailQuarantine = false },
		KindReviewDecision:  func(r *storegen.UserNotificationSetting) { r.EmailReviewDecisions = false },
		KindAdvisory:        func(r *storegen.UserNotificationSetting) { r.EmailAdvisories = false },
		KindOrgInvite:       func(r *storegen.UserNotificationSetting) { r.EmailOrgInvites = false },
		KindBilling:         func(r *storegen.UserNotificationSetting) { r.EmailBilling = false },
		KindSchedule:        func(r *storegen.UserNotificationSetting) { r.EmailSchedules = false },
		KindBugReport:       func(r *storegen.UserNotificationSetting) { r.EmailBugReports = false },
	}
	for off, switchOff := range switches {
		row := Defaults(uuid.New())
		switchOff(&row)
		for k := range switches {
			if got, want := EmailAllowed(row, k), k != off; got != want {
				t.Errorf("with only %s switched off, EmailAllowed(%s) = %v, want %v", off, k, got, want)
			}
		}
		if !EmailAllowed(row, Kind("something-new")) {
			t.Errorf("with %s switched off, an unknown kind was refused", off)
		}
	}
}

func TestEmailPermittedRequiresVerifiedAddress(t *testing.T) {
	row := Defaults(uuid.New())
	for _, k := range []Kind{KindDependencyAlert, KindQuarantine, KindReviewDecision, KindAdvisory, KindOrgInvite, KindBilling, KindSchedule, KindBugReport, Kind("something-new")} {
		if EmailPermitted(false, row, k) {
			t.Fatalf("an unverified address must get no %s mail, whatever the settings say", k)
		}
		if !EmailPermitted(true, row, k) {
			t.Fatalf("a verified address with default settings must get %s mail", k)
		}
	}
	row.EmailQuarantine = false
	if EmailPermitted(true, row, KindQuarantine) {
		t.Fatal("verified but switched off must still be refused")
	}
}

// The schedules switch governs schedule mail and nothing
// else, and nothing else governs it: billing off leaves it on.
func TestScheduleSwitchIsItsOwn(t *testing.T) {
	row := Defaults(uuid.New())
	row.EmailSchedules = false
	if EmailAllowed(row, KindSchedule) || EmailPermitted(true, row, KindSchedule) {
		t.Fatal("schedules switched off, and schedule mail is still allowed")
	}
	if !EmailAllowed(row, KindBilling) || !EmailAllowed(row, KindDependencyAlert) {
		t.Fatal("schedules off switched another kind off")
	}
	row = Defaults(uuid.New())
	row.EmailBilling = false
	if !EmailAllowed(row, KindSchedule) {
		t.Fatal("billing off switched schedule mail off")
	}
}

// The bug-report switch governs the "Reported bug fixed"
// mail and nothing else, and nothing else governs it.
func TestBugReportSwitchIsItsOwn(t *testing.T) {
	row := Defaults(uuid.New())
	if !EmailAllowed(row, KindBugReport) {
		t.Fatal("bug report mail is off by default; a new class is opt-out")
	}
	row.EmailBugReports = false
	if EmailAllowed(row, KindBugReport) || EmailPermitted(true, row, KindBugReport) {
		t.Fatal("bug reports switched off, and bug report mail is still allowed")
	}
	if !EmailAllowed(row, KindBilling) || !EmailAllowed(row, KindSchedule) {
		t.Fatal("bug reports off switched another kind off")
	}
	row = Defaults(uuid.New())
	row.EmailBilling, row.EmailSchedules = false, false
	if !EmailAllowed(row, KindBugReport) {
		t.Fatal("billing and schedules off switched bug report mail off")
	}
}

// rowFunc is a pgx.Row that fills the destinations itself.
type rowFunc func(dest ...any) error

func (r rowFunc) Scan(dest ...any) error { return r(dest...) }

// memDB answers the two queries AllowsEmail and Settings make, from memory:
// the user row (its address and when it was verified) and the settings row.
type memDB struct {
	storegen.DBTX
	user, settings pgx.Row
}

func (m memDB) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	switch {
	case strings.Contains(sql, "user_notification_settings"):
		return m.settings
	case strings.Contains(sql, "FROM users"):
		return m.user
	}
	return rowFunc(func(...any) error { return errors.New("unexpected query: " + sql) })
}

func userRow(email string, verifiedAt *time.Time) pgx.Row {
	return rowFunc(func(dest ...any) error {
		*dest[1].(*string) = email
		*dest[2].(**time.Time) = verifiedAt
		return nil
	})
}

func failRow(err error) pgx.Row { return rowFunc(func(...any) error { return err }) }

func settingsRow(set storegen.UserNotificationSetting) pgx.Row {
	return rowFunc(func(dest ...any) error {
		*dest[0].(*uuid.UUID) = set.UserID
		for i, v := range map[int]bool{
			1: set.EmailDependencyAlerts, 2: set.EmailQuarantine, 3: set.EmailReviewDecisions,
			4: set.EmailAdvisories, 5: set.EmailOrgInvites, 6: set.WebDependencyAlerts,
			8: set.EmailBilling, 9: set.EmailSchedules, 10: set.EmailBugReports,
		} {
			*dest[i].(*bool) = v
		}
		return nil
	})
}

// AllowsEmail and Settings against an in-memory store, so the decision, the
// two failure directions and the log lines are checked without a database:
// the verified-address gate comes before any preference, an unreadable user
// is no mail, an unreadable or absent settings row is the defaults, and a
// suppression is logged with the user id and the kind and never the address.
func TestAllowsEmailDecisionAndLogsWithoutADatabase(t *testing.T) {
	ctx := t.Context()
	id := uuid.New()
	verified := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	boom := errors.New("store unavailable")
	off := Defaults(id)
	off.EmailQuarantine = false

	for _, c := range []struct {
		name     string
		db       memDB
		kind     Kind
		want     bool
		wantLog  []string // substrings of the one log line; nil means no line
		forbid   []string
		wantNone bool
	}{
		{"user unreadable: no mail, warned with the error", memDB{user: failRow(boom), settings: settingsRow(Defaults(id))}, KindQuarantine, false,
			[]string{"level=WARN", "user row unreadable", "event=mail.suppressed", "user=" + id.String(), "kind=quarantine", "err=\"store unavailable\""}, []string{"@example.test"}, false},
		{"address not verified: no mail, noted without the address", memDB{user: userRow("private@example.test", nil), settings: settingsRow(Defaults(id))}, KindAdvisory, false,
			[]string{"level=INFO", "address not verified", "event=mail.suppressed", "user=" + id.String(), "kind=advisories"}, []string{"private", "@example.test", "email="}, false},
		{"verified, no settings row: the defaults", memDB{user: userRow("a@example.test", &verified), settings: failRow(pgx.ErrNoRows)}, KindQuarantine, true, nil, nil, true},
		{"verified, settings unreadable: still mail, nothing logged", memDB{user: userRow("a@example.test", &verified), settings: failRow(boom)}, KindQuarantine, true, nil, nil, true},
		{"verified, kind switched off: no mail", memDB{user: userRow("a@example.test", &verified), settings: settingsRow(off)}, KindQuarantine, false, nil, nil, true},
		{"verified, another kind switched off: mail", memDB{user: userRow("a@example.test", &verified), settings: settingsRow(off)}, KindAdvisory, true, nil, nil, true},
		{"verified, unknown kind: mail", memDB{user: userRow("a@example.test", &verified), settings: settingsRow(off)}, Kind("something-new"), true, nil, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			logger, logs := logSink()
			if got := AllowsEmail(ctx, storegen.New(c.db), logger, id, c.kind); got != c.want {
				t.Errorf("AllowsEmail = %v, want %v", got, c.want)
			}
			line := logs.String()
			if c.wantNone && line != "" {
				t.Errorf("unexpected log output: %s", line)
			}
			for _, w := range c.wantLog {
				if !strings.Contains(line, w) {
					t.Errorf("log lacks %q: %s", w, line)
				}
			}
			for _, f := range c.forbid {
				if strings.Contains(line, f) {
					t.Errorf("log carries %q: %s", f, line)
				}
			}
		})
	}

	// With no logger of its own, a suppression goes to the process default.
	t.Run("nil logger uses the process default", func(t *testing.T) {
		prev := slog.Default()
		t.Cleanup(func() { slog.SetDefault(prev) })
		logger, logs := logSink()
		slog.SetDefault(logger)
		db := memDB{user: userRow("private@example.test", nil), settings: settingsRow(Defaults(id))}
		if AllowsEmail(ctx, storegen.New(db), nil, id, KindQuarantine) {
			t.Error("an unverified address got mail")
		}
		if !strings.Contains(logs.String(), "address not verified") {
			t.Errorf("the process logger saw %q", logs.String())
		}
	})

	// Settings: no row is the defaults without an error; any other failure is
	// returned with the defaults beside it; a row is returned as stored.
	got, err := Settings(ctx, storegen.New(memDB{settings: failRow(pgx.ErrNoRows)}), id)
	if err != nil || got != Defaults(id) {
		t.Errorf("Settings with no row = %+v, %v; want the defaults and no error", got, err)
	}
	got, err = Settings(ctx, storegen.New(memDB{settings: failRow(boom)}), id)
	if !errors.Is(err, boom) || got != Defaults(id) {
		t.Errorf("Settings with a failing store = %+v, %v; want the defaults and the error", got, err)
	}
	stored := Defaults(id)
	stored.EmailBilling, stored.WebDependencyAlerts = false, false
	got, err = Settings(ctx, storegen.New(memDB{settings: settingsRow(stored)}), id)
	if err != nil || got.EmailBilling || got.WebDependencyAlerts || !got.EmailQuarantine || got.UserID != id {
		t.Errorf("Settings with a stored row = %+v, %v", got, err)
	}
}

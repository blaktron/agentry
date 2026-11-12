package extension

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// TestOrgSSOIsBoundAndAnswersByTheRequirement: an extension that binds on a
// server with a database holds the single sign-on check, which allows every
// caller of an organization that does not require SSO, and of one that does
// only a session its SSO asserted within the window or a token bound to it.
func TestOrgSSOIsBoundAndAnswersByTheRequirement(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	ext := &namedBinder{name: "sso-probe"}
	applyExtensions(srv, []Extension{ext})
	sso := ext.deps.OrgSSO
	if sso == nil {
		t.Fatal("a server with a database handed out no single sign-on check")
	}
	ctx := context.Background()
	id := uuid.New()
	handle := "sso-" + strings.ReplaceAll(id.String(), "-", "")[:20]
	pool := st.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO handles (id, handle, kind) VALUES ($1, $2, 'org')`, id, handle); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, display_name) VALUES ($1, $2)`, id, handle); err != nil {
		t.Fatal(err)
	}
	plain := &Principal{UserID: uuid.New(), Via: "session"}
	fresh := &Principal{UserID: uuid.New(), Via: "session", SSOFresh: map[uuid.UUID]time.Time{id: time.Now()}}
	bound := &Principal{UserID: uuid.New(), Via: "pat", PATOrgID: id}
	unbound := &Principal{UserID: uuid.New(), Via: "pat"}
	for name, c := range map[string]struct {
		p                    *Principal
		without, withRequire bool
	}{
		"a plain session":       {plain, true, false},
		"an SSO-fresh session":  {fresh, true, true},
		"a token bound to it":   {bound, true, true},
		"a token not bound":     {unbound, true, false},
		"a credential-less one": {&Principal{UserID: uuid.New(), Via: "user"}, true, false},
	} {
		if ok, err := sso.Allows(ctx, c.p, id); err != nil || ok != c.without {
			t.Errorf("%s, no requirement: %v, %v", name, ok, err)
		}
		if _, err := pool.Exec(ctx, `UPDATE orgs SET sso_required = true WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if ok, err := sso.Allows(ctx, c.p, id); err != nil || ok != c.withRequire {
			t.Errorf("%s, required: %v, %v", name, ok, err)
		}
		if _, err := pool.Exec(ctx, `UPDATE orgs SET sso_required = false WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := sso.Allows(ctx, plain, uuid.New()); err != nil || !ok {
		t.Errorf("an unknown organization: %v, %v", ok, err)
	}
}

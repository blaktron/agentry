package api_test

// The account door (pkg/extension.Deps.Accounts): platform staff, through
// an extension's console, read a person's account and suspend, reinstate
// and sign it out. Each act checks its actor afresh, revokes what it says
// it revokes and nothing else, is audited with the actor and the reason,
// and mails the person at a confirmed address.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/notify"
)

// accountMails records the account notices and the activation links.
type accountMails struct {
	notify.Notifier
	mu    sync.Mutex
	sent  []notify.AccountNotice
	links []string
	// fail, when set, is what every account notice is refused with.
	fail error
}

func (m *accountMails) AccountChanged(_ context.Context, n notify.AccountNotice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.sent = append(m.sent, n)
	return nil
}

// EmailVerification records the address an activation link went to.
func (m *accountMails) EmailVerification(_ context.Context, toEmail, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links = append(m.links, toEmail)
	return nil
}

// failNotices makes every account notice from now on fail with err (nil
// restores delivery).
func (m *accountMails) failNotices(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = err
}

// activationLinks lists the addresses activation links were mailed to.
func (m *accountMails) activationLinks() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.links...)
}

func (m *accountMails) changes() []notify.AccountNoticeKind {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []notify.AccountNoticeKind
	for _, n := range m.sent {
		out = append(out, n.Change)
	}
	return out
}

// accountsEnv is a test server with its account notices recorded and one
// platform-staff account to act as.
type accountsEnv struct {
	*testEnv
	srv   *api.Server
	mails *accountMails
	staff *auth.Principal
}

func newAccountsEnv(t *testing.T) *accountsEnv {
	t.Helper()
	a := &accountsEnv{mails: &accountMails{Notifier: notify.LogNotifier{}}}
	a.testEnv = newTestEnvWith(t, func(s *api.Server) { a.srv = s; s.SetNotifier(a.mails) })
	h := a.register("ac-staff")
	a.verifyEmail(h)
	a.makePlatformStaff(t, h)
	a.staff = &auth.Principal{UserID: uuid.MustParse(a.selfID(a.login(h))), Via: "session"}
	return a
}

func (a *accountsEnv) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := a.st.Pool().QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (a *accountsEnv) state(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := a.st.Pool().QueryRow(context.Background(), `SELECT state FROM users WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// seedCredentials gives the account a remembered browser and an unused
// desktop sign-in code, which no HTTP door here mints.
func (a *accountsEnv) seedCredentials(t *testing.T, id uuid.UUID) {
	t.Helper()
	a.seedRememberedBrowser(t, id)
	a.seedDesktopCode(t, id)
}

// seedRememberedBrowser gives the account one remembered browser.
func (a *accountsEnv) seedRememberedBrowser(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := a.st.Pool().Exec(context.Background(),
		`INSERT INTO trusted_devices (id, user_id, token_sha256, expires_at) VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), now() + interval '30 days')`, id); err != nil {
		t.Fatal(err)
	}
}

// seedDesktopCode gives the account one unused desktop sign-in code.
func (a *accountsEnv) seedDesktopCode(t *testing.T, id uuid.UUID) {
	t.Helper()
	if _, err := a.st.Pool().Exec(context.Background(),
		`INSERT INTO desktop_grants (id, user_id, code_sha256, state_sha256, scopes, name, expires_at)
		 VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), '\x02', '{agent:read}', 'desktop', now() + interval '60 seconds')`, id); err != nil {
		t.Fatal(err)
	}
}

// TestStaffSuspendRevokesEveryCredentialAndReinstateRestoresNone: a
// suspension revokes the account's sessions, tokens, SSH keys, remembered
// browsers and desktop codes, and every one is refused at once; it is
// audited with the staff member and the reason and the person is told. A
// second suspension changes nothing. Reinstating makes the account active
// and brings none of the revoked credentials back.
func TestStaffSuspendRevokesEveryCredentialAndReinstateRestoresNone(t *testing.T) {
	a := newAccountsEnv(t)
	ctx := context.Background()
	h := a.register("ac-person")
	a.verifyEmail(h)
	sess, other := a.login(h), a.login(h)
	id := uuid.MustParse(a.selfID(sess))
	_, pat := a.mintPAT(sess, "ac-pat", "agent:read")
	a.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "laptop", "publicKey": testPublicKeyLine(t)}, nil, http.StatusCreated)
	a.seedCredentials(t, id)

	got, err := a.srv.SuspendAccount(ctx, "directory", a.staff, id, "spam from this account")
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if !got.Changed || got.Sessions < 2 || got.Tokens != 1 || got.SSHKeys != 1 || got.RememberedBrowsers != 1 || got.DesktopGrants != 1 {
		t.Fatalf("suspend: %+v", got)
	}
	if s := a.state(t, id); s != "suspended" {
		t.Fatalf("state %q, want suspended", s)
	}
	for name, c := range map[string]caller{"a session": sess, "another session": other, "a token": {name: "pat", pat: pat}} {
		if r := a.do(c, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s after the suspension: %d, want 401", name, r.StatusCode)
		}
	}
	for what, n := range map[string]int{
		"live sessions":            a.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, id),
		"live tokens":              a.count(t, `SELECT count(*) FROM pats WHERE user_id = $1 AND revoked_at IS NULL`, id),
		"live SSH keys":            a.count(t, `SELECT count(*) FROM user_ssh_keys WHERE user_id = $1 AND revoked_at IS NULL`, id),
		"live remembered browsers": a.count(t, `SELECT count(*) FROM trusted_devices WHERE user_id = $1 AND revoked_at IS NULL`, id),
		"unused desktop codes":     a.count(t, `SELECT count(*) FROM desktop_grants WHERE user_id = $1 AND consumed_at IS NULL`, id),
	} {
		if n != 0 {
			t.Errorf("%s after the suspension: %d", what, n)
		}
	}
	audited := `SELECT count(*) FROM audit_events WHERE action = $1 AND target_id = $2 AND actor_id = $3 AND actor_kind = 'user'
		AND detail->>'reason' = $4 AND detail->>'extension' = 'directory' AND detail->>'via' = 'extension'`
	if n := a.count(t, audited, "user.suspend", id, a.staff.UserID, "spam from this account"); n != 1 {
		t.Fatalf("user.suspend rows: %d, want 1", n)
	}
	// The row says how many of each credential the act ended.
	revoked := `SELECT count(*) FROM audit_events WHERE action = 'user.suspend' AND target_id = $1
		AND detail->'revoked' = jsonb_build_object('sessions', $2::bigint, 'tokens', 1, 'sshKeys', 1, 'rememberedBrowsers', 1, 'desktopGrants', 1)`
	if n := a.count(t, revoked, id, got.Sessions); n != 1 {
		t.Fatalf("user.suspend rows with the revoked counts (%d sessions, one of each other): %d, want 1", got.Sessions, n)
	}

	again, err := a.srv.SuspendAccount(ctx, "directory", a.staff, id, "again")
	if err != nil || again.Changed {
		t.Fatalf("a second suspension: %+v %v, want no change", again, err)
	}
	if n := a.count(t, `SELECT count(*) FROM audit_events WHERE action = 'user.suspend' AND target_id = $1`, id); n != 1 {
		t.Fatalf("a second suspension was audited: %d rows", n)
	}

	// A token whose creation waited on the suspension's lock commits just
	// after it, unrevoked: written here directly, as that insert would land.
	if _, err := a.st.Pool().Exec(ctx, `INSERT INTO pats (id, user_id, name, token_sha256, token_prefix, scopes, expires_at)
		VALUES (gen_random_uuid(), $1, 'late', decode(md5(random()::text), 'hex'), 'agyp_late', '{agent:read}', now() + interval '1 day')`, id); err != nil {
		t.Fatal(err)
	}

	back, err := a.srv.ReinstateAccount(ctx, "directory", a.staff, id, "appeal upheld")
	if err != nil || !back.Changed {
		t.Fatalf("reinstate: %+v %v", back, err)
	}
	if s := a.state(t, id); s != "active" {
		t.Fatalf("state after reinstating %q, want active", s)
	}
	if back.Tokens != 1 || a.count(t, `SELECT count(*) FROM pats WHERE user_id = $1 AND revoked_at IS NULL`, id) != 0 {
		t.Fatalf("a token minted around the suspension survived the reinstatement: %+v", back)
	}
	if r := a.do(caller{name: "pat", pat: pat}, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the revoked token after reinstating: %d, want 401", r.StatusCode)
	}
	if r := a.do(sess, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the revoked session after reinstating: %d, want 401", r.StatusCode)
	}
	if n := a.count(t, audited, "user.reinstate", id, a.staff.UserID, "appeal upheld"); n != 1 {
		t.Fatalf("user.reinstate rows: %d, want 1", n)
	}
	if again, err := a.srv.ReinstateAccount(ctx, "directory", a.staff, id, "again"); err != nil || again.Changed {
		t.Fatalf("reinstating an active account: %+v %v, want no change", again, err)
	}
	if c := a.mails.changes(); len(c) != 2 || c[0] != notify.AccountSuspended || c[1] != notify.AccountReinstated {
		t.Fatalf("mails %v, want suspended then reinstated", c)
	}

	// The counts are told apart: an account holding three sessions, two
	// tokens, four SSH keys, five remembered browsers and six desktop codes
	// has each reported as its own number, on the result and on the record.
	multi := a.register("ac-multi")
	a.verifyEmail(multi)
	multiSess := a.login(multi)
	multiID := uuid.MustParse(a.selfID(multiSess))
	a.login(multi)
	a.login(multi)
	for i := range 2 {
		a.mintPAT(multiSess, fmt.Sprintf("ac-multi-pat-%d", i), "agent:read")
	}
	for range 4 {
		a.doJSON(multiSess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "k", "publicKey": testPublicKeyLine(t)}, nil, http.StatusCreated)
	}
	for range 5 {
		a.seedRememberedBrowser(t, multiID)
	}
	for range 6 {
		a.seedDesktopCode(t, multiID)
	}
	counted, err := a.srv.SuspendAccount(ctx, "directory", a.staff, multiID, "counts")
	if want := (api.AccountChange{Changed: true, Sessions: 3, Tokens: 2, SSHKeys: 4, RememberedBrowsers: 5, DesktopGrants: 6}); err != nil || counted != want {
		t.Fatalf("suspending an account holding one more of each kind: %+v %v, want %+v", counted, err, want)
	}
	if n := a.count(t, `SELECT count(*) FROM audit_events WHERE action = 'user.suspend' AND target_id = $1
		AND detail->'revoked' = '{"sessions": 3, "tokens": 2, "sshKeys": 4, "rememberedBrowsers": 5, "desktopGrants": 6}'::jsonb`, multiID); n != 1 {
		t.Fatalf("user.suspend rows with the five counts: %d, want 1", n)
	}

	// A suspended account is refused at every door by its state alone: a
	// session and a token that no revocation ever touched.
	held := a.register("ac-state")
	a.verifyEmail(held)
	heldSess := a.login(held)
	_, heldPAT := a.mintPAT(heldSess, "ac-state-pat", "user:profile")
	for name, c := range map[string]caller{"a session": heldSess, "a token": {name: "pat", pat: heldPAT}} {
		if r := a.do(c, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusOK {
			t.Fatalf("%s before the suspension: %d, want 200", name, r.StatusCode)
		}
	}
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET state = 'suspended' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, held); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]caller{"a session": heldSess, "a token": {name: "pat", pat: heldPAT}} {
		if r := a.do(c, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s of a suspended account: %d, want 401", name, r.StatusCode)
		}
	}
}

// TestStaffSignOutKeepsTokensAndKeys: signing out everywhere ends the
// sessions and forgets the remembered browsers and desktop codes; the
// account's tokens and SSH keys keep working, and with nothing left to end
// a second sign-out changes nothing.
func TestStaffSignOutKeepsTokensAndKeys(t *testing.T) {
	a := newAccountsEnv(t)
	ctx := context.Background()
	h := a.register("ac-out")
	a.verifyEmail(h)
	sess := a.login(h)
	id := uuid.MustParse(a.selfID(sess))
	_, pat := a.mintPAT(sess, "ac-out-pat", "user:profile")
	a.doJSON(sess, http.MethodPost, "/api/v1/user/ssh-keys", map[string]any{"title": "laptop", "publicKey": testPublicKeyLine(t)}, nil, http.StatusCreated)
	a.seedCredentials(t, id)

	got, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, "lost laptop")
	if err != nil || !got.Changed || got.Sessions != 1 || got.RememberedBrowsers != 1 || got.DesktopGrants != 1 || got.Tokens != 0 || got.SSHKeys != 0 {
		t.Fatalf("sign out: %+v %v", got, err)
	}
	if r := a.do(sess, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the session after signing out: %d, want 401", r.StatusCode)
	}
	if r := a.do(caller{name: "pat", pat: pat}, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("the token after signing out: %d, want 200", r.StatusCode)
	}
	if n := a.count(t, `SELECT count(*) FROM user_ssh_keys WHERE user_id = $1 AND revoked_at IS NULL`, id); n != 1 {
		t.Fatalf("live SSH keys after signing out: %d, want 1", n)
	}
	if s := a.state(t, id); s != "active" {
		t.Fatalf("state after signing out %q, want active", s)
	}
	if n := a.count(t, `SELECT count(*) FROM audit_events WHERE action = 'user.sign_out_everywhere' AND target_id = $1 AND detail->>'reason' = 'lost laptop'`, id); n != 1 {
		t.Fatalf("user.sign_out_everywhere rows: %d, want 1", n)
	}
	if again, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, "again"); err != nil || again.Changed {
		t.Fatalf("a second sign-out: %+v %v, want no change", again, err)
	}
	// Each thing a sign-out can end is a change by itself: a remembered
	// browser, an unused desktop code and a session.
	a.seedRememberedBrowser(t, id)
	if only, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, "browser"); err != nil || !only.Changed || only.RememberedBrowsers != 1 || only.Sessions != 0 || only.DesktopGrants != 0 {
		t.Fatalf("a sign-out ending only a remembered browser: %+v %v", only, err)
	}
	a.seedDesktopCode(t, id)
	if only, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, "desktop code"); err != nil || !only.Changed || only.DesktopGrants != 1 || only.Sessions != 0 || only.RememberedBrowsers != 0 {
		t.Fatalf("a sign-out ending only a desktop code: %+v %v", only, err)
	}
	next := a.login(h)
	if only, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, "session"); err != nil || !only.Changed || only.Sessions != 1 || only.DesktopGrants != 0 || only.RememberedBrowsers != 0 {
		t.Fatalf("a sign-out ending only a session: %+v %v", only, err)
	}
	if r := a.do(next, http.MethodGet, "/api/v1/user", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the session after its sign-out: %d, want 401", r.StatusCode)
	}
	// A notice that cannot be delivered does not undo the act.
	a.login(h)
	a.mails.failNotices(errors.New("mail relay down"))
	failed, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, "relay down")
	a.mails.failNotices(nil)
	if err != nil || !failed.Changed || failed.Sessions != 1 {
		t.Fatalf("a sign-out whose notice failed: %+v %v, want the act made", failed, err)
	}
	c := a.mails.changes()
	if len(c) != 4 {
		t.Fatalf("mails %v, want a signed-out for each of the four acts that were told", c)
	}
	for i, k := range c {
		if k != notify.AccountSignedOut {
			t.Errorf("mail %d is %q, want signed-out", i, k)
		}
	}
}

// TestTheAccountDoorChecksItsActor: whatever the extension checked, the
// door refuses anyone but an active platform-staff account, its own
// account, a change made with a token, a change without a reason, an
// account that is not there and one that is erased. A token may read.
func TestTheAccountDoorChecksItsActor(t *testing.T) {
	a := newAccountsEnv(t)
	ctx := context.Background()
	h := a.register("ac-target")
	a.verifyEmail(h)
	id := uuid.MustParse(a.selfID(a.login(h)))

	plain := a.register("ac-plain")
	a.verifyEmail(plain)
	plainID := uuid.MustParse(a.selfID(a.login(plain)))
	gone := a.register("ac-gone-staff")
	a.verifyEmail(gone)
	a.makePlatformStaff(t, gone)
	goneID := uuid.MustParse(a.selfID(a.login(gone)))
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET state = 'suspended' WHERE id = $1`, goneID); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name  string
		actor *auth.Principal
		user  uuid.UUID
		want  error
	}{
		{"no actor", nil, id, api.ErrActorNotStaff},
		{"anonymous", &auth.Principal{Anonymous: true}, id, api.ErrActorNotStaff},
		{"a principal with no credential", &auth.Principal{UserID: a.staff.UserID, Via: "user", PlatformStaff: true}, id, api.ErrActorNotStaff},
		{"a staff token", &auth.Principal{UserID: a.staff.UserID, Via: "pat"}, id, api.ErrActorSession},
		{"someone who is not staff, whatever the principal says", &auth.Principal{UserID: plainID, Via: "session", PlatformStaff: true}, id, api.ErrActorNotStaff},
		{"a suspended staff account", &auth.Principal{UserID: goneID, Via: "session"}, id, api.ErrActorNotStaff},
		{"staff on their own account", a.staff, a.staff.UserID, api.ErrSelfAct},
		{"staff on their own account, under another principal", &auth.Principal{UserID: a.staff.UserID, Via: "session"}, a.staff.UserID, api.ErrSelfAct},
		{"an account that is not there", a.staff, uuid.New(), api.ErrNoAccount},
		{"an anonymous principal that carries a staff id", &auth.Principal{Anonymous: true, UserID: a.staff.UserID, Via: "session"}, id, api.ErrActorNotStaff},
		{"an actor that is not there", &auth.Principal{UserID: uuid.New(), Via: "session"}, id, api.ErrActorNotStaff},
	} {
		if _, err := a.srv.SuspendAccount(ctx, "directory", c.actor, c.user, "why"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if s := a.state(t, id); s != "active" {
		t.Fatalf("a refused act moved the account to %q", s)
	}
	if _, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, "   "); err == nil {
		t.Fatal("an act without a reason was accepted")
	}
	long := make([]rune, 501)
	for i := range long {
		long[i] = 'é'
	}
	if _, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, string(long)); !errors.Is(err, api.ErrReasonLength) {
		t.Fatalf("a 501-character reason: %v, want ErrReasonLength", err)
	}
	if _, err := a.srv.SignOutAccount(ctx, "directory", a.staff, id, string(long[:500])); err != nil {
		t.Fatalf("a 500-character reason: %v", err)
	}
	if _, err := a.srv.AccountFacts(ctx, a.staff, a.staff.UserID); err != nil {
		t.Fatalf("staff reading their own account: %v", err)
	}
	if _, err := a.srv.AccountFacts(ctx, &auth.Principal{UserID: a.staff.UserID, Via: "pat"}, id); err != nil {
		t.Fatalf("a staff token reading: %v", err)
	}
	if _, err := a.srv.AccountFacts(ctx, &auth.Principal{UserID: plainID, Via: "session"}, id); !errors.Is(err, api.ErrActorNotStaff) {
		t.Fatalf("someone who is not staff reading: %v", err)
	}
	if _, err := a.srv.AccountFacts(ctx, &auth.Principal{UserID: a.staff.UserID, Via: "user", PlatformStaff: true}, id); !errors.Is(err, api.ErrActorNotStaff) {
		t.Fatalf("a principal with no credential reading: %v, want ErrActorNotStaff", err)
	}
	if _, err := a.srv.AccountFacts(ctx, a.staff, uuid.New()); !errors.Is(err, api.ErrNoAccount) {
		t.Fatalf("reading an account that is not there: %v, want ErrNoAccount", err)
	}
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET state = 'deleted' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.ReinstateAccount(ctx, "directory", a.staff, id, "why"); !errors.Is(err, api.ErrAccountErased) {
		t.Fatalf("reinstating an erased account: %v, want ErrAccountErased", err)
	}
	if _, err := a.srv.SuspendAccount(ctx, "directory", a.staff, id, "why"); !errors.Is(err, api.ErrAccountErased) {
		t.Fatalf("suspending an erased account: %v, want ErrAccountErased", err)
	}
	if s := a.state(t, id); s != "deleted" {
		t.Fatalf("an erased account was moved to %q", s)
	}
	if n := a.count(t, `SELECT count(*) FROM audit_events WHERE action IN ('user.suspend','user.reinstate') AND target_id = $1`, id); n != 0 {
		t.Fatalf("refused acts were audited: %d rows", n)
	}
	if c := a.mails.changes(); len(c) != 1 || c[0] != notify.AccountSignedOut {
		t.Fatalf("mails %v, want only the accepted sign-out's", c)
	}
}

// TestNoAccountMailToAnUnconfirmedAddress: an act on an account whose
// address is not confirmed is made and audited, and mails nobody, since
// the address may be somebody else's.
func TestNoAccountMailToAnUnconfirmedAddress(t *testing.T) {
	a := newAccountsEnv(t)
	h := a.register("ac-unconfirmed")
	id := uuid.MustParse(a.selfID(a.login(h)))
	if _, err := a.st.Pool().Exec(context.Background(), `UPDATE users SET email_verified_at = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if got, err := a.srv.SuspendAccount(context.Background(), "directory", a.staff, id, "test"); err != nil || !got.Changed {
		t.Fatalf("suspend: %+v %v", got, err)
	}
	if c := a.mails.changes(); len(c) != 0 {
		t.Fatalf("mailed an unconfirmed address: %v", c)
	}

	// A confirmed address that is the registry's own placeholder is no
	// address either.
	ph := a.register("ac-placeholder")
	a.verifyEmail(ph)
	phID := uuid.MustParse(a.selfID(a.login(ph)))
	if _, err := a.st.Pool().Exec(context.Background(), `UPDATE users SET email = $2 WHERE id = $1`, phID, ph+"@oidc"+auth.SyntheticAddressSuffix); err != nil {
		t.Fatal(err)
	}
	if got, err := a.srv.SuspendAccount(context.Background(), "directory", a.staff, phID, "test"); err != nil || !got.Changed {
		t.Fatalf("suspend: %+v %v", got, err)
	}
	if c := a.mails.changes(); len(c) != 0 {
		t.Fatalf("mailed a placeholder address: %v", c)
	}
}

// TestAccountFactsReadsWhatTheAccountHolds: its state and standing, its
// memberships, its sessions by client and its tokens by name and scope.
func TestAccountFactsReadsWhatTheAccountHolds(t *testing.T) {
	a := newAccountsEnv(t)
	h := a.register("ac-facts")
	a.verifyEmail(h)
	sess := a.login(h)
	id := uuid.MustParse(a.selfID(sess))
	a.mintPAT(sess, "ac-facts-pat", "agent:read")
	org := "ac-org" + a.sfxDigits()
	orgID := a.createOrg(sess, org)

	f, err := a.srv.AccountFacts(context.Background(), a.staff, id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Handle != h || f.State != "active" || !f.EmailVerified || f.PlatformStaff || f.CreatedAt.IsZero() {
		t.Fatalf("standing: %+v", f)
	}
	if len(f.Orgs) != 1 || f.Orgs[0].Handle != org || f.Orgs[0].Role != "admin" || f.Orgs[0].State != "active" {
		t.Fatalf("orgs: %+v", f.Orgs)
	}
	if len(f.Sessions) < 1 || f.Sessions[0].LastSeenAt.IsZero() {
		t.Fatalf("sessions: %+v", f.Sessions)
	}
	if f.Sessions[0].CreatedAt.IsZero() || f.Sessions[0].Client != "Go-http-client/1.1" {
		t.Fatalf("a session is listed by when it began and the client that signed in: %+v", f.Sessions[0])
	}
	if len(f.Tokens) != 1 || f.Tokens[0].Name != "ac-facts-pat" || len(f.Tokens[0].Scopes) != 1 || f.Tokens[0].Scopes[0] != "agent:read" {
		t.Fatalf("tokens: %+v", f.Tokens)
	}
	if tok := f.Tokens[0]; tok.CreatedAt.IsZero() || !tok.ExpiresAt.After(time.Now()) || tok.Org != "" || tok.LastUsedAt != nil {
		t.Fatalf("a token never used and bound to no organization: %+v", tok)
	}

	// A token bound to the organization says which, and one that was used
	// says when.
	a.insertPAT(id.String(), orgID, "org:admin")
	if _, err := a.st.Pool().Exec(context.Background(), `UPDATE pats SET last_used_at = now() WHERE user_id = $1 AND org_id IS NOT NULL`, id); err != nil {
		t.Fatal(err)
	}
	f, err = a.srv.AccountFacts(context.Background(), a.staff, id)
	if err != nil {
		t.Fatal(err)
	}
	var bound *api.AccountToken
	for i := range f.Tokens {
		if f.Tokens[i].Org == org {
			bound = &f.Tokens[i]
		}
	}
	if len(f.Tokens) != 2 || bound == nil || bound.LastUsedAt == nil || bound.Scopes[0] != "org:admin" || !bound.ExpiresAt.After(time.Now()) {
		t.Fatalf("tokens with an organization-bound one: %+v", f.Tokens)
	}

	// Standing differs by account: staff are staff, and an address nobody
	// confirmed is not verified.
	own, err := a.srv.AccountFacts(context.Background(), a.staff, a.staff.UserID)
	if err != nil || !own.PlatformStaff || !own.EmailVerified {
		t.Fatalf("a staff account's own facts: %+v %v, want platform staff with a verified address", own, err)
	}
	unconfirmed := a.registerUnverified("ac-facts-un")
	other, err := a.srv.AccountFacts(context.Background(), a.staff, uuid.MustParse(a.selfID(a.login(unconfirmed))))
	if err != nil || other.EmailVerified || other.PlatformStaff {
		t.Fatalf("an unconfirmed account's facts: %+v %v", other, err)
	}
}

// TestSuspendingStaffEndsTheirStaff: a suspended account is not platform
// staff, whatever its membership of the staff organization, and
// reinstating it makes it staff again by the same rule.
func TestSuspendingStaffEndsTheirStaff(t *testing.T) {
	f := newStaffFixture(t)
	ctx := context.Background()
	member := f.person("ac-member")
	f.join(member, "ac-member-"+f.env.sfx+"@"+f.domain)
	f.signIn(member)
	if !f.staff(member) {
		t.Fatal("a member of the staff organization is not staff")
	}
	// A seat that is pending, not yet approved, makes nobody staff.
	pending := f.person("ac-pending")
	f.env.seedMembership(f.org, pending, "member", "pending")
	f.signIn(pending)
	if f.staff(pending) {
		t.Fatal("a pending member of the staff organization is staff")
	}
	var id, founder uuid.UUID
	for h, dst := range map[string]*uuid.UUID{member: &id, f.founded: &founder} {
		if err := f.env.st.Pool().QueryRow(ctx, `SELECT id FROM handles WHERE handle = $1`, h).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	actor := &auth.Principal{UserID: founder, Via: "session"}
	if _, err := f.srv.SuspendAccount(ctx, "directory", actor, id, "test"); err != nil {
		t.Fatal(err)
	}
	if f.staff(member) {
		t.Fatal("a suspended account is still staff")
	}
	if _, err := f.srv.ReinstateAccount(ctx, "directory", actor, id, "test"); err != nil {
		t.Fatal(err)
	}
	if !f.staff(member) {
		t.Fatal("a reinstated member of the staff organization is not staff again")
	}

	// Each recomputation is on the record, naming the rule and the reason.
	for _, c := range []struct {
		reason string
		staff  bool
	}{{"account-state", false}, {"account-state", true}} {
		var rows int
		if err := f.env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'user.staff_sync' AND target_id = $1
			AND detail->>'reason' = $2 AND detail->>'rule' = 'staff-org' AND (detail->>'platformStaff')::boolean = $3 AND detail->>'org' = $4`,
			id, c.reason, c.staff, f.org).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 1 {
			t.Fatalf("user.staff_sync rows for platformStaff=%v by %s: %d, want 1", c.staff, c.reason, rows)
		}
	}

	// An erased account is not staff either, whatever it was.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/x/directory/staff/accounts/1/erase", nil)
	if _, err := f.srv.EraseAccount(r, "directory", actor, id, "test"); err != nil {
		t.Fatal(err)
	}
	var staff bool
	if err := f.env.st.Pool().QueryRow(ctx, `SELECT platform_staff FROM users WHERE id = $1`, id).Scan(&staff); err != nil {
		t.Fatal(err)
	}
	if staff {
		t.Fatal("an erased member of the staff organization is still staff")
	}
}

// TestTellingOfRemovedSecondFactors: the notice that staff removed second
// factors goes to the person's confirmed address and changes nothing in
// the registry. It is refused to anyone but a staff member's session acting
// on someone else, and for no factor at all; an unconfirmed address is
// told nothing.
func TestTellingOfRemovedSecondFactors(t *testing.T) {
	a := newAccountsEnv(t)
	ctx := context.Background()
	h := a.register("ac-factors")
	a.verifyEmail(h)
	sess := a.login(h)
	id := uuid.MustParse(a.selfID(sess))

	sent, err := a.srv.TellSecondFactorsRemoved(ctx, a.staff, id, 2)
	if err != nil || !sent {
		t.Fatalf("telling: sent %v, %v", sent, err)
	}
	a.mails.mu.Lock()
	got := a.mails.sent
	a.mails.mu.Unlock()
	if len(got) != 1 || got[0].Change != notify.AccountSecondFactorsRemoved || got[0].Removed != 2 || got[0].Handle != h {
		t.Fatalf("mails %+v", got)
	}
	if s := a.state(t, id); s != "active" {
		t.Fatalf("the notice moved the account to %q", s)
	}
	a.doJSON(sess, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)

	for _, c := range []struct {
		name    string
		actor   *auth.Principal
		user    uuid.UUID
		removed int
		want    error
	}{
		{"a staff token", &auth.Principal{UserID: a.staff.UserID, Via: "pat"}, id, 1, api.ErrActorSession},
		{"someone who is not staff", &auth.Principal{UserID: id, Via: "session", PlatformStaff: true}, a.staff.UserID, 1, api.ErrActorNotStaff},
		{"staff on their own account", a.staff, a.staff.UserID, 1, api.ErrSelfAct},
		{"an account that is not there", a.staff, uuid.New(), 1, api.ErrNoAccount},
		{"no factor removed", a.staff, id, 0, nil},
	} {
		sent, err := a.srv.TellSecondFactorsRemoved(ctx, c.actor, c.user, c.removed)
		if sent || err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: sent %v, %v, want %v", c.name, sent, err, c.want)
		}
	}

	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET email_verified_at = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if sent, err := a.srv.TellSecondFactorsRemoved(ctx, a.staff, id, 1); err != nil || sent {
		t.Fatalf("an unconfirmed address: sent %v, %v", sent, err)
	}

	// An erased account is refused, a confirmed placeholder is told
	// nothing, and a notice that cannot be handed over is an error, not a
	// sent notice.
	gone := a.register("ac-factors-gone")
	a.verifyEmail(gone)
	goneID := uuid.MustParse(a.selfID(a.login(gone)))
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET state = 'deleted' WHERE id = $1`, goneID); err != nil {
		t.Fatal(err)
	}
	if sent, err := a.srv.TellSecondFactorsRemoved(ctx, a.staff, goneID, 1); sent || !errors.Is(err, api.ErrAccountErased) {
		t.Fatalf("an erased account: sent %v, %v, want ErrAccountErased", sent, err)
	}
	holder := a.register("ac-factors-ph")
	a.verifyEmail(holder)
	holderID := uuid.MustParse(a.selfID(a.login(holder)))
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, holderID, holder+"@oidc"+auth.SyntheticAddressSuffix); err != nil {
		t.Fatal(err)
	}
	if sent, err := a.srv.TellSecondFactorsRemoved(ctx, a.staff, holderID, 1); err != nil || sent {
		t.Fatalf("a placeholder address: sent %v, %v", sent, err)
	}
	reachable := a.register("ac-factors-down")
	a.verifyEmail(reachable)
	reachableID := uuid.MustParse(a.selfID(a.login(reachable)))
	a.mails.failNotices(errors.New("mail relay down"))
	sent, err = a.srv.TellSecondFactorsRemoved(ctx, a.staff, reachableID, 1)
	a.mails.failNotices(nil)
	if sent || err == nil {
		t.Fatalf("a notice the notifier refused: sent %v, %v, want an error", sent, err)
	}
	if c := a.mails.changes(); len(c) != 1 {
		t.Fatalf("mails %v, want only the first notice", c)
	}
}

// TestStaffEraseIsThePersonsOwnErasure: staff erasing an account is the
// person's own erasure: credentials dead, the row pseudonymized and its
// handle retired, published versions yanked with their digests kept, the
// knowledge pack gone. Every row names the staff member and the reason,
// and the person is mailed before their address goes. An erased account
// cannot be erased again.
func TestStaffEraseIsThePersonsOwnErasure(t *testing.T) {
	a := newAccountsEnv(t)
	ctx := context.Background()
	h := a.register("ac-erase")
	a.verifyEmail(h)
	sess := a.login(h)
	id := uuid.MustParse(a.selfID(sess))
	agent := "erasable-" + a.sfx
	a.publishUnder(t, sess, h, agent)
	_, pat := a.mintPAT(sess, "ac-erase-pat", "agent:read")
	kn := seedKnowledge(t, a.testEnv, knowledge.User(id))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/x/directory/staff/accounts/1/erase", nil)
	// What else the account holds: a remembered browser, an unused desktop
	// code, an activation link, a report design, a Writing Voice and a seat
	// in an organization that has another admin.
	a.seedCredentials(t, id)
	for _, q := range []string{
		`INSERT INTO email_verifications (token_sha256, user_id, expires_at) VALUES (decode(md5(random()::text), 'hex'), $1, now() + interval '1 day')`,
		`INSERT INTO user_report_settings (user_id, design) VALUES ($1, '{}')`,
		`INSERT INTO voices (user_id, wrapper_kind, wrapper_recipient, wrapped_key) VALUES ($1, 'test', 'test', '\x00')`,
	} {
		if _, err := a.st.Pool().Exec(ctx, q, id); err != nil {
			t.Fatal(err)
		}
	}
	founderH := a.register("ac-erase-founder")
	a.verifyEmail(founderH)
	org := "ac-erase-seat" + a.sfxDigits()
	a.createOrg(a.login(founderH), org)
	a.joinOrg(a.login(founderH), org, h)

	got, err := a.srv.EraseAccount(r, "directory", a.staff, id, "asked by mail")
	if err != nil {
		t.Fatal(err)
	}
	if got.PublishedVersions != 1 || !got.Notified {
		t.Fatalf("erasure: %+v", got)
	}
	for _, c := range []caller{sess, {name: "pat", pat: pat}} {
		res := a.do(c, http.MethodGet, "/api/v1/user", nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s after the erasure: %d, want 401", c.name, res.StatusCode)
		}
	}
	assertKnowledgeGone(t, a.testEnv, kn)
	var state, email, handle string
	if err := a.st.Pool().QueryRow(ctx, `SELECT u.state, u.email::text, hd.handle FROM users u JOIN handles hd ON hd.id = u.id WHERE u.id = $1`, id).Scan(&state, &email, &handle); err != nil {
		t.Fatal(err)
	}
	if state != "deleted" || email != "deleted+"+id.String()+"@invalid.invalid" || handle != "del-"+strings.ReplaceAll(id.String(), "-", "") {
		t.Fatalf("the account row: %s %s %s", state, email, handle)
	}
	var tombReason string
	if err := a.st.Pool().QueryRow(ctx, `SELECT deleted_tombstone->>'reason' FROM users WHERE id = $1`, id).Scan(&tombReason); err != nil || tombReason != "erased by platform staff" {
		t.Fatalf("the tombstone's reason: %q (%v), want the staff erasure's", tombReason, err)
	}
	for what, q := range map[string]string{
		"remembered browsers":  `SELECT count(*) FROM trusted_devices WHERE user_id = $1`,
		"unused desktop codes": `SELECT count(*) FROM desktop_grants WHERE user_id = $1 AND consumed_at IS NULL`,
		"activation links":     `SELECT count(*) FROM email_verifications WHERE user_id = $1`,
		"report designs":       `SELECT count(*) FROM user_report_settings WHERE user_id = $1`,
		"Writing Voices":       `SELECT count(*) FROM voices WHERE user_id = $1`,
		"seats":                `SELECT count(*) FROM memberships WHERE user_id = $1`,
		"live sessions":        `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`,
		"live tokens":          `SELECT count(*) FROM pats WHERE user_id = $1 AND revoked_at IS NULL`,
	} {
		if n := a.count(t, q, id); n != 0 {
			t.Errorf("%d %s left after the erasure", n, what)
		}
	}
	var status, digest string
	if err := a.st.Pool().QueryRow(ctx, `SELECT av.status, coalesce(av.archive_digest, '') FROM agent_versions av JOIN agents ag ON ag.id = av.agent_id WHERE ag.name = $1`, agent).Scan(&status, &digest); err != nil {
		t.Fatal(err)
	}
	if status != "yanked" || digest == "" {
		t.Fatalf("the published version: %s, digest %q", status, digest)
	}
	if n := a.count(t, `SELECT count(*) FROM audit_events WHERE action = 'user.delete' AND target_id = $1 AND actor_id = $2
		AND detail->>'reason' = 'asked by mail' AND detail->>'via' = 'extension' AND detail->>'extension' = 'directory' AND detail->>'publishedContent' = 'yank'
		AND detail->>'publishedVersions' = '1' AND detail->>'desktopCodes' = '1' AND (detail->>'knowledgeObjects')::int >= 1`, id, a.staff.UserID); n != 1 {
		t.Fatalf("user.delete rows naming the staff member and the reason: %d", n)
	}
	if n := a.count(t, `SELECT count(*) FROM audit_events WHERE action = 'version.transition' AND detail->>'to' = 'yanked' AND actor_id = $1`, a.staff.UserID); n != 1 {
		t.Fatalf("the yank's rows naming the staff member: %d", n)
	}
	a.mails.mu.Lock()
	sent := append([]notify.AccountNotice(nil), a.mails.sent...)
	a.mails.mu.Unlock()
	if len(sent) != 1 || sent[0].Change != notify.AccountErased || sent[0].ToEmail != h+"@example.test" || sent[0].Handle != h {
		t.Fatalf("mails %+v", sent)
	}
	if _, err := a.srv.EraseAccount(r, "directory", a.staff, id, "again"); !errors.Is(err, api.ErrAccountErased) {
		t.Fatalf("erasing an erased account: %v, want ErrAccountErased", err)
	}

	// Who is not told: an address nobody confirmed, a confirmed placeholder,
	// and a person whose notice cannot be handed over (erased all the same).
	unconfirmed := a.registerUnverified("ac-erase-uc")
	placeholder := a.register("ac-erase-ph")
	a.verifyEmail(placeholder)
	phID := uuid.MustParse(a.selfID(a.login(placeholder)))
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, phID, placeholder+"@oidc"+auth.SyntheticAddressSuffix); err != nil {
		t.Fatal(err)
	}
	down := a.register("ac-erase-down")
	a.verifyEmail(down)
	downID := uuid.MustParse(a.selfID(a.login(down)))
	for _, c := range []struct {
		name string
		id   uuid.UUID
		fail error
	}{
		{"an unconfirmed address", uuid.MustParse(a.selfID(a.login(unconfirmed))), nil},
		{"a placeholder address", phID, nil},
		{"a notice that fails", downID, errors.New("mail relay down")},
	} {
		a.mails.failNotices(c.fail)
		got, err := a.srv.EraseAccount(r, "directory", a.staff, c.id, "tidy")
		a.mails.failNotices(nil)
		if err != nil || got.Notified {
			t.Errorf("%s: %+v %v, want an erasure that told nobody", c.name, got, err)
		}
		if st := a.state(t, c.id); st != "deleted" {
			t.Errorf("%s: the account is %q, want deleted", c.name, st)
		}
	}
	a.mails.mu.Lock()
	told := len(a.mails.sent)
	a.mails.mu.Unlock()
	if told != 1 {
		t.Fatalf("%d notices after the erasures, want only the first person's", told)
	}
}

// TestStaffEraseRefusals: one's own account, a token, someone who is not
// staff, an organization's last admin and a missing reason are refused,
// and the account is left as it was.
func TestStaffEraseRefusals(t *testing.T) {
	a := newAccountsEnv(t)
	h := a.register("ac-erase-no")
	a.verifyEmail(h)
	sess := a.login(h)
	id := uuid.MustParse(a.selfID(sess))
	org := "ac-erase-org" + a.sfxDigits()
	a.createOrg(sess, org)
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	for _, c := range []struct {
		name  string
		actor *auth.Principal
		user  uuid.UUID
		want  error
	}{
		{"staff on their own account", a.staff, a.staff.UserID, api.ErrSelfAct},
		{"a staff token", &auth.Principal{UserID: a.staff.UserID, Via: "pat"}, id, api.ErrActorSession},
		{"someone who is not staff", &auth.Principal{UserID: id, Via: "session", PlatformStaff: true}, a.staff.UserID, api.ErrActorNotStaff},
		{"an organization's last admin", a.staff, id, api.ErrLastAdmin},
	} {
		if _, err := a.srv.EraseAccount(r, "directory", c.actor, c.user, "why"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	var last api.LastAdminError
	if _, err := a.srv.EraseAccount(r, "directory", a.staff, id, "why"); !errors.As(err, &last) || last.Org != org {
		t.Fatalf("the last admin's organization: %v", err)
	}
	if _, err := a.srv.EraseAccount(r, "directory", a.staff, id, "  "); err == nil {
		t.Fatal("an erasure without a reason was accepted")
	}
	// A reason is needed on an account that is otherwise erasable.
	plain := a.register("ac-erase-blank")
	a.verifyEmail(plain)
	plainID := uuid.MustParse(a.selfID(a.login(plain)))
	if _, err := a.srv.EraseAccount(r, "directory", a.staff, plainID, " \t "); err == nil || !strings.Contains(err.Error(), "needs a reason") {
		t.Fatalf("an erasure without a reason: %v, want the refusal that a reason is needed", err)
	}
	if s := a.state(t, plainID); s != "active" {
		t.Fatalf("an erasure without a reason moved the account to %q", s)
	}
	if _, err := a.srv.EraseAccount(r, "directory", a.staff, id, strings.Repeat("\u00e9", 501)); !errors.Is(err, api.ErrReasonLength) {
		t.Fatalf("an erasure with a 501-character reason: %v, want ErrReasonLength", err)
	}
	if s := a.state(t, id); s != "active" {
		t.Fatalf("a refused erasure moved the account to %q", s)
	}
	if c := a.mails.changes(); len(c) != 0 {
		t.Fatalf("a refused erasure mailed %v", c)
	}
}

// TestStaffResendActivation: an unactivated account gets a new link, under
// the person's own interval, audited with the staff member and the
// reason; an activated account and a suspended one are refused.
func TestStaffResendActivation(t *testing.T) {
	a := newAccountsEnv(t)
	ctx := context.Background()
	h := a.registerUnverified("ac-resend")
	id := uuid.MustParse(a.selfID(a.login(h)))
	if _, err := a.st.Pool().Exec(ctx, `DELETE FROM email_verifications WHERE user_id = $1`, id); err != nil {
		t.Fatal(err)
	}

	after, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, "lost the first mail")
	if err != nil {
		t.Fatal(err)
	}
	if !after.After(time.Now()) {
		t.Fatalf("resend after %v, want a time ahead", after)
	}
	if n := a.count(t, `SELECT count(*) FROM email_verifications WHERE user_id = $1`, id); n != 1 {
		t.Fatalf("activation links: %d, want 1", n)
	}
	if n := a.count(t, `SELECT count(*) FROM audit_events WHERE action = 'user.activation_resend' AND target_id = $1 AND actor_id = $2
		AND detail->>'reason' = 'lost the first mail' AND detail->>'extension' = 'directory' AND detail->>'via' = 'extension'`, id, a.staff.UserID); n != 1 {
		t.Fatalf("user.activation_resend rows: %d", n)
	}
	if links := a.mails.activationLinks(); len(links) != 1 || links[0] != h+"@example.test" {
		t.Fatalf("activation links mailed to %v, want the person's address once", links)
	}
	var soon api.ActivationTooSoonError
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, "again"); !errors.As(err, &soon) || !soon.After.After(time.Now()) {
		t.Fatalf("a second link at once: %v, want ActivationTooSoonError", err)
	}
	if links := a.mails.activationLinks(); len(links) != 1 {
		t.Fatalf("a refused link was mailed: %v", links)
	}
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, a.staff.UserID, "mine"); !errors.Is(err, api.ErrSelfAct) {
		t.Fatalf("one's own account: %v", err)
	}

	// The person's own limits: ten links a day on top of the interval. Nine
	// in the day let another go; with ten the answer names when the oldest
	// of them leaves the day.
	if _, err := a.st.Pool().Exec(ctx, `UPDATE email_verifications SET created_at = now() - interval '1 hour' WHERE user_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.st.Pool().Exec(ctx, `INSERT INTO email_verifications (token_sha256, user_id, expires_at, created_at)
		SELECT decode(md5(random()::text || n::text), 'hex'), $1, now() + interval '1 day', now() - interval '2 hours' - n * interval '1 minute'
		FROM generate_series(1, 8) AS n`, id); err != nil {
		t.Fatal(err)
	}
	// Links older than a day are not in it.
	if _, err := a.st.Pool().Exec(ctx, `INSERT INTO email_verifications (token_sha256, user_id, expires_at, created_at)
		SELECT decode(md5(random()::text || n::text), 'hex'), $1, now() - interval '1 day', now() - interval '30 hours' - n * interval '1 hour'
		FROM generate_series(1, 3) AS n`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, "the ninth"); err != nil {
		t.Fatalf("the tenth link of the day (nine before it): %v", err)
	}
	if _, err := a.st.Pool().Exec(ctx, `UPDATE email_verifications SET created_at = created_at - interval '10 minutes' WHERE user_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	var oldest time.Time
	if err := a.st.Pool().QueryRow(ctx, `SELECT min(created_at) FROM email_verifications WHERE user_id = $1 AND created_at > now() - interval '24 hours'`, id).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	soon = api.ActivationTooSoonError{}
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, "the eleventh"); !errors.As(err, &soon) {
		t.Fatalf("an eleventh link in the day: %v, want ActivationTooSoonError", err)
	}
	if want := oldest.Add(24 * time.Hour); soon.After.Sub(want).Abs() > time.Second {
		t.Fatalf("the daily cap lifts at %v, want when the oldest link leaves the day (%v)", soon.After, want)
	}

	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, "   "); err == nil || !strings.Contains(err.Error(), "needs a reason") {
		t.Fatalf("a link without a reason: %v, want the refusal that a reason is needed", err)
	}
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, strings.Repeat("\u00e9", 501)); !errors.Is(err, api.ErrReasonLength) {
		t.Fatalf("a link with a 501-character reason: %v, want ErrReasonLength", err)
	}
	for _, c := range []struct {
		name  string
		actor *auth.Principal
		user  uuid.UUID
		want  error
	}{
		{"a staff token", &auth.Principal{UserID: a.staff.UserID, Via: "pat"}, id, api.ErrActorSession},
		{"someone who is not staff", &auth.Principal{UserID: id, Via: "session", PlatformStaff: true}, a.staff.UserID, api.ErrActorNotStaff},
		{"an account that is not there", a.staff, uuid.New(), api.ErrNoAccount},
	} {
		if _, err := a.srv.ResendActivation(ctx, "directory", c.actor, c.user, "why"); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}

	done := a.register("ac-resend-done")
	a.verifyEmail(done)
	doneID := uuid.MustParse(a.selfID(a.login(done)))
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, doneID, "why"); !errors.Is(err, api.ErrAlreadyActivated) {
		t.Fatalf("an activated account: %v, want ErrAlreadyActivated", err)
	}
	// An account whose address is the registry's placeholder has none a
	// link can reach, even unconfirmed.
	noAddr := a.registerUnverified("ac-resend-ph")
	noAddrID := uuid.MustParse(a.selfID(a.login(noAddr)))
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET email = $2 WHERE id = $1`, noAddrID, noAddr+"@oidc"+auth.SyntheticAddressSuffix); err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, noAddrID, "why"); !errors.Is(err, api.ErrNoAddress) {
		t.Fatalf("a placeholder address: %v, want ErrNoAddress", err)
	}
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET state = 'suspended' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, "why"); !errors.Is(err, api.ErrNotActive) {
		t.Fatalf("a suspended account: %v, want ErrNotActive", err)
	}
	if _, err := a.st.Pool().Exec(ctx, `UPDATE users SET state = 'deleted' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.ResendActivation(ctx, "directory", a.staff, id, "why"); !errors.Is(err, api.ErrAccountErased) {
		t.Fatalf("an erased account: %v, want ErrAccountErased", err)
	}
}

package api_test

// The account door (pkg/extension.Deps.Accounts): platform staff, through
// an extension's console, read a person's account and suspend, reinstate
// and sign it out. Each act checks its actor afresh, revokes what it says
// it revokes and nothing else, is audited with the actor and the reason,
// and mails the person at a confirmed address.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/notify"
)

// accountMails records the account notices.
type accountMails struct {
	notify.Notifier
	mu   sync.Mutex
	sent []notify.AccountNotice
}

func (m *accountMails) AccountChanged(_ context.Context, n notify.AccountNotice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, n)
	return nil
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
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO trusted_devices (id, user_id, token_sha256, expires_at) VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), now() + interval '30 days')`,
		`INSERT INTO desktop_grants (id, user_id, code_sha256, state_sha256, scopes, name, expires_at)
		 VALUES (gen_random_uuid(), $1, decode(md5(random()::text), 'hex'), '\x02', '{agent:read}', 'desktop', now() + interval '60 seconds')`,
	} {
		if _, err := a.st.Pool().Exec(ctx, q, id); err != nil {
			t.Fatal(err)
		}
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
		AND detail->>'reason' = $4 AND detail->>'extension' = 'directory'`
	if n := a.count(t, audited, "user.suspend", id, a.staff.UserID, "spam from this account"); n != 1 {
		t.Fatalf("user.suspend rows: %d, want 1", n)
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
	if c := a.mails.changes(); len(c) != 1 || c[0] != notify.AccountSignedOut {
		t.Fatalf("mails %v, want one signed-out", c)
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
	a.createOrg(sess, org)

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
	if len(f.Tokens) != 1 || f.Tokens[0].Name != "ac-facts-pat" || len(f.Tokens[0].Scopes) != 1 || f.Tokens[0].Scopes[0] != "agent:read" {
		t.Fatalf("tokens: %+v", f.Tokens)
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
	if c := a.mails.changes(); len(c) != 1 {
		t.Fatalf("mails %v, want only the first notice", c)
	}
}

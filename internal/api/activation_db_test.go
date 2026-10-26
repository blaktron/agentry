package api_test

// Unactivated accounts: a
// self-enrolled directory account arrives with email_verified false, is
// mailed an activation link at the sign-in that creates it, is read-only
// until it follows the link, may ask for another at most every five
// minutes, and is confirmed by the link in the registry. The directory
// reads that confirmation without an activation write. An unactivated
// account whose directory account is gone gives its address up to a
// verified sign-in.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/notify"
)

// activationSealingKey is the sealing key of the activation environment:
// the tombstone of an erased account is keyed with it, and a test that knows
// it can recompute the tombstone's hash.
var activationSealingKey = base64.StdEncoding.EncodeToString([]byte("activation-sealing-key-32-bytes!"))

// activationMails records every activation link the registry mails.
type activationMails struct {
	notify.Notifier
	mu     sync.Mutex
	tokens map[string][]string // address → tokens, oldest first
}

func (n *activationMails) EmailVerification(_ context.Context, to, _, token string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.tokens == nil {
		n.tokens = map[string][]string{}
	}
	n.tokens[to] = append(n.tokens[to], token)
	return nil
}

// total is how many activation links went out to any address.
func (n *activationMails) total() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	count := 0
	for _, tokens := range n.tokens {
		count += len(tokens)
	}
	return count
}

func (n *activationMails) sent(to string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.tokens[to]...)
}

// presenceDirectory is a directory an extension supplies, as the
// superseded-account check asks it: an account is there while its uid is
// present. failing makes every call fail.
type presenceDirectory struct {
	fakeDirectory
	present map[string]bool // uid → still in the directory
	failing bool
}

func (d *presenceDirectory) AccountGone(_ context.Context, l api.DirectoryLink) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failing {
		return false, errors.New("the directory is down")
	}
	return l.UID != "" && !d.present[l.UID], nil
}

func (d *presenceDirectory) set(uid string, present bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.present[uid] = present
}

// activationEnv is a deployment whose sign-in provider is a directory: the
// fake IdP signs people in as the directory's provider, and an extension's
// directory answers the superseded-account check.
func activationEnv(t *testing.T, idp *fakeOIDC, dir *presenceDirectory) (*testEnv, *activationMails, func() []api.Event) {
	t.Helper()
	mails := &activationMails{Notifier: notify.LogNotifier{}}
	var mu sync.Mutex
	var seen []api.Event
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.BaseURL = "http://127.0.0.1"
		cfg.Auth.SealingKey = activationSealingKey
		cfg.Auth.OIDC = config.OIDCProvider{ID: config.AuthentikProviderID, ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.hostClient())
		s.SetDirectory(dir)
		s.SetNotifier(mails)
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			mu.Lock()
			seen = append(seen, ev)
			mu.Unlock()
		})
	})
	return env, mails, func() []api.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]api.Event(nil), seen...)
	}
}

// signInAs completes a sign-in through the fake IdP, as the directory's
// provider, and returns the session caller and the account's id.
func signInAs(t *testing.T, env *testEnv, idp *fakeOIDC) (caller, string) {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, "authentik")
	visit, err := idp.hostClient().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, "authentik", state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	var out struct {
		CsrfToken string `json:"csrfToken"`
		User      struct {
			Id     string `json:"id"`
			Handle string `json:"handle"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	c := caller{name: out.User.Handle, csrf: out.CsrfToken}
	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" {
			c.session = ck.Value
		}
	}
	if c.session == "" {
		t.Fatal("no session")
	}
	return c, out.User.Id
}

func problemType(t *testing.T, res *http.Response) string {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var p struct {
		Type string `json:"type"`
	}
	_ = json.NewDecoder(res.Body).Decode(&p)
	return p.Type[strings.LastIndex(p.Type, "/")+1:]
}

// signInStatus runs a sign-in through the fake IdP as the directory's
// provider and returns the callback's status, for a sign-in that is
// expected to be refused.
func signInStatus(t *testing.T, env *testEnv, idp *fakeOIDC) int {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, "authentik")
	if v, err := idp.hostClient().Get(authURL.String()); err == nil {
		_ = v.Body.Close()
	}
	res := env.socialCallback(t, "authentik", state, cookie)
	_ = res.Body.Close()
	return res.StatusCode
}

// retryAfter is a response's Retry-After in seconds.
func retryAfter(t *testing.T, res *http.Response) int {
	t.Helper()
	n, err := strconv.Atoi(res.Header.Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After %q is not a number of seconds", res.Header.Get("Retry-After"))
	}
	return n
}

// ageActivationLinks moves every activation link of the account back in
// time, as if it had been made that much earlier.
func ageActivationLinks(t *testing.T, env *testEnv, userID string, minutes int) {
	t.Helper()
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE email_verifications SET created_at = created_at - ($2::int * interval '1 minute') WHERE user_id = $1::uuid`, userID, minutes); err != nil {
		t.Fatal(err)
	}
}

func TestUnactivatedAccountUntilActivated(t *testing.T) {
	idp := newFakeOIDC(t)
	dir := &presenceDirectory{present: map[string]bool{}}
	env, mails, events := activationEnv(t, idp, dir)

	// A self-enrolled directory account: the token says the address is not
	// confirmed.
	email := "ada" + env.sfx + "@example.test"
	idp.email, idp.emailUnverified = email, true
	dir.set(idp.sub, true)
	c, userID := signInAs(t, env, idp)

	// The first link went out with the sign-in that made the account.
	if got := mails.sent(email); len(got) != 1 {
		t.Fatalf("activation mails at the first sign-in: %d, want 1", len(got))
	} else if !strings.HasPrefix(got[0], auth.VerificationPrefix) {
		t.Fatalf("the activation link's token %q lacks the prefix %q", got[0][:min(len(got[0]), 6)], auth.VerificationPrefix)
	}
	// The link works for a day, and is stored hashed: the registry never
	// keeps the token it mailed.
	var lifetime float64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT extract(epoch FROM expires_at - created_at)::float8 FROM email_verifications WHERE user_id = $1::uuid`, userID).Scan(&lifetime); err != nil {
		t.Fatal(err)
	}
	if lifetime < 24*3600-120 || lifetime > 24*3600+120 {
		t.Fatalf("the activation link lives %.0f seconds, want a day", lifetime)
	}
	// Extensions hear the new account, and are told its address is not
	// confirmed.
	var registered []api.Event
	for _, ev := range events() {
		if ev.Kind == "user.registered" && ev.UserID.String() == userID {
			registered = append(registered, ev)
		}
	}
	if len(registered) != 1 {
		t.Fatalf("user.registered fired %d times, want 1", len(registered))
	}
	if pl := registered[0].Payload; pl["emailVerified"] != false || pl["via"] != "social" || pl["provider"] != "authentik" || pl["email"] != email || pl["handle"] != c.name {
		t.Fatalf("user.registered payload = %v", pl)
	}

	// It reads, and the account says it is unconfirmed and when it may ask
	// for another link.
	var me struct {
		EmailVerified                bool    `json:"emailVerified"`
		EmailVerificationResendAfter *string `json:"emailVerificationResendAfter"`
	}
	env.doJSON(c, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if me.EmailVerified || me.EmailVerificationResendAfter == nil {
		t.Fatalf("GET /user: %+v, want unconfirmed with a resend time", me)
	}

	// It does not write, outside its own housekeeping.
	res := env.do(c, http.MethodPost, "/api/v1/user/tokens", map[string]any{"name": "cli", "scopes": []string{"user:profile"}})
	if res.StatusCode != http.StatusForbidden || problemType(t, res) != "account-unactivated" {
		t.Fatalf("token while unactivated: %d", res.StatusCode)
	}
	env.doJSON(c, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "Ada"}, nil, http.StatusOK)

	// The token a desktop sign-in mints while unactivated is read-only too.
	const desktopState = "unactivated-app-nonce-0123"
	var desktopGrant struct {
		Code string `json:"code"`
	}
	env.doJSON(c, http.MethodPost, "/api/v1/user/tokens/desktop-grant", map[string]any{"state": desktopState}, &desktopGrant, http.StatusCreated)
	var desktopToken struct {
		Token string `json:"token"`
	}
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/desktop/exchange", map[string]any{"code": desktopGrant.Code, "state": desktopState}, &desktopToken, http.StatusCreated)
	desktop := caller{name: "desktop-token", pat: desktopToken.Token}
	env.doJSON(desktop, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)
	res = env.do(desktop, http.MethodPost, "/api/v1/agents", map[string]any{"namespace": c.name, "name": "unactivated", "modes": []string{"autonomous"}, "visibility": "private"})
	if res.StatusCode != http.StatusForbidden || problemType(t, res) != "account-unactivated" {
		t.Fatalf("a QuickAgent created with a token of an unactivated account: %d", res.StatusCode)
	}

	// Another link: not within five minutes of the last.
	res = env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Fatalf("resend at once: %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
	if wait := retryAfter(t, res); wait < 1 || wait > 300 {
		t.Fatalf("Retry-After %d seconds, want within the five minutes", wait)
	}
	if got := problemType(t, res); got != "activation-too-soon" {
		t.Fatalf("resend at once: problem type %q", got)
	}
	// Four minutes on it is still too soon, and the account says so.
	ageActivationLinks(t, env, userID, 4)
	res = env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("resend four minutes after the last link: %d, want 429", res.StatusCode)
	}
	if wait := retryAfter(t, res); wait < 1 || wait > 70 {
		t.Fatalf("Retry-After %d seconds four minutes in, want about a minute", wait)
	}
	_ = res.Body.Close()
	env.doJSON(c, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if me.EmailVerified || me.EmailVerificationResendAfter == nil {
		t.Fatalf("GET /user four minutes in: %+v, want unconfirmed with a resend time", me)
	}
	// Six minutes on it may ask again, and the account says it may now.
	ageActivationLinks(t, env, userID, 2)
	me.EmailVerificationResendAfter = nil
	env.doJSON(c, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if me.EmailVerified || me.EmailVerificationResendAfter != nil {
		t.Fatalf("GET /user six minutes in: %+v, want unconfirmed with no resend time", me)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE email_verifications SET created_at = created_at - interval '6 minutes' WHERE user_id = $1::uuid`, userID); err != nil {
		t.Fatal(err)
	}
	var sent struct {
		SentTo      string    `json:"sentTo"`
		ResendAfter time.Time `json:"resendAfter"`
	}
	env.doJSON(c, http.MethodPost, "/api/v1/user/email-verification", nil, &sent, http.StatusOK)
	if sent.SentTo != email || len(mails.sent(email)) != 2 {
		t.Fatalf("resend: %+v, %d mails", sent, len(mails.sent(email)))
	}
	if until := time.Until(sent.ResendAfter); until < 4*time.Minute+30*time.Second || until > 5*time.Minute+5*time.Second {
		t.Fatalf("the resend says to ask again in %s, want five minutes", until)
	}
	res = env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a second resend inside five minutes: %d", res.StatusCode)
	}
	_ = res.Body.Close()

	// An expired link activates nothing.
	links := mails.sent(email)
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE email_verifications SET expires_at = now() - interval '1 minute'
		 WHERE user_id = $1::uuid AND created_at = (SELECT max(created_at) FROM email_verifications WHERE user_id = $1::uuid)`, userID); err != nil {
		t.Fatal(err)
	}
	res = env.do(anonymous, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{"token": links[1]})
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("an expired link: %d", res.StatusCode)
	}
	_ = res.Body.Close()

	// Activation belongs to the registry: it works while the directory is
	// unavailable.
	dir.mu.Lock()
	dir.failing = true
	dir.mu.Unlock()
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{"token": links[0]}, nil, http.StatusNoContent)
	me.EmailVerificationResendAfter = nil
	env.doJSON(c, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if !me.EmailVerified || me.EmailVerificationResendAfter != nil {
		t.Fatalf("after activation: %+v", me)
	}
	var heard int
	for _, ev := range events() {
		if ev.Kind == "user.email_verified" && ev.UserID.String() == userID {
			heard++
		}
	}
	if heard != 1 {
		t.Fatalf("user.email_verified fired %d times, want 1", heard)
	}

	// A link works once; the account writes now.
	res = env.do(anonymous, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{"token": links[0]})
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a spent link: %d", res.StatusCode)
	}
	_ = res.Body.Close()
	env.doJSON(c, http.MethodPost, "/api/v1/user/tokens", map[string]any{"name": "cli", "scopes": []string{"user:profile"}}, nil, http.StatusCreated)
	res = env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("resend once activated: %d", res.StatusCode)
	}
	if got := problemType(t, res); got != "already-activated" {
		t.Fatalf("resend once activated: problem type %q", got)
	}

	// An account signed in with no address has a placeholder no link can
	// reach: it is mailed nothing, is not unactivated, and cannot ask for a
	// link.
	mailed := mails.total()
	idp.email, idp.emailUnverified = "", false
	idp.sub = "s-" + randSuffix()
	dir.set(idp.sub, true)
	bare, _ := signInAs(t, env, idp)
	var bareMe struct {
		Email                        string  `json:"email"`
		EmailVerified                bool    `json:"emailVerified"`
		EmailVerificationResendAfter *string `json:"emailVerificationResendAfter"`
	}
	env.doJSON(bare, http.MethodGet, "/api/v1/user", nil, &bareMe, http.StatusOK)
	if bareMe.EmailVerified || !strings.HasSuffix(bareMe.Email, auth.SyntheticAddressSuffix) || bareMe.EmailVerificationResendAfter != nil {
		t.Fatalf("an account with no address: %+v", bareMe)
	}
	res = env.do(bare, http.MethodPost, "/api/v1/user/email-verification", nil)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("resend to a placeholder address: %d, want 409", res.StatusCode)
	}
	if got := problemType(t, res); got != "no-address" {
		t.Fatalf("resend to a placeholder address: problem type %q", got)
	}
	env.doJSON(bare, http.MethodPost, "/api/v1/user/tokens", map[string]any{"name": "cli", "scopes": []string{"user:profile"}}, nil, http.StatusCreated)

	// A provider that asserts the placeholder suffix as a verified address
	// does not get the account a confirmed address: the placeholder is the
	// registry's own and nobody confirmed anything.
	idp.email = "victim" + env.sfx + "@authentik" + auth.SyntheticAddressSuffix
	idp.sub = "s-" + randSuffix()
	dir.set(idp.sub, true)
	forged, forgedID := signInAs(t, env, idp)
	env.doJSON(forged, http.MethodGet, "/api/v1/user", nil, &bareMe, http.StatusOK)
	if bareMe.EmailVerified || bareMe.Email == idp.email {
		t.Fatalf("an asserted placeholder address was taken as given: %+v", bareMe)
	}
	var verifiedAt *time.Time
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT email_verified_at FROM users WHERE id = $1::uuid`, forgedID).Scan(&verifiedAt); err != nil || verifiedAt != nil {
		t.Fatalf("the placeholder account's address was confirmed: %v, %v", verifiedAt, err)
	}
	if mails.total() != mailed {
		t.Fatalf("%d activation links went to accounts without an address", mails.total()-mailed)
	}
}

// TestUnactivatedSupersededByVerifiedSignIn: the directory removed
// an unactivated account when a trusted provider proved its address, and
// the registry account it leaves behind gives the address up.
func TestUnactivatedSupersededByVerifiedSignIn(t *testing.T) {
	idp := newFakeOIDC(t)
	dir := &presenceDirectory{present: map[string]bool{}}
	env, mails, _ := activationEnv(t, idp, dir)
	email := "squat" + env.sfx + "@example.test"

	// The squatter's unactivated account, signed in once through the directory.
	idp.email, idp.emailUnverified = email, true
	dir.set(idp.sub, true)
	squatterSub := idp.sub
	_, squatter := signInAs(t, env, idp)

	// The owner proves the address at the directory, which signs them in as
	// another of its accounts. While the directory still holds the
	// squatter's, that verified sign-in is told to link, as before.
	idp.emailUnverified = false
	idp.sub = "s-" + randSuffix()
	authURL, state, cookie := env.socialStart(t, "authentik")
	if v, err := idp.hostClient().Get(authURL.String()); err == nil {
		_ = v.Body.Close()
	}
	res := env.socialCallback(t, "authentik", state, cookie)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("verified sign-in while the unactivated account's directory account exists: %d", res.StatusCode)
	}
	_ = res.Body.Close()

	accountState := func(id string) string {
		t.Helper()
		var st string
		if err := env.st.Pool().QueryRow(context.Background(), `SELECT state FROM users WHERE id = $1::uuid`, id).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	// With the directory gone from the squatter's account but unable to
	// answer, nothing is known: the answer stays "link it explicitly".
	dir.set(squatterSub, false)
	dir.mu.Lock()
	dir.failing = true
	dir.mu.Unlock()
	if got := signInStatus(t, env, idp); got != http.StatusConflict {
		t.Fatalf("verified sign-in while the directory cannot be asked: %d, want 409", got)
	}
	dir.mu.Lock()
	dir.failing = false
	dir.mu.Unlock()
	if got := accountState(squatter); got != "active" {
		t.Fatalf("the squatter's account while the directory was down: %q, want active", got)
	}

	// An address the provider does not vouch for takes nothing from an
	// unactivated account, whatever the directory says.
	ownerSub := idp.sub
	idp.emailUnverified = true
	idp.sub = "s-" + randSuffix()
	if got := signInStatus(t, env, idp); got != http.StatusConflict {
		t.Fatalf("unverified sign-in at an unactivated account's address: %d, want 409", got)
	}
	idp.emailUnverified = false
	idp.sub = ownerSub
	if got := accountState(squatter); got != "active" {
		t.Fatalf("the squatter's account after an unverified sign-in: %q, want active", got)
	}

	// The directory removes it; the next verified sign-in takes the
	// address, and the squatter's registry account is erased.
	dir.set(squatterSub, false)
	_, owner := signInAs(t, env, idp)
	if owner == squatter {
		t.Fatal("signed in as the squatter's account")
	}
	var state2, gotEmail string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT state, email FROM users WHERE id = $1::uuid`, squatter).Scan(&state2, &gotEmail); err != nil {
		t.Fatal(err)
	}
	if state2 != "deleted" || gotEmail == email {
		t.Fatalf("the superseded account: state %q, email %q", state2, gotEmail)
	}
	var verified bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1::uuid AND email = $2`, owner, email).Scan(&verified); err != nil || !verified {
		t.Fatalf("the owner's account at the address: verified %v, %v", verified, err)
	}

	// What the erasure left of the squatter: a scrubbed address, a retired
	// handle, a tombstone holding only a keyed hash of the address, no
	// activation link, and an audit row that names the system and why.
	var scrubbed, retired, tombHash, tombReason string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT u.email, h.handle, u.deleted_tombstone->>'emailHash', u.deleted_tombstone->>'reason'
		   FROM users u JOIN handles h ON h.id = u.id WHERE u.id = $1::uuid`, squatter).Scan(&scrubbed, &retired, &tombHash, &tombReason); err != nil {
		t.Fatal(err)
	}
	if want := "deleted+" + squatter + "@invalid.invalid"; scrubbed != want {
		t.Fatalf("the superseded account's address = %q, want %q", scrubbed, want)
	}
	if want := "del-" + strings.ReplaceAll(squatter, "-", ""); retired != want {
		t.Fatalf("the superseded account's handle = %q, want %q", retired, want)
	}
	mac := hmac.New(sha256.New, []byte(activationSealingKey))
	_, _ = mac.Write([]byte(email))
	if tombHash != hex.EncodeToString(mac.Sum(nil)) || strings.Contains(tombHash, "@") {
		t.Fatalf("the tombstone's address hash = %q, want the keyed hash of the address", tombHash)
	}
	if tombReason != "unactivated account superseded by a verified sign-in" {
		t.Fatalf("the tombstone's reason = %q", tombReason)
	}
	var links int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM email_verifications WHERE user_id = $1::uuid`, squatter).Scan(&links); err != nil || links != 0 {
		t.Fatalf("activation links left for the erased account: %d, %v", links, err)
	}
	var actorKind string
	var detail []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT actor_kind, detail FROM audit_events WHERE action = 'user.delete' AND target_id = $1::uuid`, squatter).Scan(&actorKind, &detail); err != nil {
		t.Fatalf("audit user.delete: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(detail, &d)
	if actorKind != "system" || d["reason"] != "unactivated-superseded" || d["provider"] != "authentik" {
		t.Fatalf("user.delete audit row: actor %q, detail %s", actorKind, detail)
	}
	if got := accountState(owner); got != "active" {
		t.Fatalf("the owner's account: %q", got)
	}

	// An activated account is never superseded: its owner confirmed the
	// address, so a verified sign-in is linked to it, whatever became of its
	// directory account.
	activatedEmail := "activated" + env.sfx + "@example.test"
	idp.email, idp.emailUnverified = activatedEmail, true
	idp.sub = "s-" + randSuffix()
	activatedSub := idp.sub
	dir.set(activatedSub, true)
	_, activated := signInAs(t, env, idp)
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{"token": mails.sent(activatedEmail)[0]}, nil, http.StatusNoContent)
	dir.set(activatedSub, false)
	idp.emailUnverified = false
	idp.sub = "s-" + randSuffix()
	if _, linked := signInAs(t, env, idp); linked != activated {
		t.Fatalf("verified sign-in at an activated account's address signed in as %s, want the activated account %s", linked, activated)
	}
	if got := accountState(activated); got != "active" {
		t.Fatalf("the activated account: %q, want active", got)
	}

	// An organization's last admin is never erased this way, however
	// unactivated: the organization would be left without one.
	adminEmail := "lastadmin" + env.sfx + "@example.test"
	idp.email, idp.emailUnverified = adminEmail, true
	idp.sub = "s-" + randSuffix()
	adminSub := idp.sub
	dir.set(adminSub, true)
	_, lastAdmin := signInAs(t, env, idp)
	founder := env.register("sup-founder")
	env.verifyEmail(founder)
	orgID := env.createOrg(env.login(founder), "suporg"+env.sfxDigits())
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO memberships (org_id, user_id, role, state) VALUES ($1::uuid, $2::uuid, 'admin', 'active')`, orgID, lastAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE memberships SET role = 'member' WHERE org_id = $1::uuid AND user_id <> $2::uuid`, orgID, lastAdmin); err != nil {
		t.Fatal(err)
	}
	dir.set(adminSub, false)
	idp.emailUnverified = false
	idp.sub = "s-" + randSuffix()
	if got := signInStatus(t, env, idp); got != http.StatusConflict {
		t.Fatalf("verified sign-in at the last admin's address: %d, want 409", got)
	}
	if got := accountState(lastAdmin); got != "active" {
		t.Fatalf("the last admin's account: %q, want active", got)
	}

	// An account that never signed in through the directory has no directory
	// account to be gone: nothing supersedes it.
	passwordH := env.registerUnverified("sup-password")
	var passwordEmail, passwordID string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT u.email, u.id::text FROM users u JOIN handles h ON h.id = u.id WHERE h.handle = $1`, passwordH).Scan(&passwordEmail, &passwordID); err != nil {
		t.Fatal(err)
	}
	idp.email = passwordEmail
	idp.sub = "s-" + randSuffix()
	if got := signInStatus(t, env, idp); got != http.StatusConflict {
		t.Fatalf("verified sign-in at a password account's address: %d, want 409", got)
	}
	if got := accountState(passwordID); got != "active" {
		t.Fatalf("the password account: %q, want active", got)
	}

	// An account with two directory accounts is superseded only when both
	// are gone.
	twiceEmail := "twice" + env.sfx + "@example.test"
	idp.email, idp.emailUnverified = twiceEmail, true
	idp.sub = "s-" + randSuffix()
	firstSub := idp.sub
	dir.set(firstSub, true)
	_, twice := signInAs(t, env, idp)
	secondSub := "s-" + randSuffix()
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO identities (id, user_id, provider_kind, subject) VALUES (gen_random_uuid(), $1::uuid, 'social', $2)`,
		twice, "authentik:"+secondSub); err != nil {
		t.Fatal(err)
	}
	dir.set(secondSub, false)
	idp.emailUnverified = false
	idp.sub = "s-" + randSuffix()
	if got := signInStatus(t, env, idp); got != http.StatusConflict {
		t.Fatalf("verified sign-in while one of two directory accounts remains: %d, want 409", got)
	}
	if got := accountState(twice); got != "active" {
		t.Fatalf("the two-account squatter: %q, want active", got)
	}
	dir.set(firstSub, false)
	if _, taken := signInAs(t, env, idp); taken == twice {
		t.Fatal("signed in as the two-account squatter")
	}
	if got := accountState(twice); got != "deleted" {
		t.Fatalf("the two-account squatter once both are gone: %q, want deleted", got)
	}
}

// TestActivationDailyCap: past ten links in a day an account is sent no
// more, whatever the interval (anyone can sign up with another person's
// address, and the cap bounds what they can make it receive).
func TestActivationDailyCap(t *testing.T) {
	mails := &activationMails{Notifier: notify.LogNotifier{}}
	env := newTestEnvWith(t, func(s *api.Server) { s.SetNotifier(mails) })
	h := env.registerUnverified("capped")
	c := env.login(h)
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO email_verifications (token_sha256, user_id, expires_at, created_at)
		 SELECT sha256(convert_to(gen_random_uuid()::text, 'UTF8')), id, now() + interval '1 day', now() - interval '6 minutes'
		 FROM handles, generate_series(1, 10) WHERE handle = $1`, h); err != nil {
		t.Fatal(err)
	}
	res := env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusTooManyRequests || len(mails.sent(h+"@example.test")) != 0 {
		t.Fatalf("an eleventh link in a day: %d, %d mails", res.StatusCode, len(mails.sent(h+"@example.test")))
	}
	// The retry time is when the oldest link leaves the day, not the five
	// minutes of the interval.
	if wait := retryAfter(t, res); wait < 23*3600 || wait > 24*3600+1 {
		t.Fatalf("Retry-After %d seconds past the daily cap, want most of a day", wait)
	}
	if got := problemType(t, res); got != "activation-too-soon" {
		t.Fatalf("past the daily cap: problem type %q", got)
	}

	// The cap counts links in the last day, ten of them.
	for i, tc := range []struct {
		name   string
		rows   int
		minute int // how long ago each was made
		status int
	}{
		{"nine links in the last day", 9, 6, http.StatusOK},
		{"ten links, all more than a day old", 10, 25 * 60, http.StatusOK},
		{"ten links, the oldest 23 hours old", 10, 23 * 60, http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := env.registerUnverified("capcase" + strconv.Itoa(i))
			c := env.login(h)
			if _, err := env.st.Pool().Exec(ctx,
				`INSERT INTO email_verifications (token_sha256, user_id, expires_at, created_at)
				 SELECT sha256(convert_to(gen_random_uuid()::text, 'UTF8')), id, now() + interval '1 day', now() - ($3::int * interval '1 minute')
				 FROM handles, generate_series(1, $2::int) WHERE handle = $1`, h, tc.rows, tc.minute); err != nil {
				t.Fatal(err)
			}
			res := env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
			_ = res.Body.Close()
			sent := len(mails.sent(h + "@example.test"))
			if res.StatusCode != tc.status || (tc.status == http.StatusOK) != (sent == 1) {
				t.Fatalf("%d links made %d minutes ago: %d, %d mails, want %d", tc.rows, tc.minute, res.StatusCode, sent, tc.status)
			}
		})
	}
}

var _ = uuid.Nil

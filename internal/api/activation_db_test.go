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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/notify"
)

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

func (n *activationMails) sent(to string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.tokens[to]...)
}

// fakeDirectoryUsers is authentik's users admin API as activation and the
// superseded-account check use it: read one account by id and search by
// address. PATCH is refused, as the registry's restricted token refuses
// directory writes. failing makes every call answer 503.
type fakeDirectoryUsers struct {
	mu       sync.Mutex
	accounts map[int]map[string]any // pk → the account as the API returns it
	failing  bool
}

func (d *fakeDirectoryUsers) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/core/users/{pk}/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.failing {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		pk, _ := strconv.Atoi(r.PathValue("pk"))
		u, ok := d.accounts[pk]
		if !ok {
			http.Error(w, "{}", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(u)
	})
	mux.HandleFunc("PATCH /api/v3/core/users/{pk}/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("GET /api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		q := strings.ToLower(r.URL.Query().Get("search"))
		results := []map[string]any{}
		for _, u := range d.accounts {
			if e, _ := u["email"].(string); q != "" && strings.Contains(strings.ToLower(e), q) {
				results = append(results, u)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pagination": map[string]any{"next": 0}, "results": results})
	})
	return mux
}

func (d *fakeDirectoryUsers) attributes(pk int) map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, _ := d.accounts[pk]["attributes"].(map[string]any)
	return a
}

// activationEnv is a deployment whose credentials live in the directory:
// the fake IdP signs people in as the directory (and as Google), the fake
// users API is the directory's admin API, and unactivated accounts are
// read-only.
func activationEnv(t *testing.T, idp *fakeOIDC, dir *fakeDirectoryUsers) (*testEnv, *activationMails, func() []api.Event) {
	t.Helper()
	dsrv := httptest.NewServer(dir.handler())
	t.Cleanup(dsrv.Close)
	mails := &activationMails{Notifier: notify.LogNotifier{}}
	var mu sync.Mutex
	var seen []api.Event
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.BaseURL = "http://127.0.0.1"
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
		cfg.Social.Google = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
		cfg.Auth.IdPAdminURL = dsrv.URL
		cfg.Auth.IdPAdminToken = "tok"
		cfg.Auth.IdPTrustCheckToken = directoryTrustToken
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.hostClient())
		s.SetNotifier(mails)
		s.SetUnactivatedReadOnly(true)
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

// TestDirectoryEmailVerification answers only for the directory identity's
// exact confirmed address, and only to the directory on the private network.
func TestDirectoryEmailVerification(t *testing.T) {
	idp := newFakeOIDC(t)
	dir := &fakeDirectoryUsers{accounts: map[int]map[string]any{}}
	env, mails, _ := activationEnv(t, idp, dir)
	idp.email, idp.emailUnverified = "activation"+env.sfx+"@example.test", true
	_, userID := signInAs(t, env, idp, "authentik")
	check := func(secret, sub, email string, headers map[string]string, wantStatus int, wantVerified bool) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"sub": sub, "email": email})
		req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/internal/directory/email-verification", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+secret)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != wantStatus {
			t.Fatalf("check: status %d, want %d", res.StatusCode, wantStatus)
		}
		if wantStatus == http.StatusOK {
			var answer struct {
				Verified *bool `json:"verified"`
			}
			if err := json.NewDecoder(res.Body).Decode(&answer); err != nil || answer.Verified == nil || *answer.Verified != wantVerified {
				t.Fatalf("check: %+v (%v), want verified=%v", answer, err, wantVerified)
			}
		}
	}
	check(directoryTrustToken, idp.sub, idp.email, nil, http.StatusOK, false)
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{"token": mails.sent(idp.email)[0]}, nil, http.StatusNoContent)
	check(directoryTrustToken, idp.sub, strings.ToUpper(idp.email), nil, http.StatusOK, true)
	check(directoryTrustToken, "another-subject", idp.email, nil, http.StatusOK, false)
	check(directoryTrustToken, idp.sub, "somebody-else@example.test", nil, http.StatusOK, false)
	check("wrong", idp.sub, idp.email, nil, http.StatusUnauthorized, false)
	check(directoryTrustToken, "", idp.email, nil, http.StatusBadRequest, false)
	check(directoryTrustToken, idp.sub, "", nil, http.StatusBadRequest, false)
	for _, h := range []string{"X-Forwarded-For", "Forwarded"} {
		check(directoryTrustToken, idp.sub, idp.email, map[string]string{h: "for=203.0.113.9"}, http.StatusNotFound, false)
	}
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE users SET state = 'suspended' WHERE id = $1::uuid`, userID); err != nil {
		t.Fatal(err)
	}
	check(directoryTrustToken, idp.sub, idp.email, nil, http.StatusOK, false)
	// An unavailable store must never become an affirmative answer.
	if _, err := env.st.Pool().Exec(context.Background(), `ALTER TABLE identities RENAME TO identities_hidden`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.st.Pool().Exec(context.Background(), `ALTER TABLE identities_hidden RENAME TO identities`); err != nil {
			t.Fatal(err)
		}
	})
	check(directoryTrustToken, idp.sub, idp.email, nil, http.StatusServiceUnavailable, false)
}

// signInAs completes a sign-in through the fake IdP and returns the session
// caller and the account's id.
func signInAs(t *testing.T, env *testEnv, idp *fakeOIDC, provider string) (caller, string) {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, provider)
	visit, err := idp.hostClient().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, provider, state, cookie)
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

func TestUnactivatedAccountUntilActivated(t *testing.T) {
	idp := newFakeOIDC(t)
	dir := &fakeDirectoryUsers{accounts: map[int]map[string]any{}}
	env, mails, events := activationEnv(t, idp, dir)

	// A self-enrolled directory account: the token says the address is not
	// confirmed, and carries the directory's id for the account.
	email := "ada" + env.sfx + "@example.test"
	idp.email, idp.emailUnverified = email, true
	idp.extra = map[string]any{"agentry_directory_id": 4242}
	dir.accounts[4242] = map[string]any{"pk": 4242, "uid": "", "email": email, "type": "internal", "is_active": true,
		"attributes": map[string]any{"agentry_email_verified": false, "agentry_promo_code": "LAUNCH-1"}}
	c, userID := signInAs(t, env, idp, "authentik")
	var uid string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT substring(subject from 11) FROM identities WHERE user_id = $1::uuid`, userID).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	dir.accounts[4242]["uid"] = uid

	// The first link went out with the sign-in that made the account.
	if got := mails.sent(email); len(got) != 1 {
		t.Fatalf("activation mails at the first sign-in: %d, want 1", len(got))
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

	// Another link: not within five minutes of the last.
	res = env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Fatalf("resend at once: %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
	_ = res.Body.Close()
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE email_verifications SET created_at = created_at - interval '6 minutes' WHERE user_id = $1::uuid`, userID); err != nil {
		t.Fatal(err)
	}
	var sent struct {
		SentTo string `json:"sentTo"`
	}
	env.doJSON(c, http.MethodPost, "/api/v1/user/email-verification", nil, &sent, http.StatusOK)
	if sent.SentTo != email || len(mails.sent(email)) != 2 {
		t.Fatalf("resend: %+v, %d mails", sent, len(mails.sent(email)))
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
	// unavailable, and does not change the directory's attributes.
	dir.failing = true
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/verify-email", map[string]any{"token": links[0]}, nil, http.StatusNoContent)
	me.EmailVerificationResendAfter = nil
	env.doJSON(c, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if !me.EmailVerified || me.EmailVerificationResendAfter != nil {
		t.Fatalf("after activation: %+v", me)
	}
	attrs := dir.attributes(4242)
	if attrs["agentry_email_verified"] != false || attrs["agentry_promo_code"] != "LAUNCH-1" {
		t.Fatalf("the directory account's attributes after activation: %v", attrs)
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
	_ = res.Body.Close()
}

// TestUnactivatedSupersededByVerifiedSignIn: the directory removed
// an unactivated account when a trusted provider proved its address, and
// the registry account it leaves behind gives the address up.
func TestUnactivatedSupersededByVerifiedSignIn(t *testing.T) {
	idp := newFakeOIDC(t)
	dir := &fakeDirectoryUsers{accounts: map[int]map[string]any{}}
	env, _, _ := activationEnv(t, idp, dir)
	email := "squat" + env.sfx + "@example.test"

	// The squatter's unactivated account, signed in once through the directory.
	idp.email, idp.emailUnverified = email, true
	idp.extra = map[string]any{"agentry_directory_id": 5151}
	dir.accounts[5151] = map[string]any{"pk": 5151, "uid": "", "email": email, "type": "internal", "is_active": true}
	_, squatter := signInAs(t, env, idp, "authentik")
	var uid string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT substring(subject from 11) FROM identities WHERE user_id = $1::uuid`, squatter).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	dir.accounts[5151]["uid"] = uid

	// While the directory still holds it, a verified sign-in is told to link,
	// as before.
	idp.emailUnverified = false
	idp.extra = nil
	authURL, state, cookie := env.socialStart(t, "google")
	if v, err := idp.hostClient().Get(authURL.String()); err == nil {
		_ = v.Body.Close()
	}
	res := env.socialCallback(t, "google", state, cookie)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("verified sign-in while the unactivated account's directory account exists: %d", res.StatusCode)
	}
	_ = res.Body.Close()

	// The directory removes it; the next verified sign-in takes the
	// address, and the squatter's registry account is erased.
	delete(dir.accounts, 5151)
	_, owner := signInAs(t, env, idp, "google")
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
}

// TestActivationDailyCap: past ten links in a day an account is sent no
// more, whatever the interval (anyone can sign up with another person's
// address, and the cap bounds what they can make it receive).
func TestActivationDailyCap(t *testing.T) {
	mails := &activationMails{Notifier: notify.LogNotifier{}}
	env := newTestEnvWith(t, func(s *api.Server) { s.SetNotifier(mails) })
	h := env.register("capped")
	c := env.login(h)
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE email_verifications SET created_at = now() - interval '6 minutes'
		 WHERE user_id = (SELECT id FROM handles WHERE handle = $1)`, h); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO email_verifications (token_sha256, user_id, expires_at, created_at)
		 SELECT sha256(convert_to(gen_random_uuid()::text, 'UTF8')), id, now() + interval '1 day', now() - interval '6 minutes'
		 FROM handles, generate_series(1, 9) WHERE handle = $1`, h); err != nil {
		t.Fatal(err)
	}
	res := env.do(c, http.MethodPost, "/api/v1/user/email-verification", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusTooManyRequests || len(mails.sent(h+"@example.test")) != 1 {
		t.Fatalf("an eleventh link in a day: %d, %d mails", res.StatusCode, len(mails.sent(h+"@example.test")))
	}
}

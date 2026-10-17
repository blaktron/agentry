package api_test

// Trusted devices (remembered browsers): a browser that answered the second
// factor at the sign-in provider may be remembered, so a later sign-in from
// it is not asked for the code. The server keeps the record: it is minted
// through the sign-in hook's RememberBrowser, from that sign-in's own
// verified token, and checked through UseRememberedBrowser. The directory
// that asked for the code sets and reads the cookie.
//
// These tests are written to be mutation-checked. Each names the control
// it proves, so breaking the control breaks a named test:
//
//	mint only from a fresh second factor     → TestTrustedDeviceIsEarnedOnlyByAnsweringTheSecondFactor
//	a sign-in mints nothing unless asked     → TestTrustedDeviceIsNotMintedUnlessAskedFor
//	the token is never itself a credential   → TestTrustedDeviceCookieAuthenticatesNothingOnItsOwn
//	the record is bound to its owner in SQL  → TestTrustedDeviceIsBoundToItsOwner
//	expired / revoked / unknown are refused  → TestTrustedDeviceRefusesADeadCredential
//	a store that cannot be read fails closed → TestTrustedDeviceStoreFailureDemandsTheCode
//	the lifetime is absolute, not sliding    → TestTrustedDeviceExpiryIsAbsoluteNotSliding
//	only the hash is stored                  → TestTrustedDeviceStoresOnlyTheHash
//	the token says what it is                → TestTrustedDeviceTokenIdentifiesItself
//	deactivation takes the browser away      → TestSCIMDeactivationRevokesTrustedDevices
//	erasure removes the row, not just trust  → TestErasureDeletesTrustedDevices
//	the sweep deletes only what has expired  → TestTrustedDeviceSweepDeletesOnlyWhatHasExpired
//	logout leaves the browser remembered     → TestTrustedDeviceSurvivesLogout
//	so does "sign out everywhere else"       → TestTrustedDeviceSurvivesSignOutEverywhereElse
//
// Deleting "AND user_id = $2" from the lookup does NOT prove the owner scoping.
// The generated Go still passes two arguments, so pgx rejects the query, the
// lookup fails closed, and TestTrustedDeviceIsBoundToItsOwner passes for the
// wrong reason. Making the scoping vacuous while keeping the argument count
// valid — "AND (user_id = $2 OR user_id IS NOT NULL)" — is the mutation that
// actually exercises it.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/testidp"
)

const trustedDeviceCookie = "agentry_trusted_device"

// deviceTTL is the lifetime this file's server is configured with. It is
// deliberately not the 30-day default: a mint that answers with a
// distinctive value proves the server read the configuration rather than
// hard-coding the ceiling. The default and the ceiling are config's own tests.
const deviceTTL = 100 * time.Hour

// newTrustedDeviceEnv builds a server whose trusted-device lifetime is
// distinctive.
func newTrustedDeviceEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.TrustedDeviceTTL = deviceTTL
	})
}

// userIDOf is the account id behind a handle.
func userIDOf(t *testing.T, env *testEnv, handle string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id FROM handles WHERE handle = $1`, handle).Scan(&id); err != nil {
		t.Fatalf("no account %s: %v", handle, err)
	}
	return id
}

// signInRequest stands in for the sign-in callback's request, which the
// mint and the use record facts from.
func signInRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/oidc/callback", nil)
}

// earnTrustedDevice makes a fresh account and remembers a browser for it the
// one way there is: the mint a sign-in hook reaches, with evidence of a second
// factor answered just now. It returns the handle, the account id and the
// token the directory would set as its cookie.
func earnTrustedDevice(t *testing.T, env *testEnv, handle string) (string, uuid.UUID, string) {
	t.Helper()
	h := env.register(handle)
	id := userIDOf(t, env, h)
	token, ttl, err := env.srvObj.MintRememberedBrowser(signInRequest(), id, []string{"pwd", "otp"}, time.Now(), map[string]any{"via": "test"})
	if err != nil {
		t.Fatalf("a fresh second factor earned no remembered browser: %v", err)
	}
	if ttl != deviceTTL {
		t.Fatalf("the mint's lifetime is %s, want the configured %s", ttl, deviceTTL)
	}
	return h, id, token
}

// useDevice asks the server whether token is a live remembered browser of
// id's account, as a directory's check does.
func useDevice(t *testing.T, env *testEnv, id uuid.UUID, token string) (bool, error) {
	t.Helper()
	return env.srvObj.UseRememberedBrowser(signInRequest(), id, token, map[string]any{"via": "test"})
}

func requireRemembered(t *testing.T, env *testEnv, id uuid.UUID, token string, want bool) {
	t.Helper()
	got, err := useDevice(t, env, id, token)
	if err != nil {
		t.Fatalf("use: %v", err)
	}
	if got != want {
		t.Fatalf("remembered = %v, want %v", got, want)
	}
}

func countDevices(t *testing.T, env *testEnv, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM trusted_devices WHERE user_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// deviceRow is the stored record behind an account's most recent trusted
// device. It reads the table directly because what a test needs to know is
// what was persisted, not what the API said it persisted.
type deviceRow struct {
	id         uuid.UUID
	tokenHash  []byte
	expiresAt  time.Time
	lastSeenAt time.Time
	revokedAt  *time.Time
}

func fetchDeviceRow(t *testing.T, env *testEnv, userID uuid.UUID) deviceRow {
	t.Helper()
	var d deviceRow
	err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id, token_sha256, expires_at, last_seen_at, revoked_at
		   FROM trusted_devices WHERE user_id = $1
		  ORDER BY created_at DESC, id DESC LIMIT 1`, userID).
		Scan(&d.id, &d.tokenHash, &d.expiresAt, &d.lastSeenAt, &d.revokedAt)
	if err != nil {
		t.Fatalf("no trusted_devices row for %s: %v", userID, err)
	}
	return d
}

// TestTrustedDeviceIsEarnedOnlyByAnsweringTheSecondFactor is the positive
// path and the mint rule at once: evidence of a second factor answered just
// now earns a record, and nothing less does. A token whose `amr` names no
// factor, or whose `auth_time` is old (an IdP re-issuing a token against a
// session of its own), mints nothing; using the record mints nothing more.
func TestTrustedDeviceIsEarnedOnlyByAnsweringTheSecondFactor(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h := env.register("td-earn")
	id := userIDOf(t, env, h)
	for name, ev := range map[string]struct {
		amr      []string
		authTime time.Time
	}{
		"no second factor":           {[]string{"pwd"}, time.Now()},
		"no amr at all":              {nil, time.Now()},
		"no auth_time":               {[]string{"otp"}, time.Time{}},
		"a factor answered long ago": {[]string{"otp"}, time.Now().Add(-time.Hour)},
	} {
		if _, _, err := env.srvObj.MintRememberedBrowser(signInRequest(), id, ev.amr, ev.authTime, nil); !errors.Is(err, api.ErrNoSecondFactor) {
			t.Errorf("%s: mint err = %v, want ErrNoSecondFactor", name, err)
		}
	}
	if n := countDevices(t, env, id); n != 0 {
		t.Fatalf("%d records minted without a fresh second factor", n)
	}

	_, other, token := earnTrustedDevice(t, env, "td-earn2")
	requireRemembered(t, env, other, token, true)
	// The use did not mint a second credential, which is what keeps the
	// lifetime absolute: one browser earns one record.
	if n := countDevices(t, env, other); n != 1 {
		t.Fatalf("%d trusted-device rows after one earn and one use, want exactly 1", n)
	}
}

// TestTrustedDeviceIsNotMintedUnlessAskedFor: a sign-in through the
// provider, second factor and all, leaves no record and sets no cookie
// unless a sign-in hook asks for one.
func TestTrustedDeviceIsNotMintedUnlessAskedFor(t *testing.T) {
	env, idp := newOIDCTestEnv(t, func(c *config.Config) { c.Auth.TrustedDeviceTTL = deviceTTL })
	h := "td-optin" + env.sfx
	in := env.signInOIDC(t, idp, config.OIDCProviderID, testidp.Person{
		Subject: "sub-" + h, Email: h + "@example.test", EmailVerified: true, Username: h,
		AMR: []string{"pwd", "otp"}, AuthTime: time.Now(),
	})
	if in.status != http.StatusOK {
		t.Fatalf("sign-in: %d %s", in.status, in.body)
	}
	requireNoCookie(t, in.cookies, trustedDeviceCookie)
	if n := countDevices(t, env, uuid.MustParse(in.userID)); n != 0 {
		t.Fatalf("%d trusted-device rows recorded for a sign-in that never asked for one", n)
	}
}

// TestTrustedDeviceCookieAuthenticatesNothingOnItsOwn proves the credential is
// narrow. It stands in for the second factor at the directory and grants
// nothing here: no session, no scope, no access to an authenticated route,
// whether it arrives as the cookie or as a bearer.
func TestTrustedDeviceCookieAuthenticatesNothingOnItsOwn(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, _, token := earnTrustedDevice(t, env, "td-narrow")
	for name, set := range map[string]func(*http.Request){
		"as the cookie": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: trustedDeviceCookie, Value: token}) },
		"as a bearer":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
	} {
		req, err := http.NewRequest(http.MethodGet, env.srv.URL+"/api/v1/user/sessions", nil)
		if err != nil {
			t.Fatal(err)
		}
		set(req)
		res, err := env.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, res.StatusCode)
		}
	}
}

// TestTrustedDeviceIsBoundToItsOwner proves the lookup is scoped by user_id in
// SQL rather than by a branch above it: one account's record is worth nothing
// to another, and the answer is the same one an unknown token gets.
func TestTrustedDeviceIsBoundToItsOwner(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, _, token := earnTrustedDevice(t, env, "td-owner")
	other := userIDOf(t, env, env.register("td-other"))
	requireRemembered(t, env, other, token, false)
}

// TestTrustedDeviceRefusesADeadCredential walks every way a presented token
// can fail to be live. Each is refused the same way as an absent one.
func TestTrustedDeviceRefusesADeadCredential(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	ctx := context.Background()
	_, id, token := earnTrustedDevice(t, env, "td-dead")

	cases := []struct {
		name  string
		token string
		// kill mutates the stored row before the use, for the cases where
		// the token is genuine but the record behind it is not live.
		kill func(t *testing.T)
	}{
		{name: "no token at all"},
		{name: "a value that was never issued", token: "agyd_neverissued"},
		{name: "another credential's prefix", token: "agys_notasession"},
		{
			name:  "revoked",
			token: token,
			kill: func(t *testing.T) {
				if _, err := env.st.Pool().Exec(ctx,
					`UPDATE trusted_devices SET revoked_at = now() WHERE token_sha256 = $1`,
					auth.HashToken(token)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:  "expired",
			token: token,
			kill: func(t *testing.T) {
				// Undo the revoke first, so this case fails for its own
				// reason and not because an earlier one still applies.
				if _, err := env.st.Pool().Exec(ctx,
					`UPDATE trusted_devices SET revoked_at = NULL, expires_at = now() - interval '1 second'
					  WHERE token_sha256 = $1`, auth.HashToken(token)); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.kill != nil {
				tc.kill(t)
			}
			requireRemembered(t, env, id, tc.token, false)
		})
	}
}

// TestTrustedDeviceStoreFailureDemandsTheCode is the fail-closed control, and
// the one that matters most: an outage must never be the way past a factor.
// The table is renamed out from under the lookup so the query errors with
// something other than "no rows", and the use must answer no, with the error
// the caller treats as no.
func TestTrustedDeviceStoreFailureDemandsTheCode(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	ctx := context.Background()
	_, id, token := earnTrustedDevice(t, env, "td-failclosed")

	// No test in internal/api calls t.Parallel(), so the rename cannot race
	// another test's query. It is restored before the test ends either way.
	if _, err := env.st.Pool().Exec(ctx, `ALTER TABLE trusted_devices RENAME TO trusted_devices_hidden`); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		_, _ = env.st.Pool().Exec(context.Background(),
			`ALTER TABLE trusted_devices_hidden RENAME TO trusted_devices`)
	}
	t.Cleanup(restore)

	if ok, err := useDevice(t, env, id, token); ok || err == nil {
		t.Fatalf("with the store unreadable the use answered %v, %v: want no, with an error", ok, err)
	}
	if _, _, err := env.srvObj.MintRememberedBrowser(signInRequest(), id, []string{"otp"}, time.Now(), nil); err == nil {
		t.Fatal("with the store unreadable a mint succeeded")
	}

	// And the record works once the store is back, so the failure is
	// contained to the answer and did not damage the record.
	restore()
	requireRemembered(t, env, id, token, true)
}

// TestTrustedDeviceExpiryIsAbsoluteNotSliding proves the lifetime is absolute. Using
// the credential refreshes last_seen_at and must not move expires_at, so a
// stolen cookie does not become immortal by being used and a person who signs
// in daily is still asked again on day thirty.
func TestTrustedDeviceExpiryIsAbsoluteNotSliding(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, id, token := earnTrustedDevice(t, env, "td-absolute")

	before := fetchDeviceRow(t, env, id)
	requireRemembered(t, env, id, token, true)
	after := fetchDeviceRow(t, env, id)
	if !after.expiresAt.Equal(before.expiresAt) {
		t.Fatalf("using the credential moved its expiry from %s to %s: the lifetime is sliding, and it must be absolute",
			before.expiresAt.Format(time.RFC3339Nano), after.expiresAt.Format(time.RFC3339Nano))
	}
	if !after.lastSeenAt.After(before.lastSeenAt) {
		t.Fatalf("using the credential did not refresh last_seen_at (still %s): the row cannot describe when it was last used",
			after.lastSeenAt.Format(time.RFC3339Nano))
	}
	if after.id != before.id {
		t.Fatalf("using the credential replaced the record (%s → %s): a use must not mint", before.id, after.id)
	}
	// Neither read may find the row revoked: use is not revocation, and a
	// record that came back revoked here would make every assertion above
	// about a different row than the one that was issued.
	if before.revokedAt != nil || after.revokedAt != nil {
		t.Fatalf("the record is revoked (before=%v after=%v) while still being honoured", before.revokedAt, after.revokedAt)
	}
	if n := countDevices(t, env, id); n != 1 {
		t.Fatalf("%d records after one earn and one use, want exactly 1", n)
	}
}

// TestTrustedDeviceStoresOnlyTheHash proves the token is not recoverable from
// the database: only its SHA-256 is stored, so reading the table yields no
// credential. This is the rule every other token in the registry follows.
func TestTrustedDeviceStoresOnlyTheHash(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, id, token := earnTrustedDevice(t, env, "td-hash")

	row := fetchDeviceRow(t, env, id)
	want := auth.HashToken(token)
	if len(row.tokenHash) != len(want) {
		t.Fatalf("stored hash is %d bytes, want %d", len(row.tokenHash), len(want))
	}
	for i := range want {
		if row.tokenHash[i] != want[i] {
			t.Fatal("the stored value is not the SHA-256 of the issued token")
		}
	}

	// And the token appears nowhere in the row, in any column — the check that
	// would catch it being stored in the clear beside its own hash.
	var whole string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT row_to_json(trusted_devices)::text FROM trusted_devices WHERE id = $1`, row.id).
		Scan(&whole); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(whole, token) {
		t.Fatal("the issued token is recoverable from the stored row")
	}
}

// TestTrustedDeviceTokenIdentifiesItself: the token the directory sets as
// its cookie carries its own prefix, so a leaked string says what it is,
// and enough of it to carry 32 bytes of entropy.
func TestTrustedDeviceTokenIdentifiesItself(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, _, token := earnTrustedDevice(t, env, "td-attrs")
	if !strings.HasPrefix(token, auth.TrustedDevicePrefix) {
		t.Fatalf("the issued token has prefix %q, want %q so a leaked string identifies itself",
			token[:min(len(token), 8)], auth.TrustedDevicePrefix)
	}
	if len(token) <= len(auth.TrustedDevicePrefix) {
		t.Fatalf("the issued token is %d characters: too short to carry 32 bytes of entropy", len(token))
	}
}

// insertTrustedDevice records one directly, the way insertSession and insertPAT
// do for the credentials they stand in for. It exists for the paths that take
// trust away rather than grant it: a SCIM-provisioned account never signed in
// and so cannot have earned a record, and what deactivation does to one is
// the thing under test.
func insertTrustedDevice(t *testing.T, env *testEnv, userID string) string {
	t.Helper()
	tok, err := auth.NewToken(auth.TrustedDevicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO trusted_devices (id, user_id, token_sha256, expires_at)
		 VALUES (gen_random_uuid(), $1, $2, now() + interval '30 days')`,
		userID, auth.HashToken(tok)); err != nil {
		t.Fatal(err)
	}
	return tok
}

// deviceState reports what became of a record: live, revoked, or gone. Erasure
// deletes and deactivation revokes, and telling them apart is the point — a
// revoked row still holds an address and a user agent, which is personal data
// an erased account must not leave behind.
func deviceState(t *testing.T, env *testEnv, token string) string {
	t.Helper()
	var revoked *time.Time
	err := env.st.Pool().QueryRow(context.Background(),
		`SELECT revoked_at FROM trusted_devices WHERE token_sha256 = $1`, auth.HashToken(token)).
		Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return "gone"
	}
	if err != nil {
		t.Fatal(err)
		return "" // unreachable: t.Fatal does not return
	}
	if revoked != nil {
		return "revoked"
	}
	return "live"
}

// TestSCIMDeactivationRevokesTrustedDevices proves deactivation takes the
// remembered browser away as well as the sessions.
//
// Deactivation drops the membership, revokes the org-bound PATs and kills the
// sessions, but it deliberately leaves the account's state alone, because the
// person may exist outside the organization. So a surviving record would let a
// deprovisioned user sign straight back in and be asked for *less* than before
// them — the second factor skipped — which is the opposite of what
// scimDeactivate promises. TestTrustedDeviceRefusesADeadCredential already
// proves a revoked record is refused at use; this proves deactivation is what
// revokes it, and the two together are the property.
func TestSCIMDeactivationRevokesTrustedDevices(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	scim, _ := env.scimOrg(t, "td-scim")

	email := "td-deact-" + env.sfx + "@acme.example"
	var created struct {
		ID string `json:"id"`
	}
	env.doJSON(scim, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   true,
	}, &created, http.StatusCreated)

	tok := insertTrustedDevice(t, env, created.ID)
	if got := deviceState(t, env, tok); got != "live" {
		t.Fatalf("before deactivation the record is %s, want live", got)
	}

	env.doJSON(scim, http.MethodPatch, "/scim/v2/Users/"+created.ID, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	}, nil, http.StatusOK)

	if got := deviceState(t, env, tok); got != "revoked" {
		t.Fatalf("after SCIM deactivation the record is %s, want revoked: a deprovisioned user would keep a browser that skips their second factor", got)
	}
}

// TestErasureDeletesTrustedDevices proves erasure removes the record
// rather than revoking it. PseudonymizeUser purges the account's own PII but
// leaves child rows alone, so without an explicit delete a remembered browser
// would survive erasure holding an address and a user agent belonging to a
// person who asked to be deleted. That the credential was issued is already in
// the audit log, so deleting the row loses no record.
func TestErasureDeletesTrustedDevices(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, _, token := earnTrustedDevice(t, env, "td-erase")

	if got := deviceState(t, env, token); got != "live" {
		t.Fatalf("before erasure the record is %s, want live", got)
	}

	env.doJSON(env.login(h), http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)

	if got := deviceState(t, env, token); got != "gone" {
		t.Fatalf("after erasure the record is %s, want gone: a revoked row would still hold an address and a user agent belonging to a person who asked to be deleted", got)
	}
}

// TestTrustedDeviceSweepDeletesOnlyWhatHasExpired: the sweep
// removes records past their own expiry and nothing else. A live record stays,
// and so does a revoked one that has not expired: no cap of the sweep's
// decides when a record goes, its own lifetime does.
func TestTrustedDeviceSweepDeletesOnlyWhatHasExpired(t *testing.T) {
	var srv *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) { c.Auth.TrustedDeviceTTL = deviceTTL }, func(s *api.Server) { srv = s })
	ctx := context.Background()
	h := env.register("td-sweep")
	var userID string
	if err := env.st.Pool().QueryRow(ctx, `SELECT id::text FROM handles WHERE handle = $1`, h).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	live := insertTrustedDevice(t, env, userID)
	expired := insertTrustedDevice(t, env, userID)
	revoked := insertTrustedDevice(t, env, userID)
	revokedExpired := insertTrustedDevice(t, env, userID)
	for _, stmt := range []struct {
		sql, token string
	}{
		{`UPDATE trusted_devices SET expires_at = now() - interval '1 minute' WHERE token_sha256 = $1`, expired},
		{`UPDATE trusted_devices SET revoked_at = now() WHERE token_sha256 = $1`, revoked},
		{`UPDATE trusted_devices SET revoked_at = now() - interval '2 days', expires_at = now() - interval '1 minute' WHERE token_sha256 = $1`, revokedExpired},
	} {
		if _, err := env.st.Pool().Exec(ctx, stmt.sql, auth.HashToken(stmt.token)); err != nil {
			t.Fatal(err)
		}
	}

	n, err := srv.RunTrustedDeviceSweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The test database is shared, so another test's expired rows may go
	// too; what this test owns is its own three records.
	if n < 1 {
		t.Fatalf("the sweep deleted %d records, want at least this test's expired one", n)
	}
	for name, tc := range map[string]struct{ token, want string }{
		"live":                 {live, "live"},
		"expired":              {expired, "gone"},
		"revoked, not expired": {revoked, "revoked"},
		// A revoked record is kept to its own lifetime, and then it goes too.
		"revoked and expired": {revokedExpired, "gone"},
	} {
		if got := deviceState(t, env, tc.token); got != tc.want {
			t.Errorf("%s record after the sweep: %s, want %s", name, got, tc.want)
		}
	}
	// Nothing of this test's left to sweep: a second run leaves the rest.
	if _, err := srv.RunTrustedDeviceSweep(ctx); err != nil {
		t.Fatal(err)
	}
	if deviceState(t, env, live) != "live" || deviceState(t, env, revoked) != "revoked" {
		t.Error("a second sweep touched a record that had not expired")
	}
}

// TestTrustedDeviceSurvivesLogout: signing out ends the session
// and leaves the remembered browser alone, because surviving it is the point
// of the feature. A future reader who "fixes" logout to revoke it fails here.
func TestTrustedDeviceSurvivesLogout(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, id, token := earnTrustedDevice(t, env, "td-logout")
	out := env.do(env.login(h), http.MethodPost, "/api/v1/auth/logout", nil)
	_ = out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", out.StatusCode)
	}
	requireNoCookie(t, out.Cookies(), trustedDeviceCookie)
	requireRemembered(t, env, id, token, true)
}

// TestTrustedDeviceSurvivesSignOutEverywhereElse: "sign out
// everywhere else" is a session control. It must not also take away the
// remembered browsers, silently: that is the clear-all's job
// (DELETE /user/trusted-devices), which says so.
func TestTrustedDeviceSurvivesSignOutEverywhereElse(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, id, token := earnTrustedDevice(t, env, "td-elsewhere")
	env.login(h)
	env.doJSON(env.login(h), http.MethodDelete, "/api/v1/user/sessions", nil, nil, http.StatusNoContent)
	requireRemembered(t, env, id, token, true)
}

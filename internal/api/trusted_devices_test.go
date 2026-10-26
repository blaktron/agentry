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
//	deprovisioning takes the browser away    → TestTheMembersSeamDeprovisionTakesEverythingAway
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
	"encoding/json"
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
	"github.com/blaktron/agentry/internal/queue"
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
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/oidc/callback", nil)
	r.Header.Set("User-Agent", "td-test/1.0")
	return r
}

// deviceAudit is the audit rows of an action about an account, oldest first:
// who acted, and what the row says.
func deviceAudit(t *testing.T, env *testEnv, action string, userID uuid.UUID) (actors []string, details []map[string]any) {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT actor_kind || ':' || coalesce(actor_id::text, ''), detail FROM audit_events
		  WHERE action = $1 AND target_id = $2 ORDER BY occurred_at, id`, action, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var actor string
		var raw []byte
		if err := rows.Scan(&actor, &raw); err != nil {
			t.Fatal(err)
		}
		var d map[string]any
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		actors, details = append(actors, actor), append(details, d)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return actors, details
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
		"no second factor":                  {[]string{"pwd"}, time.Now()},
		"no amr at all":                     {nil, time.Now()},
		"no auth_time":                      {[]string{"otp"}, time.Time{}},
		"a factor answered long ago":        {[]string{"otp"}, time.Now().Add(-time.Hour)},
		"a factor answered ten minutes ago": {[]string{"otp"}, time.Now().Add(-10 * time.Minute)},
		"a factor answered six minutes ago": {[]string{"otp"}, time.Now().Add(-6 * time.Minute)},
		"an auth_time an hour ahead":        {[]string{"otp"}, time.Now().Add(time.Hour)},
		"an auth_time six minutes ahead":    {[]string{"otp"}, time.Now().Add(6 * time.Minute)},
	} {
		if _, _, err := env.srvObj.MintRememberedBrowser(signInRequest(), id, ev.amr, ev.authTime, nil); !errors.Is(err, api.ErrNoSecondFactor) {
			t.Errorf("%s: mint err = %v, want ErrNoSecondFactor", name, err)
		}
	}
	if n := countDevices(t, env, id); n != 0 {
		t.Fatalf("%d records minted without a fresh second factor", n)
	}

	// A factor answered four minutes ago, or an auth_time four minutes ahead
	// of this clock, is still fresh.
	for name, authTime := range map[string]time.Time{
		"four minutes ago":   time.Now().Add(-4 * time.Minute),
		"four minutes ahead": time.Now().Add(4 * time.Minute),
	} {
		fresh := userIDOf(t, env, env.register("td-win"+strings.ReplaceAll(name, " ", "")))
		if _, _, err := env.srvObj.MintRememberedBrowser(signInRequest(), fresh, []string{"pwd", "otp"}, authTime, nil); err != nil {
			t.Errorf("a factor answered %s earned no remembered browser: %v", name, err)
		}
	}

	// An account that is not active is remembered nowhere, and a record it
	// held before is no longer honoured.
	_, suspended, suspendedToken := earnTrustedDevice(t, env, "td-suspended")
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE users SET state = 'suspended' WHERE id = $1`, suspended); err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.srvObj.MintRememberedBrowser(signInRequest(), suspended, []string{"otp"}, time.Now(), nil); err == nil || errors.Is(err, api.ErrNoSecondFactor) {
		t.Errorf("a suspended account's mint err = %v, want a refusal of the account", err)
	}
	if n := countDevices(t, env, suspended); n != 1 {
		t.Errorf("%d records for a suspended account after a refused mint, want the 1 it had", n)
	}
	requireRemembered(t, env, suspended, suspendedToken, false)

	_, other, token := earnTrustedDevice(t, env, "td-earn2")
	requireRemembered(t, env, other, token, true)
	// The mint is audited as the person, with what the sign-in said.
	actors, details := deviceAudit(t, env, "user.trusted_device_add", other)
	if len(actors) != 1 || actors[0] != "user:"+other.String() || details[0]["via"] != "test" {
		t.Fatalf("user.trusted_device_add rows: %v %v, want one by the person with the sign-in's detail", actors, details)
	}
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
		// user, when set, is the account asking instead of the owner.
		user uuid.UUID
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
		{
			name:  "an account that does not exist",
			token: token,
			user:  uuid.New(),
		},
		{
			name:  "an account that is not active",
			token: token,
			kill: func(t *testing.T) {
				// A live record again, behind an account that is not.
				if _, err := env.st.Pool().Exec(ctx,
					`UPDATE trusted_devices SET revoked_at = NULL, expires_at = now() + interval '1 hour'
					  WHERE token_sha256 = $1`, auth.HashToken(token)); err != nil {
					t.Fatal(err)
				}
				requireRemembered(t, env, id, token, true)
				if _, err := env.st.Pool().Exec(ctx, `UPDATE users SET state = 'suspended' WHERE id = $1`, id); err != nil {
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
			who := id
			if tc.user != uuid.Nil {
				who = tc.user
			}
			requireRemembered(t, env, who, tc.token, false)
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
	// The stored lifetime is the configured one, from now.
	if left := time.Until(before.expiresAt); left < deviceTTL-5*time.Minute || left > deviceTTL+time.Minute {
		t.Fatalf("the record expires in %s, want the configured %s", left, deviceTTL)
	}
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
	// The use is audited as the person, naming the record; a detail the
	// caller passes cannot rename the record.
	if _, err := env.srvObj.UseRememberedBrowser(signInRequest(), id, token, map[string]any{"via": "second", "device": "forged"}); err != nil {
		t.Fatal(err)
	}
	actors, details := deviceAudit(t, env, "user.trusted_device_use", id)
	if len(actors) != 2 {
		t.Fatalf("%d user.trusted_device_use rows after two uses, want 2", len(actors))
	}
	for i, via := range []string{"test", "second"} {
		if actors[i] != "user:"+id.String() || details[i]["device"] != before.id.String() || details[i]["via"] != via {
			t.Fatalf("use %d audit row: %s %v, want the person, record %s and via %q", i+1, actors[i], details[i], before.id, via)
		}
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

	// The record describes the browser to its owner: the address and user
	// agent of the sign-in that earned it.
	var ip, agent string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT coalesce(host(ip), ''), coalesce(user_agent, '') FROM trusted_devices WHERE id = $1`, row.id).Scan(&ip, &agent); err != nil {
		t.Fatal(err)
	}
	if ip != "192.0.2.1" || agent != "td-test/1.0" {
		t.Fatalf("the record holds address %q and user agent %q, want the sign-in's", ip, agent)
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
// trust away rather than grant it: what deprovisioning or erasure does to
// one is the thing under test.
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
	expiringSoon := insertTrustedDevice(t, env, userID)
	for _, stmt := range []struct {
		sql, token string
	}{
		{`UPDATE trusted_devices SET expires_at = now() - interval '1 minute' WHERE token_sha256 = $1`, expired},
		{`UPDATE trusted_devices SET revoked_at = now() WHERE token_sha256 = $1`, revoked},
		{`UPDATE trusted_devices SET revoked_at = now() - interval '2 days', expires_at = now() - interval '1 minute' WHERE token_sha256 = $1`, revokedExpired},
		{`UPDATE trusted_devices SET expires_at = now() + interval '1 hour' WHERE token_sha256 = $1`, expiringSoon},
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
		// A record is kept to the second of its own expiry, not a day short.
		"expiring in an hour": {expiringSoon, "live"},
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
	session := env.login(h)
	out := env.do(session, http.MethodPost, "/api/v1/auth/logout", nil)
	_ = out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", out.StatusCode)
	}
	requireNoCookie(t, out.Cookies(), trustedDeviceCookie)
	// What logout does end is the session, and its cookie.
	requireClearedCookie(t, out.Cookies(), "agentry_session", false)
	after := env.do(session, http.MethodGet, "/api/v1/user", nil)
	_ = after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the signed-out session: %d, want 401", after.StatusCode)
	}
	requireRemembered(t, env, id, token, true)
}

// TestTrustedDeviceSurvivesSignOutEverywhereElse: "sign out
// everywhere else" is a session control. It must not also take away the
// remembered browsers, silently: that is the clear-all's job
// (DELETE /user/trusted-devices), which says so.
func TestTrustedDeviceSurvivesSignOutEverywhereElse(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, id, token := earnTrustedDevice(t, env, "td-elsewhere")
	elsewhere := env.login(h)
	here := env.login(h)
	env.doJSON(here, http.MethodDelete, "/api/v1/user/sessions", nil, nil, http.StatusNoContent)
	// The session control ends the other browser's session and spares this one.
	gone := env.do(elsewhere, http.MethodGet, "/api/v1/user", nil)
	_ = gone.Body.Close()
	kept := env.do(here, http.MethodGet, "/api/v1/user", nil)
	_ = kept.Body.Close()
	if gone.StatusCode != http.StatusUnauthorized || kept.StatusCode != http.StatusOK {
		t.Fatalf("after signing out everywhere else: the other session %d (want 401), this one %d (want 200)", gone.StatusCode, kept.StatusCode)
	}
	requireRemembered(t, env, id, token, true)
}

// TestTrustedDeviceSweepRunsOnTheQueue: the worker role runs the sweep as a
// job: an enqueued sweep removes the expired record and leaves the live one.
func TestTrustedDeviceSweepRunsOnTheQueue(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	ctx := context.Background()
	userID := userIDOf(t, env, env.register("td-queue")).String()
	live := insertTrustedDevice(t, env, userID)
	expired := insertTrustedDevice(t, env, userID)
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE trusted_devices SET expires_at = now() - interval '1 minute' WHERE token_sha256 = $1`, auth.HashToken(expired)); err != nil {
		t.Fatal(err)
	}
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	env.srvObj.RegisterQueueHandlers(q)
	if _, err := q.Enqueue(ctx, api.JobTrustedDeviceSweep, "core", struct{}{}); err != nil {
		t.Fatal(err)
	}
	q.Drain(ctx, "core")
	if got := deviceState(t, env, expired); got != "gone" {
		t.Errorf("the expired record after the queued sweep: %s, want gone", got)
	}
	if got := deviceState(t, env, live); got != "live" {
		t.Errorf("the live record after the queued sweep: %s, want live", got)
	}
}

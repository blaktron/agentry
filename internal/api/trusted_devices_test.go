package api_test

// Trusted devices (plan trusted-devices.md, agentry#461): a browser that
// answered the second factor may be remembered, so a later password sign-in
// from it is not asked for the code.
//
// These tests are written to be mutation-checked, which is what ARCHITECTURE §9
// requires of a new invariant row before the row is written. Each names the
// control it proves, so breaking the control breaks a named test:
//
//	mint only after the factor was answered  → TestTrustedDeviceIsEarnedOnlyByAnsweringTheSecondFactor
//	the opt-in defaults to off               → TestTrustedDeviceIsNotMintedUnlessAskedFor
//	the cookie is never itself a credential  → TestTrustedDeviceCookieAuthenticatesNothingOnItsOwn
//	the record is bound to its owner in SQL  → TestTrustedDeviceIsBoundToItsOwner
//	expired / revoked / unknown are refused  → TestTrustedDeviceRefusesADeadCredential
//	a store that cannot be read fails closed → TestTrustedDeviceStoreFailureDemandsTheCode
//	the lifetime is absolute, not sliding    → TestTrustedDeviceExpiryIsAbsoluteNotSliding
//	only the hash is stored                  → TestTrustedDeviceStoresOnlyTheHash
//	the cookie carries its attributes        → TestTrustedDeviceCookieAttributes
//	deactivation takes the browser away      → TestSCIMDeactivationRevokesTrustedDevices
//	erasure removes the row, not just trust  → TestErasureDeletesTrustedDevices
//
// All eleven were mutation-checked on 2026-09-22 before this file was
// committed, with twelve mutations between them — the dead-credential control
// takes two, one for expiry and one for revocation. Each control was broken in
// turn and the named test failed; then the control was restored and the suite
// went green again. Two results are worth keeping, because each is a trap.
//
// Deleting "AND user_id = $2" from the lookup does NOT prove the owner scoping.
// The generated Go still passes two arguments, so pgx rejects the query, the
// lookup fails closed, and TestTrustedDeviceIsBoundToItsOwner passes for the
// wrong reason. Making the scoping vacuous while keeping the argument count
// valid — "AND (user_id = $2 OR user_id IS NOT NULL)" — is the mutation that
// actually exercises it, and the test catches that one with "status 200, want
// 401".
//
// And the first pass here claimed eight controls checked against a list of
// nine: "the cookie is never itself a credential" and "only the hash is stored"
// were listed and never broken, which a review caught. Both are checked now —
// disabling the password comparison, and storing the token in the clear — and
// each fails its named test. The number is written out rather than implied so
// that a list and a count cannot drift apart again unnoticed.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
)

const trustedDeviceCookie = "agentry_trusted_device"

// deviceTTL is the lifetime this file's server is configured with. It is
// deliberately not the 30-day default: a cookie whose Max-Age matches a
// distinctive value proves the server read the configuration rather than
// hard-coding the ceiling. The default and the ceiling are config's own tests.
const deviceTTL = 100 * time.Hour

// newTrustedDeviceEnv builds a server whose trusted-device lifetime is
// distinctive, so the issued cookie's Max-Age is checkable.
func newTrustedDeviceEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.TrustedDeviceTTL = deviceTTL
	})
}

// enrolTOTP turns the second factor on for a registered account and returns its
// secret so a test can compute live codes. It goes through the real setup and
// verify endpoints rather than writing the row, because what is under test is
// what a sign-in does once the factor exists.
func enrolTOTP(t *testing.T, env *testEnv, handle string) string {
	t.Helper()
	sess := env.login(handle)
	var setup struct {
		Secret string `json:"secret"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/setup", nil, &setup, http.StatusOK)
	if setup.Secret == "" {
		t.Fatal("TOTP setup returned no secret")
	}
	code, err := totpCode(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/verify",
		map[string]any{"code": code}, nil, http.StatusNoContent)
	return setup.Secret
}

// earnTrustedDevice enrols the second factor on a fresh account and signs in
// answering it with the opt-in set, returning the handle, the TOTP secret and
// the issued cookie. Every test here needs exactly that, and needing it is the
// point: the credential cannot be obtained any other way.
func earnTrustedDevice(t *testing.T, env *testEnv, handle string) (string, string, caller) {
	t.Helper()
	h := env.register(handle)
	secret := enrolTOTP(t, env, h)
	code, err := totpCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	c, cookies := env.loginWith(h, loginOpts{totpCode: code, rememberDevice: true})
	if c.device == "" {
		t.Fatal("answering the second factor with the opt-in set issued no trusted-device cookie")
	}
	requireSetCookie(t, cookies, trustedDeviceCookie, int(deviceTTL.Seconds()), false)
	return h, secret, c
}

// deviceRow is the stored record behind a handle's most recent trusted device.
// It reads the table directly because what a test needs to know is what was
// persisted, not what the API said it persisted.
type deviceRow struct {
	id         uuid.UUID
	tokenHash  []byte
	expiresAt  time.Time
	lastSeenAt time.Time
	revokedAt  *time.Time
}

func fetchDeviceRow(t *testing.T, env *testEnv, handle string) deviceRow {
	t.Helper()
	var d deviceRow
	err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id, token_sha256, expires_at, last_seen_at, revoked_at
		   FROM trusted_devices
		  WHERE user_id = (SELECT id FROM handles WHERE handle = $1)
		  ORDER BY created_at DESC, id DESC LIMIT 1`, handle).
		Scan(&d.id, &d.tokenHash, &d.expiresAt, &d.lastSeenAt, &d.revokedAt)
	if err != nil {
		t.Fatalf("no trusted_devices row for %s: %v", handle, err)
	}
	return d
}

// requireRefused proves a sign-in was turned away: a 401 and no session. It is
// deliberately not named for the reason, because the point of several of these
// cases is that a dead credential, a missing one and a wrong password are all
// refused the same way, and nothing about the refusal says which happened.
func requireRefused(t *testing.T, res *http.Response) {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" && ck.Value != "" && ck.MaxAge >= 0 {
			t.Fatal("a session was issued on a sign-in that should have been refused")
		}
	}
}

func passwordOnly(handle string) map[string]any {
	return map[string]any{"login": handle, "password": "hunter2hunter2"}
}

// TestTrustedDeviceIsEarnedOnlyByAnsweringTheSecondFactor is the positive path
// and the mint rule at once: answering the code with the opt-in set issues the
// cookie, and a later sign-in presenting it is not asked for the code.
func TestTrustedDeviceIsEarnedOnlyByAnsweringTheSecondFactor(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, _, c := earnTrustedDevice(t, env, "td-earn")

	// A later sign-in presents the cookie and no code, and is let through.
	res := env.do(caller{device: c.device}, http.MethodPost, "/api/v1/auth/login", passwordOnly(h))
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a sign-in from a trusted device was refused: %d", res.StatusCode)
	}

	// The skip did not mint a second credential, which is what keeps the
	// lifetime absolute: one browser earns one record, and using it does not
	// produce another or extend the first.
	requireNoCookie(t, res.Cookies(), trustedDeviceCookie)
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM trusted_devices WHERE user_id = (SELECT id FROM handles WHERE handle = $1)`, h).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d trusted-device rows after one earn and one skip, want exactly 1", n)
	}
}

// TestTrustedDeviceIsNotMintedUnlessAskedFor proves the opt-in defaults to off.
// A correct code with no rememberDevice must leave nothing behind, and the next
// sign-in must be asked again.
func TestTrustedDeviceIsNotMintedUnlessAskedFor(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h := env.register("td-optin")
	secret := enrolTOTP(t, env, h)

	code, err := totpCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	_, cookies := env.loginWith(h, loginOpts{totpCode: code})
	requireNoCookie(t, cookies, trustedDeviceCookie)

	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM trusted_devices WHERE user_id = (SELECT id FROM handles WHERE handle = $1)`, h).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d trusted-device rows recorded for a sign-in that never asked for one", n)
	}

	res := env.do(anonymous, http.MethodPost, "/api/v1/auth/login", passwordOnly(h))
	requireRefused(t, res)
}

// TestTrustedDeviceCookieAuthenticatesNothingOnItsOwn proves the credential is
// narrow. It stands in for the second factor at sign-in and grants nothing
// else: no session, no scope, no access to an authenticated route. Without
// this, "skips the second factor" could quietly become "is a session".
func TestTrustedDeviceCookieAuthenticatesNothingOnItsOwn(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, _, c := earnTrustedDevice(t, env, "td-narrow")

	// The cookie alone is not a credential: an authenticated route refuses it.
	env.doJSON(caller{device: c.device}, http.MethodGet, "/api/v1/user/sessions", nil, nil, http.StatusUnauthorized)

	// And it does not survive a wrong password. The factor is skipped only
	// after the password is verified, never instead of verifying it.
	res := env.do(caller{device: c.device}, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"login": h, "password": "wrong-password"})
	requireRefused(t, res)
}

// TestTrustedDeviceIsBoundToItsOwner proves the lookup is scoped by user_id in
// SQL rather than by a branch above it: one user's cookie is worth nothing to
// another, and the refusal is the same one an unknown cookie gets.
func TestTrustedDeviceIsBoundToItsOwner(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, _, owner := earnTrustedDevice(t, env, "td-owner")

	other := env.register("td-other")
	enrolTOTP(t, env, other)

	// The other account presents the owner's cookie and no code. It must be
	// asked for its own, and the answer must not distinguish "that is someone
	// else's record" from "that record does not exist".
	res := env.do(caller{device: owner.device}, http.MethodPost, "/api/v1/auth/login", passwordOnly(other))
	requireRefused(t, res)
}

// TestTrustedDeviceRefusesADeadCredential walks every way a presented cookie
// can fail to be live. Each must demand the code, and each must be refused the
// same way as an absent one.
func TestTrustedDeviceRefusesADeadCredential(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	ctx := context.Background()
	h, _, c := earnTrustedDevice(t, env, "td-dead")

	cases := []struct {
		name string
		// cookie is what the browser presents; empty means it presents none.
		cookie string
		// kill mutates the stored row before the sign-in, for the cases where
		// the cookie is genuine but the record behind it is not live.
		kill func(t *testing.T)
	}{
		{name: "no cookie at all"},
		{name: "a value that was never issued", cookie: "agyd_neverissued"},
		{name: "another credential's prefix", cookie: "agys_notasession"},
		{
			name:   "revoked",
			cookie: c.device,
			kill: func(t *testing.T) {
				if _, err := env.st.Pool().Exec(ctx,
					`UPDATE trusted_devices SET revoked_at = now() WHERE token_sha256 = $1`,
					auth.HashToken(c.device)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "expired",
			cookie: c.device,
			kill: func(t *testing.T) {
				// Undo the revoke first, so this case fails for its own
				// reason and not because an earlier one still applies.
				if _, err := env.st.Pool().Exec(ctx,
					`UPDATE trusted_devices SET revoked_at = NULL, expires_at = now() - interval '1 second'
					  WHERE token_sha256 = $1`, auth.HashToken(c.device)); err != nil {
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
			res := env.do(caller{device: tc.cookie}, http.MethodPost, "/api/v1/auth/login", passwordOnly(h))
			requireRefused(t, res)
		})
	}
}

// TestTrustedDeviceStoreFailureDemandsTheCode is the fail-closed control, and
// the one that matters most: an outage must never be the way past a factor.
// The table is renamed out from under the lookup so the query errors with
// something other than "no rows", and the sign-in must demand the code rather
// than skip it or answer 500.
func TestTrustedDeviceStoreFailureDemandsTheCode(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	ctx := context.Background()
	h, secret, c := earnTrustedDevice(t, env, "td-failclosed")

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

	// The control: with the store unreadable, the second factor is demanded.
	// Skipping here would make an outage a bypass; a 500 would make it an
	// outage. Demanding the code is the only acceptable answer.
	res := env.do(caller{device: c.device}, http.MethodPost, "/api/v1/auth/login", passwordOnly(h))
	requireRefused(t, res)

	// And the sign-in still works once the store is back and the code is
	// supplied, so the failure is contained to the skip and does not take the
	// factor down with it.
	restore()
	code, err := totpCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	env.loginWith(h, loginOpts{totpCode: code})
}

// TestTrustedDeviceExpiryIsAbsoluteNotSliding proves plan decision D9. Using
// the credential refreshes last_seen_at and must not move expires_at, so a
// stolen cookie does not become immortal by being used and a person who signs
// in daily is still asked again on day thirty.
func TestTrustedDeviceExpiryIsAbsoluteNotSliding(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, _, c := earnTrustedDevice(t, env, "td-absolute")

	before := fetchDeviceRow(t, env, h)

	// The skip is asked to remember the browser as well. It must not: trust is
	// earned by answering the factor, and letting a skip re-mint would turn an
	// absolute lifetime into a sliding one that never expires for as long as
	// the cookie is used at least once every thirty days.
	body := passwordOnly(h)
	body["rememberDevice"] = true
	res := env.do(caller{device: c.device}, http.MethodPost, "/api/v1/auth/login", body)
	requireNoCookie(t, res.Cookies(), trustedDeviceCookie)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a sign-in from a trusted device was refused: %d", res.StatusCode)
	}

	after := fetchDeviceRow(t, env, h)
	if !after.expiresAt.Equal(before.expiresAt) {
		t.Fatalf("using the credential moved its expiry from %s to %s: the lifetime is sliding, and D9 says absolute",
			before.expiresAt.Format(time.RFC3339Nano), after.expiresAt.Format(time.RFC3339Nano))
	}
	if !after.lastSeenAt.After(before.lastSeenAt) {
		t.Fatalf("using the credential did not refresh last_seen_at (still %s): the row cannot describe when it was last used",
			after.lastSeenAt.Format(time.RFC3339Nano))
	}
	if after.id != before.id {
		t.Fatalf("using the credential replaced the record (%s → %s): a skip must not mint", before.id, after.id)
	}
	// Neither read may find the row revoked: use is not revocation, and a
	// record that came back revoked here would make every assertion above
	// about a different row than the one that was issued.
	if before.revokedAt != nil || after.revokedAt != nil {
		t.Fatalf("the record is revoked (before=%v after=%v) while still being honoured", before.revokedAt, after.revokedAt)
	}
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM trusted_devices WHERE user_id = (SELECT id FROM handles WHERE handle = $1)`, h).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d records after one earn and one skip that asked to be remembered, want exactly 1", n)
	}
}

// TestTrustedDeviceStoresOnlyTheHash proves the token is not recoverable from
// the database: only its SHA-256 is stored, so reading the table yields no
// credential. This is the rule every other token in the estate follows.
func TestTrustedDeviceStoresOnlyTheHash(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	h, _, c := earnTrustedDevice(t, env, "td-hash")

	row := fetchDeviceRow(t, env, h)
	want := auth.HashToken(c.device)
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
	if strings.Contains(whole, c.device) {
		t.Fatal("the issued token is recoverable from the stored row")
	}
}

// TestTrustedDeviceCookieAttributes proves the cookie is issued with the
// attributes every cookie this server carries, and a Max-Age that comes from
// the configuration rather than from a literal. HttpOnly is the load-bearing
// one: DEV-012 forbids auth material reachable by browser JavaScript, and
// nothing in internal/api asserted a cookie being *set* before agentry#461.
func TestTrustedDeviceCookieAttributes(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, _, c := earnTrustedDevice(t, env, "td-attrs")

	if !strings.HasPrefix(c.device, auth.TrustedDevicePrefix) {
		t.Fatalf("the issued token has prefix %q, want %q so a leaked string identifies itself",
			c.device[:min(len(c.device), 8)], auth.TrustedDevicePrefix)
	}
	if len(c.device) <= len(auth.TrustedDevicePrefix) {
		t.Fatalf("the issued token is %d characters: too short to carry 32 bytes of entropy", len(c.device))
	}
}

// insertTrustedDevice records one directly, the way insertSession and insertPAT
// do for the credentials they stand in for. It exists for the paths that take
// trust away rather than grant it: a SCIM-provisioned account has no password
// and so cannot earn a record by signing in, and what deactivation does to one
// is the thing under test.
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

// TestSCIMDeactivationRevokesTrustedDevices proves §12.5 deactivation takes the
// remembered browser away as well as the sessions.
//
// Deactivation drops the membership, revokes the org-bound PATs and kills the
// sessions, but it deliberately leaves the account's password and state alone,
// because the person may exist outside the organization. So a surviving record
// would let a deprovisioned user sign straight back in and be asked for *less*
// than before them — the second factor skipped — which is the opposite of what
// scimDeactivate promises. TestTrustedDeviceRefusesADeadCredential already
// proves a revoked record is refused at sign-in; this proves deactivation is
// what revokes it, and the two together are the property.
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

// TestErasureDeletesTrustedDevices proves §12.7 erasure removes the record
// rather than revoking it. PseudonymizeUser purges the account's own PII but
// leaves child rows alone, so without an explicit delete a remembered browser
// would survive erasure holding an address and a user agent belonging to a
// person who asked to be deleted. That the credential was issued is already in
// the audit log, so deleting the row loses no record.
func TestErasureDeletesTrustedDevices(t *testing.T) {
	env := newTrustedDeviceEnv(t)
	_, _, c := earnTrustedDevice(t, env, "td-erase")

	if got := deviceState(t, env, c.device); got != "live" {
		t.Fatalf("before erasure the record is %s, want live", got)
	}

	env.doJSON(c, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)

	if got := deviceState(t, env, c.device); got != "gone" {
		t.Fatalf("after erasure the record is %s, want gone: a revoked row would still hold an address and a user agent belonging to a person who asked to be deleted", got)
	}
}

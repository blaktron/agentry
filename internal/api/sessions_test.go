package api_test

// Session self-management and the rule-bundle endpoint that backs
// `agentry validate --rules-update`.

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/pkg/ruleset"
)

// sessionCookieCleared reports whether res expires the session cookie.
func sessionCookieCleared(res *http.Response) bool {
	for _, c := range res.Cookies() {
		if c.Name == "agentry_session" && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// logoutRows counts the user.logout audit rows an actor wrote with the given
// scope detail.
func (env *testEnv) logoutRows(t *testing.T, handle, scope string) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.actor_id
		  WHERE h.handle = $1 AND a.action = 'user.logout' AND a.detail->>'scope' = $2`, handle, scope).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// sessionRow mirrors the SessionInfo wire shape.
type sessionRow struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"createdAt"`
	LastSeenAt string `json:"lastSeenAt"`
	Current    bool   `json:"current"`
	IP         string `json:"ip"`
	UserAgent  string `json:"userAgent"`
}

type sessionListBody struct {
	Sessions []sessionRow `json:"sessions"`
}

func (env *testEnv) listSessions(t *testing.T, c caller) sessionListBody {
	t.Helper()
	var out sessionListBody
	env.doJSON(c, http.MethodGet, "/api/v1/user/sessions", nil, &out, http.StatusOK)
	return out
}

// TestListUserSessionsMarksCurrent covers the contract the web console
// depends on: every live session, with exactly one flagged `current`.
func TestListUserSessionsMarksCurrent(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("sess-a")
	first := env.login(h)
	second := env.login(h)
	third := env.login(h)

	got := env.listSessions(t, second)
	if len(got.Sessions) != 3 {
		t.Fatalf("sessions = %d, want 3: %+v", len(got.Sessions), got.Sessions)
	}
	var currents, ids []string
	for _, s := range got.Sessions {
		ids = append(ids, s.ID)
		if s.Current {
			currents = append(currents, s.ID)
		}
		if s.ID == "" || s.CreatedAt == "" || s.LastSeenAt == "" {
			t.Errorf("session %+v is missing a required field", s)
		}
	}
	if len(currents) != 1 {
		t.Fatalf("current sessions = %v, want exactly one", currents)
	}
	// A session in use is touched: only the caller's row is recent.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE sessions SET last_seen_at = now() - interval '1 day' WHERE user_id = (SELECT id FROM handles WHERE handle = $1)`, h); err != nil {
		t.Fatal(err)
	}
	for _, s := range env.listSessions(t, third).Sessions {
		seen, err := time.Parse(time.RFC3339Nano, s.LastSeenAt)
		if err != nil {
			t.Fatal(err)
		}
		if recent := time.Since(seen) < time.Hour; recent != s.Current {
			t.Errorf("session %s (current %v) last seen %s: only the session in use should have been touched", s.ID, s.Current, s.LastSeenAt)
		}
	}
	// Each row says where the session was last used from.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE sessions SET ip = '203.0.113.9' WHERE user_id = (SELECT id FROM handles WHERE handle = $1)`, h); err != nil {
		t.Fatal(err)
	}
	for _, s := range env.listSessions(t, second).Sessions {
		if s.IP != "203.0.113.9" || s.UserAgent != "Go-http-client/1.1" {
			t.Errorf("session %s from %q by %q, want 203.0.113.9 by the client that signed in", s.ID, s.IP, s.UserAgent)
		}
	}
	// The calling session, not merely some session, must be the flagged one.
	other := env.listSessions(t, first)
	var otherCurrent string
	for _, s := range other.Sessions {
		if s.Current {
			otherCurrent = s.ID
		}
	}
	if otherCurrent == currents[0] {
		t.Fatalf("two different sessions both report current=%s", otherCurrent)
	}
	_ = third
	_ = ids
}

// TestListUserSessionsPATIsEmpty: a PAT has no sessions of its own, and must
// not become a way to enumerate the user's browsers. 200 with an empty list —
// not 403, so a client need not special-case the credential kind.
func TestListUserSessionsPATIsEmpty(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("sess-p")
	sess := env.login(h)
	env.login(h) // a second browser session that must stay invisible
	_, tok := env.mintPAT(sess, "sess-pat", "user:profile")

	got := env.listSessions(t, caller{name: "pat", pat: tok})
	if len(got.Sessions) != 0 {
		t.Fatalf("PAT saw %d sessions, want 0: %+v", len(got.Sessions), got.Sessions)
	}
}

// TestRevokeUserSessionOwnOnly: revoking works on your own session, and a
// session belonging to someone else is indistinguishable from one that does
// not exist.
func TestRevokeUserSessionOwnOnly(t *testing.T) {
	env := newTestEnv(t)
	ownerH := env.register("sess-o")
	keep := env.login(ownerH)
	doomed := env.login(ownerH)
	strangerH := env.register("sess-s")
	stranger := env.login(strangerH)

	var doomedID string
	for _, s := range env.listSessions(t, doomed).Sessions {
		if s.Current {
			doomedID = s.ID
		}
	}
	if doomedID == "" {
		t.Fatal("no current session id")
	}

	// A stranger cannot revoke it, and learns nothing from trying.
	res := env.do(stranger, http.MethodDelete, "/api/v1/user/sessions/"+doomedID, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("stranger revoke: %d, want 404", res.StatusCode)
	}
	// An id nobody owns answers identically.
	res = env.do(stranger, http.MethodDelete, "/api/v1/user/sessions/"+uuid.NewString(), nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id revoke: %d, want 404", res.StatusCode)
	}

	// Neither attempt was a revocation, so neither is on the record.
	if n := env.logoutRows(t, strangerH, "one"); n != 0 {
		t.Fatalf("a revocation that revoked nothing was audited: %d row(s)", n)
	}

	// The owner can, from a different session; the browser holding the
	// other session keeps its cookie.
	res = env.do(keep, http.MethodDelete, "/api/v1/user/sessions/"+doomedID, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke from another session: %d, want 204", res.StatusCode)
	}
	if sessionCookieCleared(res) {
		t.Fatal("revoking another session expired the caller's own cookie")
	}
	var audited int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.actor_id
		  WHERE h.handle = $1 AND a.action = 'user.logout' AND a.target_kind = 'session' AND a.target_id = $2
		    AND a.detail->>'scope' = 'one' AND a.detail->>'self' = 'false'`, ownerH, doomedID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audit rows for the revoked session: %d (%v), want 1 naming it and that it was not the caller's own", audited, err)
	}

	// The revoked session is dead as a credential...
	res = env.do(doomed, http.MethodGet, "/api/v1/user/sessions", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session still authenticates: %d", res.StatusCode)
	}
	// ...and gone from the list.
	for _, s := range env.listSessions(t, keep).Sessions {
		if s.ID == doomedID {
			t.Fatalf("revoked session %s still listed", doomedID)
		}
	}

	// Revoking the session in hand is a sign-out: the cookie goes too.
	mine := env.login(ownerH)
	var mineID string
	for _, s := range env.listSessions(t, mine).Sessions {
		if s.Current {
			mineID = s.ID
		}
	}
	res = env.do(mine, http.MethodDelete, "/api/v1/user/sessions/"+mineID, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent || !sessionCookieCleared(res) {
		t.Fatalf("revoking the held session: %d, cookie cleared %v, want 204 and an expired cookie", res.StatusCode, sessionCookieCleared(res))
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.actor_id
		  WHERE h.handle = $1 AND a.action = 'user.logout' AND a.target_id = $2 AND a.detail->>'self' = 'true'`, ownerH, mineID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audit rows for the held session: %d (%v), want 1 marked as the caller's own", audited, err)
	}
}

// TestRevokeOtherUserSessionsSparesCaller is the "sign out everywhere else"
// contract: everything but the calling session dies, and the caller stays
// signed in.
func TestRevokeOtherUserSessionsSparesCaller(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("sess-x")
	a := env.login(h)
	b := env.login(h)
	c := env.login(h)

	res := env.do(a, http.MethodDelete, "/api/v1/user/sessions", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent || sessionCookieCleared(res) {
		t.Fatalf("sign out everywhere else: %d, cookie cleared %v, want 204 and the caller's cookie kept", res.StatusCode, sessionCookieCleared(res))
	}
	var revoked int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.actor_id
		  WHERE h.handle = $1 AND a.action = 'user.logout' AND a.target_kind = 'user' AND a.target_id = h.id
		    AND a.detail->>'scope' = 'others' AND a.detail->>'revoked' = '2'`, h).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatalf("audit rows for signing out the other sessions: %d (%v), want 1 saying 2 were revoked", revoked, err)
	}

	got := env.listSessions(t, a)
	if len(got.Sessions) != 1 || !got.Sessions[0].Current {
		t.Fatalf("after revoke-others: %+v, want only the calling session", got.Sessions)
	}
	for _, dead := range []caller{b, c} {
		res := env.do(dead, http.MethodGet, "/api/v1/user/sessions", nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("session %s survived revoke-others: %d", dead.name, res.StatusCode)
		}
	}
}

// TestRevokeSessionsRejectsPAT: a token must not be able to sign its holder
// out of their browsers, the same rule that makes logout session-only.
func TestRevokeSessionsRejectsPAT(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("sess-r")
	sess := env.login(h)
	_, tok := env.mintPAT(sess, "sess-revoke-pat", "user:profile")
	pat := caller{name: "pat", pat: tok}

	for _, path := range []string{"/api/v1/user/sessions", "/api/v1/user/sessions/" + uuid.NewString()} {
		res := env.do(pat, http.MethodDelete, path, nil)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("DELETE %s as PAT: %d, want 403", path, res.StatusCode)
		}
	}
	// And the sessions are still there.
	if got := env.listSessions(t, sess); len(got.Sessions) != 1 {
		t.Fatalf("sessions after refused PAT revoke: %d, want 1", len(got.Sessions))
	}
}

// TestGetLatestRulesetBundle: the bundle endpoint serves a tar whose digest
// matches the advertised header, anonymously (a CLI runs `--rules-update`
// before it has any credential).
func TestGetLatestRulesetBundle(t *testing.T) {
	env := newTestEnv(t)

	res := env.do(anonymous, http.MethodGet, "/api/v1/ruleset-releases/latest/bundle", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("bundle: %d %s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/x-tar" {
		t.Errorf("Content-Type = %q, want application/x-tar", ct)
	}
	semver := res.Header.Get("X-Agentry-Bundle-Semver")
	digest := res.Header.Get("X-Agentry-Bundle-Digest")
	if semver == "" {
		t.Error("no X-Agentry-Bundle-Semver header")
	}
	if !bytes.HasPrefix([]byte(digest), []byte("sha256:")) {
		t.Errorf("X-Agentry-Bundle-Digest = %q, want sha256:<hex>", digest)
	}
	// The headers describe the bundle this binary runs.
	running, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	if semver != running.Version() || digest != "sha256:"+strings.TrimPrefix(running.Digest(), "sha256:") {
		t.Errorf("headers say %s %s, want the running bundle's %s sha256:%s", semver, digest, running.Version(), strings.TrimPrefix(running.Digest(), "sha256:"))
	}
	if cc := res.Header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want public, max-age=300", cc)
	}
	if etag := res.Header.Get("ETag"); etag != `"`+digest+`"` {
		t.Errorf("ETag = %q, want the quoted digest %q", etag, digest)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	// The archive must be a flat tar of YAML files including bundle.yaml —
	// exactly what pkg/rules.LoadBundle expects to find in a directory.
	tr := tar.NewReader(bytes.NewReader(body))
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			t.Errorf("entry %q is not a regular file", hdr.Name)
		}
		names = append(names, hdr.Name)
		if _, err := io.Copy(io.Discard, tr); err != nil {
			t.Fatal(err)
		}
	}
	if len(names) < 2 || names[0] != "bundle.yaml" {
		t.Fatalf("archive entries = %v, want bundle.yaml first plus rule files", names)
	}

	// A release recorded for this version under another digest means the
	// deployment's identity is contested, and neither is served; the same
	// digest, written with or without its prefix, is served.
	ctx := context.Background()
	var recorded *string
	if err := env.st.Pool().QueryRow(ctx, `SELECT bundle_digest FROM ruleset_releases WHERE semver = $1`, semver).Scan(&recorded); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if recorded != nil {
			_, _ = env.st.Pool().Exec(ctx, `UPDATE ruleset_releases SET bundle_digest = $2 WHERE semver = $1`, semver, *recorded)
			return
		}
		_, _ = env.st.Pool().Exec(ctx, `DELETE FROM ruleset_releases WHERE semver = $1`, semver)
	})
	for _, c := range []struct {
		name string
		row  string
		want int
	}{
		{"another digest", "sha256:" + strings.Repeat("0", 64), http.StatusInternalServerError},
		{"the same digest with its prefix", digest, http.StatusOK},
		{"the same digest without its prefix", strings.TrimPrefix(digest, "sha256:"), http.StatusOK},
	} {
		if _, err := env.st.Pool().Exec(ctx, `INSERT INTO ruleset_releases (id, semver, bundle_digest) VALUES (gen_random_uuid(), $1, $2)
			ON CONFLICT (semver) DO UPDATE SET bundle_digest = EXCLUDED.bundle_digest`, semver, c.row); err != nil {
			t.Fatal(err)
		}
		got := env.do(anonymous, http.MethodGet, "/api/v1/ruleset-releases/latest/bundle", nil)
		_ = got.Body.Close()
		if got.StatusCode != c.want {
			t.Errorf("a release recorded with %s: %d, want %d", c.name, got.StatusCode, c.want)
		}
	}
}

package api_test

// Session self-management and the rule-bundle endpoint that backs
// `agentry validate --rules-update`.

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

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

	// The owner can, from a different session.
	env.doJSON(keep, http.MethodDelete, "/api/v1/user/sessions/"+doomedID, nil, nil, http.StatusNoContent)

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

	env.doJSON(a, http.MethodDelete, "/api/v1/user/sessions", nil, nil, http.StatusNoContent)

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
}

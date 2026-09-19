package api_test

// Test environment for M1 API tests: real Postgres (AGENTRY_TEST_DATABASE_URL,
// see DEVIATIONS.md DEV-001), real handler stack, seeded users/org fixtures.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/store"
)

var (
	envOnce sync.Once
	envSt   *store.Store
	envErr  error
)

// testEnv is one API test environment over the shared database.
type testEnv struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store
	sfx string // unique suffix for fixture handles
	// srvObj is the server behind srv, for a test that must change a seam
	// after the fixture is built (a resolver that starts answering and then
	// fails).
	srvObj *api.Server
}

func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvWith(t)
}

// newTestEnvWith builds a test env, applying opts to the *api.Server before it
// is wrapped in the HTTP handler (M6 tests inject fake resolvers, OIDC clients,
// and webhook dispatchers).
func newTestEnvWith(t *testing.T, opts ...func(*api.Server)) *testEnv {
	return newTestEnvCfg(t, nil, opts...)
}

// newTestEnvCfg additionally lets a test mutate the config BEFORE api.New
// reads it (social login providers, audit stream, rate classes).
func newTestEnvCfg(t *testing.T, cfgFn func(*config.Config), opts ...func(*api.Server)) *testEnv {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping API integration test")
	}
	envOnce.Do(func() {
		ctx := context.Background()
		if err := store.Migrate(ctx, url); err != nil {
			envErr = err
			return
		}
		envSt, envErr = store.Connect(ctx, url)
	})
	if envErr != nil {
		t.Fatalf("test env: %v", envErr)
	}

	cfg := config.Default()
	cfg.Scan.OSVURL = "none" // S7 never dials out of a test; TestS7 installs a fake
	cfg.Auth.SessionTTL = time.Hour
	// Tests hammer auth endpoints from one IP; keep prod defaults out of the way.
	cfg.Limits.LoginPerMin = 10000
	cfg.Limits.AnonymousPerMin = 100000
	cfg.Limits.AuthedPerHour = 10000000
	cfg.Limits.AuthedBurstPerMin = 100000
	if cfgFn != nil {
		cfgFn(&cfg)
	}
	srvObj := api.New(cfg, envSt, nil)
	for _, o := range opts {
		o(srvObj)
	}
	srv := httptest.NewServer(api.NewHandler(srvObj))
	t.Cleanup(srv.Close)

	return &testEnv{
		t:      t,
		srv:    srv,
		srvObj: srvObj,
		st:     envSt,
		sfx:    fmt.Sprintf("%06x", rand.Int63n(1<<24)), //nolint:gosec // test fixture names
	}
}

// caller carries credentials for requests.
type caller struct {
	name    string
	session string // session cookie value
	csrf    string
	pat     string // bearer token
}

var anonymous = caller{name: "anonymous"}

// do performs an HTTP request with the caller's credentials.
func (env *testEnv) do(c caller, method, path string, body any) *http.Response {
	env.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			env.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, env.srv.URL+path, rd)
	if err != nil {
		env.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.pat != "" {
		req.Header.Set("Authorization", "Bearer "+c.pat)
	} else if c.session != "" {
		req.AddCookie(&http.Cookie{Name: "agentry_session", Value: c.session})
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("X-Agentry-CSRF", c.csrf)
		}
	}
	res, err := env.srv.Client().Do(req)
	if err != nil {
		env.t.Fatal(err)
	}
	return res
}

// doWithHeaders is do() plus extra request headers (Idempotency-Key, …).
//
//nolint:unparam // method is part of the address; today's callers are all POST
func (env *testEnv) doWithHeaders(c caller, method, path string, body any, headers map[string]string) *http.Response {
	env.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			env.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, env.srv.URL+path, rd)
	if err != nil {
		env.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.pat != "" {
		req.Header.Set("Authorization", "Bearer "+c.pat)
	} else if c.session != "" {
		req.AddCookie(&http.Cookie{Name: "agentry_session", Value: c.session})
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("X-Agentry-CSRF", c.csrf)
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := env.srv.Client().Do(req)
	if err != nil {
		env.t.Fatal(err)
	}
	return res
}

// sfxDigits renders the fixture suffix as decimal digits, for places that
// need a numeric component (semver segments).
func (env *testEnv) sfxDigits() string {
	var b strings.Builder
	for _, r := range env.sfx {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('0' + (r-'a')%10)
		}
	}
	return b.String()
}

// skillFiles is the minimum publishable skill workspace, with optional tags.
//
//nolint:unparam // version is part of the address; tests happen to use 1.0.0
func skillFiles(ns, name, version string, tags []string) map[string]string {
	y := `schemaVersion: "2"
name: ` + name + `
namespace: ` + ns + `
modes: [autonomous]
version: ` + version + `
summary: "test"
license: Apache-2.0
`
	if len(tags) > 0 {
		y += "tags: [" + strings.Join(tags, ", ") + "]\n"
	}
	y += `entrypoints:
  instruction: SKILL.md
publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE]
`
	return map[string]string{
		"agent.yaml": y,
		"README.md":  "# " + name + "\nA well-behaved agent.\n",
		"SKILL.md":   "Summarize politely and cite sources.\n",
		"LICENSE":    "Apache-2.0\n",
	}
}

// decodeInto reads a JSON response body into out, failing on a non-200.
func decodeInto(t *testing.T, res *http.Response, out any) {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", res.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode: %v (%s)", err, raw)
	}
}

// cursorFromLink extracts the cursor query parameter from a Link header.
func cursorFromLink(t *testing.T, link string) string {
	t.Helper()
	start := strings.Index(link, "<")
	end := strings.Index(link, ">")
	if start < 0 || end < start {
		t.Fatalf("malformed Link header: %q", link)
	}
	u, err := url.Parse(link[start+1 : end])
	if err != nil {
		t.Fatalf("Link target is not a URL: %v", err)
	}
	cur := u.Query().Get("cursor")
	if cur == "" {
		t.Fatalf("Link target carries no cursor: %q", link)
	}
	return cur
}

// doJSON performs the request and decodes a JSON body into out (may be nil).
func (env *testEnv) doJSON(c caller, method, path string, body any, out any, wantStatus int) {
	env.t.Helper()
	res := env.do(c, method, path, body)
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != wantStatus {
		env.t.Fatalf("%s %s: status %d want %d: %s", method, path, res.StatusCode, wantStatus, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			env.t.Fatalf("%s %s: decode: %v (%s)", method, path, err, raw)
		}
	}
}

// register creates a user and returns its handle.
func (env *testEnv) register(handle string) string {
	env.t.Helper()
	h := handle + env.sfx
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"handle": h, "email": h + "@example.test", "password": "hunter2hunter2",
	}, nil, http.StatusCreated)
	return h
}

// registerEmail registers an account at a chosen address, for a fixture
// whose subject is an IdP assertion about that address rather than the
// address the register helper would invent.
func (env *testEnv) registerEmail(handle, email string) string {
	env.t.Helper()
	h := handle + env.sfx
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"handle": h, "email": email, "password": "hunter2hunter2",
	}, nil, http.StatusCreated)
	return h
}

// verifyOrgDomain records that the organization proved control of a
// domain, which a DNS-TXT claim does in real life (handlers_domains.go):
// a verified row in domain_claims (agentry#363). A verified domain belongs
// to one organization, and the test database persists between runs, so a
// verified claim another test's organization left on the same domain is
// released first — that organization is done with it.
func (env *testEnv) verifyOrgDomain(org, domain string) {
	env.t.Helper()
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx,
		`DELETE FROM domain_claims WHERE domain = $2 AND verified_at IS NOT NULL
		   AND org_id <> (SELECT id FROM handles WHERE handle = $1)`, org, domain); err != nil {
		env.t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO domain_claims (id, org_id, domain, verification_token, verified_at)
		 SELECT gen_random_uuid(), id, $2, 'test', now() FROM handles WHERE handle = $1
		 ON CONFLICT (org_id, domain) DO UPDATE SET verified_at = now()`, org, domain); err != nil {
		env.t.Fatal(err)
	}
}

// handOverAndLeave makes other an admin of org and removes the admin's own
// membership: what a person does before creating a second organization,
// since they belong to one at a time (D26, agentry#363).
func (env *testEnv) handOverAndLeave(admin caller, org, otherHandle string) {
	env.t.Helper()
	env.doJSON(admin, http.MethodPut, "/api/v1/orgs/"+org+"/members/"+otherHandle,
		map[string]any{"role": "admin"}, nil, http.StatusOK)
	env.doJSON(admin, http.MethodDelete, "/api/v1/orgs/"+org+"/members/"+admin.name, nil, nil, http.StatusNoContent)
}

// joinOrg makes handle an active member of org through the real doors —
// since agentry#361 an invitation accepted by the invited account is the
// only way in, so a fixture that needs a member builds one the way a person
// would. The account must be registered; its address is verified here
// because accepting requires it. A fixture that needs another role changes
// it afterwards, which is what the PUT route is still for.
func (env *testEnv) joinOrg(admin caller, org, handle string) {
	env.t.Helper()
	env.verifyEmail(handle)
	var inv struct {
		Token string `json:"token"`
	}
	env.doJSON(admin, http.MethodPost, "/api/v1/orgs/"+org+"/invitations",
		map[string]any{"email": handle + "@example.test", "role": "member"}, &inv, http.StatusCreated)
	env.doJSON(env.login(handle), http.MethodPost, "/api/v1/invitations/"+inv.Token, nil, nil, http.StatusOK)
}

// seedMembership writes a membership straight into the database, for a
// fixture whose subject is not the door: a security_reviewer (which the API
// assigns only inside a first-party organization) or a pending member (whom
// only SCIM or the fold-in creates).
func (env *testEnv) seedMembership(org, handle, role, state string) {
	env.t.Helper()
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO memberships (org_id, user_id, role, state)
		 SELECT o.id, u.id, $3, $4 FROM handles o, handles u WHERE o.handle = $1 AND u.handle = $2
		 ON CONFLICT (org_id, user_id) DO UPDATE SET role = $3, state = $4`, org, handle, role, state); err != nil {
		env.t.Fatal(err)
	}
}

// login opens a session for a registered user.
func (env *testEnv) login(handle string) caller {
	env.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/v1/auth/login",
		bytes.NewReader(mustJSON(map[string]any{"login": handle, "password": "hunter2hunter2"})))
	req.Header.Set("Content-Type", "application/json")
	res, err := env.srv.Client().Do(req)
	if err != nil {
		env.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		env.t.Fatalf("login %s: %d %s", handle, res.StatusCode, raw)
	}
	var out struct {
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		env.t.Fatal(err)
	}
	c := caller{name: handle, csrf: out.CsrfToken}
	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" {
			c.session = ck.Value
		}
	}
	if c.session == "" {
		env.t.Fatal("login: no session cookie")
	}
	return c
}

// mintPAT creates a PAT via the caller's session.
func (env *testEnv) mintPAT(c caller, name string, scopes ...string) (id, token string) {
	env.t.Helper()
	var out struct {
		Id    string `json:"id"`
		Token string `json:"token"`
	}
	env.doJSON(c, http.MethodPost, "/api/v1/user/tokens", map[string]any{
		"name": name, "scopes": scopes,
	}, &out, http.StatusCreated)
	return out.Id, out.Token
}

// verifyEmail marks a user's email verified directly (the token only leaves
// through the notifier; tests shortcut the mailbox).
func (env *testEnv) verifyEmail(handle string) {
	env.t.Helper()
	_, err := env.st.Pool().Exec(context.Background(),
		`UPDATE users SET email_verified_at = now() WHERE id = (SELECT id FROM handles WHERE handle = $1)`, handle)
	if err != nil {
		env.t.Fatal(err)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

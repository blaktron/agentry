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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/PLACEHOLDER_ORG/agentry/internal/api"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
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
}

func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvWith(t)
}

// newTestEnvWith builds a test env, applying opts to the *api.Server before it
// is wrapped in the HTTP handler (M6 tests inject fake resolvers, OIDC clients,
// and webhook dispatchers).
func newTestEnvWith(t *testing.T, opts ...func(*api.Server)) *testEnv {
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
	cfg.Auth.SessionTTL = time.Hour
	// Tests hammer auth endpoints from one IP; keep prod defaults out of the way.
	cfg.Limits.LoginPerMin = 10000
	cfg.Limits.AnonymousPerMin = 100000
	cfg.Limits.AuthedPerHour = 10000000
	cfg.Limits.AuthedBurstPerMin = 100000
	srvObj := api.New(cfg, envSt, nil)
	for _, o := range opts {
		o(srvObj)
	}
	srv := httptest.NewServer(api.NewHandler(srvObj))
	t.Cleanup(srv.Close)

	return &testEnv{
		t:   t,
		srv: srv,
		st:  envSt,
		sfx: fmt.Sprintf("%06x", rand.Int63n(1<<24)), //nolint:gosec // test fixture names
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

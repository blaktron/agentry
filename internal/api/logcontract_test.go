package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/logx"
)

// The log contract (docs/logging.md) on the assembled handler, without a
// database: what the access line carries, when the probes are skipped, and
// when an inbound X-Request-Id is honoured.

func contractServer(t *testing.T, trustedProxies int, proxyRequestID bool) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	cfg := config.Default()
	cfg.DevMode = true
	cfg.HTTP.TrustedProxies = trustedProxies
	cfg.HTTP.ProxyRequestID = proxyRequestID
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf, Service: "agentryd", Role: "api", Version: "test"})
	srv := httptest.NewServer(api.NewHandler(api.New(cfg, nil, log)))
	t.Cleanup(srv.Close)
	return srv, &buf
}

// accessLine is the last access line in buf, or nil.
func accessLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var found map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "http" {
			found = m
		}
	}
	return found
}

func get(t *testing.T, url string, headers map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "contract-test/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res
}

var mintedID = regexp.MustCompile(`^[0-9a-f]{16}$`)

func TestAccessLineCarriesTheContract(t *testing.T) {
	srv, buf := contractServer(t, 0, false)
	res := get(t, srv.URL+"/api/v1/meta", nil)
	id := res.Header.Get("X-Request-Id")
	if !mintedID.MatchString(id) {
		t.Fatalf("X-Request-Id = %q, want a minted 16-hex id", id)
	}
	line := accessLine(t, buf)
	if line == nil {
		t.Fatalf("no access line: %s", buf.String())
	}
	want := map[string]any{
		"event": "http.request", "request_id": id, "method": "GET", "path": "/api/v1/meta",
		"route": "/api/v1/meta", "status": float64(200), "user_agent": "contract-test/1",
		"actor": "anonymous", "service": "agentryd", "role": "api", "version": "test",
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("%s = %v, want %v", k, line[k], v)
		}
	}
	if b, _ := line["bytes"].(float64); b <= 0 {
		t.Errorf("bytes = %v, want the body's size", line["bytes"])
	}
	if ip, _ := line["client_ip"].(string); ip == "" {
		t.Errorf("client_ip missing: %v", line)
	}
	if _, ok := line["dur_ms"]; !ok {
		t.Errorf("dur_ms missing")
	}
}

// The probes are polled every few seconds; they are not access-logged.
func TestProbesAreNotAccessLogged(t *testing.T) {
	srv, buf := contractServer(t, 0, false)
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		buf.Reset()
		get(t, srv.URL+p, nil)
		if l := accessLine(t, buf); l != nil {
			t.Errorf("%s produced an access line: %v", p, l)
		}
	}
}

// An inbound X-Request-Id is honoured only when the operator has said the
// hop in front sets it (http.proxyRequestID) on top of a trusted hop count —
// a hop that merely forwards the header would let a client choose its own
// id — and only when well-formed (D19).
func TestInboundRequestIDHonouredOnlyWhenTheHopSetsIt(t *testing.T) {
	const edgeID = "5f3a9c0e1b2d4f6a8c0e2b4d6f8a0c1e" // nginx's $request_id shape
	cases := []struct {
		name    string
		trusted int
		proxyID bool
		header  string
		honour  bool
	}{
		{"direct client with a header: minted", 0, false, edgeID, false},
		{"trusted hop that only forwards the header: minted", 1, false, edgeID, false},
		{"flag without a hop count: minted", 0, true, edgeID, false},
		{"hop that sets it, well-formed: honoured", 1, true, edgeID, true},
		{"hop that sets it, hyphenated id: honoured", 1, true, "edge-00112233445566778899", true},
		{"hop that sets it, malformed: minted", 1, true, "not an id!", false},
		{"hop that sets it, too short: minted", 1, true, "abc", false},
		{"hop that sets it, too long: minted", 1, true, strings.Repeat("a", 65), false},
		{"hop that sets it, no header: minted", 1, true, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, buf := contractServer(t, c.trusted, c.proxyID)
			h := map[string]string{}
			if c.header != "" {
				h["X-Request-Id"] = c.header
			}
			res := get(t, srv.URL+"/api/v1/meta", h)
			got := res.Header.Get("X-Request-Id")
			if c.honour && got != c.header {
				t.Fatalf("returned %q, want the inbound %q", got, c.header)
			}
			if !c.honour && (got == c.header || !mintedID.MatchString(got)) {
				t.Fatalf("returned %q, want a minted id", got)
			}
			if l := accessLine(t, buf); l == nil || l["request_id"] != got {
				t.Fatalf("access line carries %v, response carries %q", l["request_id"], got)
			}
		})
	}
}

// The split git role mounts a bare mux through the same stack: a git
// deployment answers with a request id and logs an access line too.
func TestWrapMiddlewareGivesABareMuxTheContract(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf, Role: "git"})
	s := api.New(cfg, nil, log)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x/info/refs", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("refs")) })
	srv := httptest.NewServer(s.WrapMiddleware(mux))
	defer srv.Close()
	res := get(t, srv.URL+"/x/info/refs", nil)
	if !mintedID.MatchString(res.Header.Get("X-Request-Id")) {
		t.Fatalf("no request id on the git role's response")
	}
	l := accessLine(t, &buf)
	if l == nil || l["route"] != "/x/info/refs" || l["role"] != "git" {
		t.Fatalf("git access line: %v", l)
	}
}

// The request id reaches the audit row: a mutation audited inside a request
// carries the same id in its detail that the request's lines carry, so a row
// and its lines find each other. Needs the database (the row is the record).
func TestRequestIDReachesTheAuditRow(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) { c.HTTP.TrustedProxies = 1; c.HTTP.ProxyRequestID = true })
	h := env.register("reqid")
	sess := env.login(h)
	const id = "edge-00112233445566778899aabbccddeeff"
	res := env.doWithHeaders(sess, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "Traced"}, map[string]string{"X-Request-Id": id})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /user: %d", res.StatusCode)
	}
	if got := res.Header.Get("X-Request-Id"); got != id {
		t.Fatalf("response id %q, want the honoured %q (one hop that sets it)", got, id)
	}
	var n int
	err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.update' AND detail->>'request_id' = $1`, id).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("audit rows carrying request_id %s: %d, want 1", id, n)
	}
}

// A failed native sign-in is named (`auth.login_failed`) and, with the audit
// mirror on, its audit event is a line too (`audit.user.login_failed`) — both
// under the request's id, beside the access line. Needs the database; on the
// dev host native sign-in answers 410 under the directory service (DEV-057),
// so this test is where the criterion is proved.
func TestFailedSignInIsNamedAndMirrored(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(logx.New(logx.Options{W: &buf}))
	t.Cleanup(func() { slog.SetDefault(old) })
	env := newTestEnvCfg(t, func(c *config.Config) { c.Audit.StreamKind = "log" })
	h := env.register("named")
	res := env.do(anonymous, http.MethodPost, "/api/v1/auth/login", map[string]any{"login": h, "password": "wrong-password-x"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", res.StatusCode)
	}
	id := res.Header.Get("X-Request-Id")
	events := map[string]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["request_id"] == id {
			if ev, _ := m["event"].(string); ev != "" {
				events[ev] = m
			}
		}
	}
	for _, want := range []string{"http.request", "auth.login_failed", "audit.user.login_failed"} {
		if events[want] == nil {
			t.Errorf("no %s line under request %s; events seen: %v", want, id, events)
		}
	}
	if l := events["auth.login_failed"]; l != nil && (l["user"] == nil || l["user"] == "00000000-0000-0000-0000-000000000000") {
		t.Errorf("auth.login_failed should name the account the login matched: %v", l)
	}
	if l := events["audit.user.login_failed"]; l != nil {
		if d, _ := l["detail"].(map[string]any); d == nil || d["login"] != h || d["request_id"] != id {
			t.Errorf("the mirror carries the record's detail with the request id: %v", l["detail"])
		}
	}
}

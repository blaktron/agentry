package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/logx"
)

// The log contract (docs/logging.md) on the assembled handler, without a
// database: what the access line carries, when the probes are skipped, and
// when an inbound X-Request-Id is honoured.

func contractServer(t *testing.T, trustedProxies int, proxyRequestID bool, trustedFrom ...string) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	cfg := config.Default()
	cfg.DevMode = true
	cfg.HTTP.TrustedProxies = trustedProxies
	cfg.HTTP.ProxyRequestID = proxyRequestID
	cfg.HTTP.TrustedProxyCIDRs = trustedFrom
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

// getHeader is get with a request header set that may repeat.
func getHeader(t *testing.T, url string, h http.Header) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res
}

// logSink is a log sink safe to read while the server's background
// goroutines still write.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logSink) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logSink) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.Reset()
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
	if ip, _ := line["client_ip"].(string); ip != "127.0.0.1" {
		t.Errorf("client_ip = %q, want the peer's address", ip)
	}
	if res.ContentLength <= 0 || line["bytes"] != float64(res.ContentLength) {
		t.Errorf("bytes = %v, want the %d bytes the response carried", line["bytes"], res.ContentLength)
	}
	// Every response, whatever the route, carries the baseline headers.
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if got := res.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	// The line names the request as the router matched it: a query string
	// (which may carry a credential) is never part of the path, an unmatched
	// path is one low-cardinality route, and a matched pattern is logged as
	// the pattern and not as the concrete path.
	buf.Reset()
	res = get(t, srv.URL+"/api/v1/no-such-route?token=hunter2-credential", nil)
	line = accessLine(t, buf)
	if line == nil || line["path"] != "/api/v1/no-such-route" || line["route"] != "other" || line["status"] != float64(http.StatusNotFound) {
		t.Errorf("unmatched path: access line %v, want path /api/v1/no-such-route, route other, status 404", line)
	}
	if res.StatusCode != http.StatusNotFound || strings.Contains(buf.String(), "hunter2-credential") {
		t.Errorf("a query string reached the log: %s", buf.String())
	}
	buf.Reset()
	get(t, srv.URL+"/api/v1/agents/someone/thing", nil)
	line = accessLine(t, buf)
	if line == nil || line["path"] != "/api/v1/agents/someone/thing" || line["route"] != "/api/v1/agents/{ns}/{name}" {
		t.Errorf("matched pattern: access line %v, want the pattern as the route and the concrete path", line)
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
	// Only the probes' own paths are skipped: anything under or beside them
	// is an ordinary request and is logged.
	for _, p := range []string{"/healthz/extra", "/readyz/extra", "/metrics/extra", "/api/v1/healthz"} {
		buf.Reset()
		get(t, srv.URL+p, nil)
		if l := accessLine(t, buf); l == nil || l["path"] != p {
			t.Errorf("%s produced no access line: %v", p, l)
		}
	}
}

// An inbound X-Request-Id is honoured only when the operator has said the
// hop in front sets it (http.proxyRequestID) on top of a trusted hop count —
// a hop that merely forwards the header would let a client choose its own
// id — and only when well-formed.
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
		{"hop that sets it, exactly 8 characters: honoured", 1, true, "abcdefgh", true},
		{"hop that sets it, 7 characters: minted", 1, true, "abcdefg", false},
		{"hop that sets it, exactly 64 characters: honoured", 1, true, strings.Repeat("0123456789abcdef", 4), true},
		{"hop that sets it, upper case and digits: honoured", 1, true, "ABCDEFGH-0123456789", true},
		{"hop that sets it, hyphens only: honoured", 1, true, "--------", true},
		{"hop that sets it, underscore: minted", 1, true, "abcd_efgh", false},
		{"hop that sets it, dot: minted", 1, true, "abcd.efgh", false},
		{"hop that sets it, space inside: minted", 1, true, "abcd efgh", false},
		{"hop that sets it, junk before a valid run: minted", 1, true, "!!abcdefgh", false},
		{"hop that sets it, junk after a valid run: minted", 1, true, "abcdefgh!!", false},
		// The log masks a run of 52 or more [a-z2-7] characters as a token, so
		// such an id could not be found in the log: it is replaced.
		{"hop that sets it, 52 base32 characters: minted", 1, true, strings.Repeat("a", 52), false},
		{"hop that sets it, 64 base32 characters in upper case: minted", 1, true, strings.Repeat("A2", 32), false},
		{"hop that sets it, 51 base32 characters: honoured", 1, true, strings.Repeat("a", 51), true},
		{"hop that sets it, 64 characters with a stop in the run: honoured", 1, true, strings.Repeat("a", 40) + "-" + strings.Repeat("a", 23), true},
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

// A page of the /ui/ surface calls the API in-process. That call is part of
// the browser's request, not a second request: the response carries one
// X-Request-Id, the log carries one access line, and every line written
// under the request (the API handler's included) carries that same id.
func TestUICallsLogAndCountOnce(t *testing.T) {
	srv, buf := contractServer(t, 0, false)
	// A page that calls the API (the signed-in lookup) when a session
	// cookie is present; the session does not exist, which is enough to make
	// the call and have it refused.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/ui/authorize?port=40123&state=abcdefghij", nil)
	req.AddCookie(&http.Cookie{Name: "agentry_session", Value: "no-such-session"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if got := res.Header.Values("X-Request-Id"); len(got) != 1 || !mintedID.MatchString(got[0]) {
		t.Fatalf("X-Request-Id = %v, want exactly one minted id", got)
	}

	var access []map[string]any
	ids := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		if id, ok := m["request_id"].(string); ok {
			ids[id] = true
		}
		if m["msg"] == "http" {
			access = append(access, m)
		}
	}
	if len(access) != 1 {
		t.Fatalf("access lines = %d, want 1: %s", len(access), buf.String())
	}
	if access[0]["path"] != "/ui/authorize" || access[0]["request_id"] != res.Header.Get("X-Request-Id") {
		t.Fatalf("access line = %v", access[0])
	}
	if len(ids) != 1 {
		t.Fatalf("lines carry %d distinct request ids, want 1: %v", len(ids), ids)
	}
}

// The git role mounts a bare mux through the same stack: a git
// deployment answers with a request id and logs an access line too.
func TestWrapMiddlewareGivesABareMuxTheContract(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	var buf bytes.Buffer
	log := logx.New(logx.Options{W: &buf, Role: "git"})
	s := api.New(cfg, nil, log)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x/info/refs", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("refs")) })
	mux.HandleFunc("GET /x/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
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

	// A handler that panics answers 500 with a request id, is logged at error
	// level under that id, and still produces its access line.
	buf.Reset()
	res = get(t, srv.URL+"/x/boom", nil)
	id := res.Header.Get("X-Request-Id")
	if res.StatusCode != http.StatusInternalServerError || !mintedID.MatchString(id) {
		t.Fatalf("panicking handler: status %d, request id %q, want 500 and a minted id", res.StatusCode, id)
	}
	if l := accessLine(t, &buf); l == nil || l["status"] != float64(http.StatusInternalServerError) || l["path"] != "/x/boom" || l["request_id"] != id {
		t.Fatalf("access line of the panicking request: %v", l)
	}
	var logged bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "panic in handler" {
			logged = m["level"] == "ERROR" && m["request_id"] == id && m["path"] == "/x/boom"
		}
	}
	if !logged {
		t.Fatalf("no error-level panic line under request %s: %s", id, buf.String())
	}
}

// The request id reaches the audit row: a mutation audited inside a request
// carries the same id in its detail that the request's lines carry, so a row
// and its lines find each other. Needs the database (the row is the record).
func TestRequestIDReachesTheAuditRow(t *testing.T) {
	var buf logSink
	prev := slog.Default()
	slog.SetDefault(logx.New(logx.Options{W: &buf}))
	t.Cleanup(func() { slog.SetDefault(prev) })
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

	// The access line of the request names its caller by opaque ids only:
	// the user id and how it signed in, never a credential.
	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "http" && m["request_id"] == id {
			line = m
		}
	}
	if line == nil || line["actor"] != env.userID(h) || line["actor_via"] != "session" {
		t.Fatalf("session request's access line: %v, want actor %s via session", line, env.userID(h))
	}
	if _, ok := line["actor_pat"]; ok {
		t.Errorf("a session request names a token: %v", line)
	}
	patID, pat := env.mintPAT(sess, "traced", "user:profile")
	buf.Reset()
	res = env.do(caller{pat: pat}, http.MethodGet, "/api/v1/user/notifications", nil)
	_ = res.Body.Close()
	patReq := res.Header.Get("X-Request-Id")
	line = nil
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "http" && m["request_id"] == patReq {
			line = m
		}
	}
	if res.StatusCode != http.StatusOK || line == nil || line["actor"] != env.userID(h) || line["actor_via"] != "pat" || line["actor_pat"] != patID {
		t.Fatalf("token request: status %d, access line %v, want actor %s via pat %s", res.StatusCode, line, env.userID(h), patID)
	}
	if strings.Contains(buf.String(), pat) || strings.Contains(buf.String(), sess.session) {
		t.Fatalf("a credential reached the log: %s", buf.String())
	}
}

// A sign-in the provider's token exchange rejects is named
// (`auth.social_rejected`, with the provider) under the request's id,
// beside the access line, and with the audit mirror on a sign-in's audit
// event is a line too (`audit.user.login`). Needs the database.
func TestFailedSignInIsNamedAndMirrored(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(logx.New(logx.Options{W: &buf}))
	t.Cleanup(func() { slog.SetDefault(old) })
	env, idp := newOIDCTestEnv(t, func(c *config.Config) { c.Audit.StreamKind = "log" })

	_, state, cookie := env.socialStart(t, config.OIDCProviderID)
	req, err := http.NewRequest(http.MethodGet, env.srv.URL+"/api/v1/auth/oidc/oidc/callback?code=never-issued&state="+url.QueryEscape(state), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	res, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a code the provider never issued: %d", res.StatusCode)
	}
	id := res.Header.Get("X-Request-Id")
	lines := func() []map[string]any {
		var out []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil {
				out = append(out, m)
			}
		}
		return out
	}
	events := map[string]map[string]any{}
	for _, m := range lines() {
		if ev, _ := m["event"].(string); ev != "" && m["request_id"] == id {
			events[ev] = m
		}
	}
	for _, want := range []string{"http.request", "auth.social_rejected"} {
		if events[want] == nil {
			t.Errorf("no %s line under request %s; events seen: %v", want, id, events)
		}
	}
	if l := events["auth.social_rejected"]; l != nil && l["provider"] != config.OIDCProviderID {
		t.Errorf("auth.social_rejected should name the provider: %v", l)
	}

	c := env.mintAccount(t, idp, "named")
	var mirrored bool
	for _, m := range lines() {
		if m["event"] == "audit.user.login" {
			if d, _ := m["detail"].(map[string]any); d != nil && d["provider"] == config.OIDCProviderID && m["request_id"] != nil && m["request_id"] != "" {
				mirrored = true
			}
		}
	}
	if !mirrored {
		t.Errorf("no audit.user.login line for %s's sign-in, with its detail and request id", c.name)
	}
}

// On the assembled handler, http.trustedProxyCIDRs decides whose forwarded
// headers count: the test client connects from 127.0.0.1, so
// a list that leaves loopback out makes it a direct client, whose
// X-Forwarded-For and X-Request-Id are both ignored, and a list that names
// it makes it the trusted hop.
func TestForwardedHeadersCountOnlyFromAListedPeer(t *testing.T) {
	const edgeID = "5f3a9c0e1b2d4f6a8c0e2b4d6f8a0c1e"
	hdr := map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Request-Id": edgeID}

	srv, buf := contractServer(t, 1, true, "10.0.0.0/8")
	res := get(t, srv.URL+"/api/v1/meta", hdr)
	l := accessLine(t, buf)
	if l == nil || l["client_ip"] != "127.0.0.1" {
		t.Fatalf("an unlisted peer's X-Forwarded-For was believed: access line %v", l)
	}
	if got := res.Header.Get("X-Request-Id"); got == edgeID || !mintedID.MatchString(got) {
		t.Fatalf("an unlisted peer chose its request id: %q", got)
	}

	srv, buf = contractServer(t, 1, true, "127.0.0.0/8")
	res = get(t, srv.URL+"/api/v1/meta", hdr)
	if l := accessLine(t, buf); l == nil || l["client_ip"] != "203.0.113.7" {
		t.Fatalf("the listed hop's X-Forwarded-For was not read: access line %v", l)
	}
	if got := res.Header.Get("X-Request-Id"); got != edgeID {
		t.Fatalf("the listed hop's request id was not honoured: %q", got)
	}

	// Which entry of the header names the client. The peer here is always
	// 127.0.0.1: with N trusted hops the Nth entry from the end is the
	// address the nearest hop vouched for, and anything the client wrote
	// before it is ignored.
	const peer = "127.0.0.1"
	for _, c := range []struct {
		name    string
		hops    int
		list    []string
		xff     []string
		want    string
		honours bool
	}{
		{"no trusted hop: the header is ignored", 0, nil, []string{"203.0.113.7"}, peer, false},
		{"a listed peer with no trusted hop: the header is ignored", 0, []string{"127.0.0.0/8"}, []string{"203.0.113.7"}, peer, false},
		{"one hop and no header: the peer", 1, nil, nil, peer, true},
		{"one hop: entries the client prepended are ignored", 1, nil, []string{"9.9.9.9, 203.0.113.7"}, "203.0.113.7", true},
		{"one hop: the same across two header lines", 1, nil, []string{"9.9.9.9", "203.0.113.7"}, "203.0.113.7", true},
		{"two hops: the second from the end", 2, nil, []string{"9.9.9.9, 203.0.113.7, 198.51.100.4"}, "203.0.113.7", true},
		{"two hops and a chain of one: the peer, not the oldest entry", 2, nil, []string{"203.0.113.7"}, peer, true},
		{"two hops and one entry that is not an address: the peer", 2, nil, []string{"198.51.100.5, not-an-ip"}, peer, true},
		{"an address with a port", 1, nil, []string{"203.0.113.7:4711"}, "203.0.113.7", true},
		{"a bracketed address with a port", 1, nil, []string{"[2001:db8::1]:443"}, "2001:db8::1", true},
		{"a bracketed address without a port", 1, nil, []string{"[2001:db8::1]"}, "2001:db8::1", true},
		{"a peer list that does not parse trusts nobody", 1, []string{"not-a-cidr"}, []string{"203.0.113.7"}, peer, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, buf := contractServer(t, c.hops, true, c.list...)
			h := http.Header{"X-Request-Id": {edgeID}}
			if c.xff != nil {
				h["X-Forwarded-For"] = c.xff
			}
			res := getHeader(t, srv.URL+"/api/v1/meta", h)
			if l := accessLine(t, buf); l == nil || l["client_ip"] != c.want {
				t.Fatalf("client_ip = %v, want %s", l["client_ip"], c.want)
			}
			if got := res.Header.Get("X-Request-Id"); (got == edgeID) != c.honours {
				t.Fatalf("request id %q: honoured = %t, want %t", got, got == edgeID, c.honours)
			}
		})
	}
}

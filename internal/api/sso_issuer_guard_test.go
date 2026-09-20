package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/webhook"
)

// An organization's OIDC issuer is an address any org admin can name, and an
// org admin is any account with a verified email. The registry fetches it, so
// it is judged like every other outbound destination: https only, a public
// host, no credentials in the URL, and — at dial time — the egress guard.
// Security review 2026-09-20 §5.8.1 (C15).

func TestOIDCIssuerIsValidatedAtWrite(t *testing.T) {
	env := newTestEnv(t) // dev mode: http to a loopback IdP is the one allowance
	owner := env.register("issuer-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "issuerorg" + env.sfx
	env.createOrg(sess, orgH)

	put := func(issuer string) int {
		t.Helper()
		resp := env.do(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
			"enabled": false,
			"config":  map[string]any{"issuer": issuer, "clientId": "c", "clientSecret": "shh"},
		})
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	refused := []string{
		"http://idp.example",             // plain http to a public host
		"http://10.0.0.1",                // private range
		"https://10.0.0.1/realm",         // private range over https
		"https://169.254.169.254/latest", // cloud metadata
		"https://0.1.2.3",                // 0.0.0.0/8
		"https://100.64.0.1",             // CGNAT
		"https://[2002:0a00:1::1]",       // 6to4 of 10.0.0.1
		"https://[64:ff9b::a00:1]",       // NAT64 of 10.0.0.1
		"https://[fe80::1]",              // link-local v6
		"https://user:pw@idp.example",    // userinfo
		"https://idp.example/?x=1",       // a query is not an issuer
		"https://idp.example/#frag",      // nor a fragment
		"ftp://idp.example",              // not a web scheme
		"idp.example",                    // no scheme
		"https://",                       // no host
	}
	for _, iss := range refused {
		if got := put(iss); got != http.StatusUnprocessableEntity {
			t.Errorf("issuer %q: status %d, want 422", iss, got)
		}
	}
	for _, iss := range []string{"https://idp.example", "https://idp.example/realms/acme", "https://idp.example:8443/", "http://127.0.0.1:9", "http://localhost:9/dev"} {
		if got := put(iss); got != http.StatusOK {
			t.Errorf("issuer %q: status %d, want 200", iss, got)
		}
	}
}

func TestOIDCIssuerLoopbackAllowanceIsDevModeOnly(t *testing.T) {
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.DevMode = false
		// Outside dev mode the server insists on a sealing key and a real
		// signing key; the issuer rule is what is under test.
		c.Auth.SealingKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
		c.Signing.Kind, c.Signing.KeyFile = "file", writeTestSigningKey(t)
	})
	owner := env.register("prod-issuer-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "prodissuer" + env.sfx
	env.createOrg(sess, orgH)
	// Outside dev mode loopback is refused however it is spelled, including
	// the 6to4 encoding of it, which dev mode admits as the loopback it is.
	for _, iss := range []string{"http://127.0.0.1:9", "http://localhost:9", "https://127.0.0.1", "https://localhost/realm", "https://[::1]", "https://[2002:7f00:1::1]"} {
		resp := env.do(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
			"enabled": false, "config": map[string]any{"issuer": iss, "clientId": "c", "clientSecret": "shh"},
		})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("outside dev mode, issuer %q: status %d, want 422", iss, resp.StatusCode)
		}
	}
}

// A name that passes the write-time check can still resolve to a private
// address (a rebinding resolver, or simply an IdP hostname on a corporate
// LAN). The dial goes through the egress guard on the probe and on the
// sign-in path alike, so no request leaves the process.
func TestOIDCDiscoveryGoesThroughTheEgressGuard(t *testing.T) {
	var hits atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer idp.Close()
	lis := netip.MustParseAddrPort(idp.Listener.Addr().String())
	// The guard is the production one (loopback refused); only its resolver
	// is the test's, answering the public-looking name with the listener.
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetOIDCEgressGuard(webhook.Guard{LookupNetIP: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{lis.Addr()}, nil
		}})
	})
	owner := env.register("guard-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "guardorg" + env.sfx
	env.createOrg(sess, orgH)
	issuer := fmt.Sprintf("https://rebind.example:%d", lis.Port()) // no such name; the resolver seam answers it
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": true, "config": map[string]any{"issuer": issuer, "clientId": "c", "clientSecret": "shh"},
	}, nil, http.StatusOK)

	var probe struct {
		Ok      bool   `json:"ok"`
		Summary string `json:"summary"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/sso/connections/oidc/test", nil, &probe, http.StatusOK)
	if probe.Ok || !strings.Contains(probe.Summary, "non-public address") {
		t.Fatalf("probe against a private-resolving issuer: %+v", probe)
	}
	// The sign-in door builds the same RP and must refuse the same way.
	resp := env.do(anonymous, http.MethodGet, "/api/v1/orgs/"+orgH+"/sso/oidc/start", nil)
	_ = resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("oidc start against a private-resolving issuer: status %d", resp.StatusCode)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the listener behind the private address was reached %d time(s)", n)
	}
}

// Whatever the issuer answers, the admin learns the status, never the body:
// the body of an internal endpoint is the read primitive the guard exists to
// deny, and a probe summary is the one place it could leak.
func TestOIDCProbeNeverReflectsTheUpstreamBody(t *testing.T) {
	const marker = "UPSTREAM-BODY-MARKER-7f3a"
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("{\"error\":\"" + marker + "\"}"))
	}))
	defer idp.Close()
	env := newTestEnv(t)
	owner := env.register("reflect-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "reflectorg" + env.sfx
	env.createOrg(sess, orgH)
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": false, "config": map[string]any{"issuer": idp.URL, "clientId": "c", "clientSecret": "shh"},
	}, nil, http.StatusOK)
	resp := env.do(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/sso/connections/oidc/test", nil)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := json.Marshal(func() any { var v any; _ = json.NewDecoder(resp.Body).Decode(&v); return v }())
	body := string(raw)
	if strings.Contains(body, marker) {
		t.Fatalf("the probe reflected the upstream body: %s", body)
	}
	if !strings.Contains(body, "503") {
		t.Fatalf("the probe should name the status the issuer answered: %s", body)
	}
}

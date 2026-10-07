package egressguard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGuard_IsAllowedIP(t *testing.T) {
	g := Guard{} // strict (production)
	cases := []struct {
		ip      string
		allowed bool
	}{
		{"8.8.8.8", true},              // public v4
		{"1.1.1.1", true},              // public v4
		{"2606:4700:4700::1111", true}, // public v6
		{"127.0.0.1", false},           // loopback
		{"::1", false},                 // loopback v6
		{"10.0.0.1", false},            // RFC1918
		{"172.16.5.4", false},          // RFC1918
		{"172.32.0.1", true},           // just outside 172.16/12
		{"192.168.1.1", false},         // RFC1918
		{"169.254.169.254", false},     // link-local / cloud metadata
		{"169.254.1.1", false},         // link-local
		{"fc00::1", false},             // ULA v6
		{"fe80::1", false},             // link-local v6
		{"100.64.0.1", false},          // CGNAT
		{"0.0.0.0", false},             // unspecified
		{"0.1.2.3", false},             // 0.0.0.0/8: Linux routes the whole /8 to lo
		{"0.255.255.255", false},       // 0.0.0.0/8, top of the range
		{"::ffff:0.1.2.3", false},      // v4-mapped 0/8
		{"224.0.0.1", false},           // multicast
		{"::ffff:10.0.0.1", false},     // v4-mapped private
		{"::", false},                  // unspecified v6
		{"2002:7f00:1::1", false},      // 6to4 embedding 127.0.0.1
		{"2002:0a00:1::1", false},      // 6to4 embedding 10.0.0.1
		{"2002:0001:0203::1", false},   // 6to4 embedding 0.1.2.3
		{"2002:0808:0808::1", true},    // 6to4 embedding 8.8.8.8 stays public
		{"64:ff9b::a00:1", false},      // NAT64 well-known prefix embedding 10.0.0.1
		{"64:ff9b::7f00:1", false},     // NAT64 embedding 127.0.0.1
		{"64:ff9b::808:808", true},     // NAT64 embedding 8.8.8.8 stays public
		{"64:ff9b:1::a00:1", false},    // NAT64 local-use prefix (RFC 8215) is never public
		{"::a00:1", false},             // deprecated IPv4-compatible form of 10.0.0.1
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := g.IsAllowedIP(ip); got != c.allowed {
			t.Errorf("IsAllowedIP(%s) = %v, want %v", c.ip, got, c.allowed)
		}
	}
}

func TestGuard_LoopbackSeam(t *testing.T) {
	if (Guard{}).IsAllowedIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("strict guard must block loopback")
	}
	if !(Guard{AllowLoopback: true}).IsAllowedIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("test seam should allow loopback")
	}
	// Even with loopback allowed, private/metadata stay blocked.
	if (Guard{AllowLoopback: true}).IsAllowedIP(netip.MustParseAddr("169.254.169.254")) {
		t.Fatal("metadata IP must stay blocked even with loopback seam")
	}
}

func TestGuard_DialBlocksNonPublic(t *testing.T) {
	g := Guard{}
	for _, addr := range []string{"10.0.0.1:443", "169.254.169.254:80", "127.0.0.1:443", "[::1]:443"} {
		if _, err := g.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Errorf("dial %s should be blocked", addr)
		}
	}
}

// TestGuard_DialPinsTheResolvedAddress exercises the resolve-then-check-then-pin
// half of DialContext against a resolver the test controls: the "DNS rebinding
// defeated" claim of ARCHITECTURE §9 is that a hostname's answer is checked
// per candidate and the dial goes to the checked literal, never back through
// DNS. A public-looking name that resolves to a private address is refused
// before any connection; padding the answer with one public address does not
// help; and when every candidate clears, the dial reaches the first one.
func TestGuard_DialPinsTheResolvedAddress(t *testing.T) {
	answers := map[string][]netip.Addr{
		"private.example":   {netip.MustParseAddr("10.0.0.1")},
		"padded.example":    {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("169.254.169.254")},
		"zeronet.example":   {netip.MustParseAddr("0.1.2.3")},
		"sixtofour.example": {netip.MustParseAddr("2002:7f00:1::1")},
	}
	g := Guard{LookupNetIP: func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := answers[host]; ok {
			return a, nil
		}
		t.Fatalf("unexpected lookup %q", host)
		return nil, nil
	}}
	for host := range answers {
		_, err := g.DialContext(context.Background(), "tcp", host+":443")
		var blocked *BlockedAddressError
		if !errors.As(err, &blocked) {
			t.Errorf("dial %s: err = %v, want BlockedAddressError", host, err)
			continue
		}
		if blocked.Host != host {
			t.Errorf("dial %s: blocked host = %q", host, blocked.Host)
		}
	}

	// Every candidate public: the dial goes to the first checked literal. A
	// loopback httptest listener stands in for it through the test seam, and
	// the resolver answers a name the listener never registered — proof the
	// connect used the literal, not a second lookup.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	lis := netip.MustParseAddrPort(ts.Listener.Addr().String())
	pinned := Guard{AllowLoopback: true, LookupNetIP: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{lis.Addr()}, nil
	}}
	conn, err := pinned.DialContext(context.Background(), "tcp", fmt.Sprintf("pinned.example:%d", lis.Port()))
	if err != nil {
		t.Fatalf("dial through the pinned literal: %v", err)
	}
	_ = conn.Close()
}

func TestClient_NoRedirectFollowing(t *testing.T) {
	redirected := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer ts.Close()
	resp, err := Guard{AllowLoopback: true, TLS: tlsTrusting(ts)}.Client().Get(ts.URL + "/start")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound || redirected {
		t.Fatalf("the redirect was followed (status %d, reached %v)", resp.StatusCode, redirected)
	}
}

// TestClient_TakesNoProxy: a proxy named in the environment is never used;
// the request goes to the checked address itself (here a loopback server
// through the test seam), so a proxy cannot carry it somewhere the guard
// did not check.
func TestClient_TakesNoProxy(t *testing.T) {
	proxied := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied = true
		w.WriteHeader(http.StatusTeapot)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	resp, err := Guard{AllowLoopback: true, TLS: tlsTrusting(ts)}.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = resp.Body.Close()
	if proxied || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("the request took the environment's proxy (status %d, proxied %v)", resp.StatusCode, proxied)
	}
}

// TestClient_TheTLSSeam: without the test's pool the httptest certificate
// is refused, so a test's trust never leaks into production's zero value.
func TestClient_TheTLSSeam(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	if resp, err := (Guard{AllowLoopback: true}).Client().Get(ts.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an untrusted certificate was accepted")
	}
}

// TestClient_HTTPSOnly: a guard that names HTTPSOnly refuses a plain http
// request before it dials, even to an address it would allow; without it
// the request goes out.
func TestClient_HTTPSOnly(t *testing.T) {
	reached := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	if resp, err := (Guard{AllowLoopback: true, HTTPSOnly: true}).Client().Get(ts.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("an http request went out under HTTPSOnly")
	}
	if reached {
		t.Fatal("the http server was reached under HTTPSOnly")
	}
	resp, err := Guard{AllowLoopback: true}.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("without HTTPSOnly: %v", err)
	}
	_ = resp.Body.Close()
}

// TestClient_RefusesNonPublicTargets: the client, not only the dialer,
// refuses a private or metadata address with a BlockedAddressError.
func TestClient_RefusesNonPublicTargets(t *testing.T) {
	c := Guard{}.Client()
	for _, u := range []string{"https://10.0.0.1/", "https://169.254.169.254/latest/meta-data/", "https://127.0.0.1/", "https://[::1]/"} {
		resp, err := c.Get(u)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s was fetched", u)
			continue
		}
		var blocked *BlockedAddressError
		if !errors.As(err, &blocked) {
			t.Errorf("%s: err = %v, want BlockedAddressError", u, err)
		}
	}
}

func TestClient_DefaultTimeout(t *testing.T) {
	if got := (Guard{}).Client().Timeout; got != DefaultTimeout {
		t.Fatalf("timeout %v, want %v", got, DefaultTimeout)
	}
	if got := (Guard{Timeout: 20 * time.Second}).Client().Timeout; got != 20*time.Second {
		t.Fatalf("timeout %v", got)
	}
}

// tlsTrusting returns a TLS config trusting an httptest TLS server's cert.
func tlsTrusting(ts *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// connectProxy is a CONNECT proxy on loopback that records each tunnel it
// is asked for and opens it to route[target], standing in for production's
// allowlisting egress proxy.
type connectProxy struct {
	*httptest.Server
	mu      sync.Mutex
	asked   []string
	route   map[string]string
	refused int // requests that were not CONNECT
}

func newConnectProxy(t *testing.T, route map[string]string) *connectProxy {
	t.Helper()
	p := &connectProxy{route: route}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		if r.Method != http.MethodConnect {
			p.refused++
			p.mu.Unlock()
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		p.asked = append(p.asked, r.Host)
		to, ok := p.route[r.Host]
		p.mu.Unlock()
		if !ok {
			http.Error(w, "not in the allowlist", http.StatusForbidden)
			return
		}
		up, err := net.Dial("tcp", to)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, buf); _ = up.Close() }()
		_, _ = io.Copy(conn, up)
		_ = conn.Close()
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *connectProxy) tunnels() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.asked...)
}

// proxied is a TLS server on loopback named vendor as example.com (its
// certificate's name) through the guard's resolver seam, and a guard whose
// proxy tunnels to it.
func proxied(t *testing.T, answer string) (*httptest.Server, *connectProxy, Guard, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	port := netip.MustParseAddrPort(ts.Listener.Addr().String()).Port()
	target := fmt.Sprintf("example.com:%d", port)
	p := newConnectProxy(t, map[string]string{target: ts.Listener.Addr().String()})
	pu, _ := url.Parse(p.URL)
	g := Guard{
		AllowLoopback: true,
		TLS:           tlsTrusting(ts),
		Proxy:         pu,
		LookupNetIP: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(answer)}, nil
		},
	}
	return ts, p, g, "https://" + target
}

// TestProxy_TunnelsToTheTarget: with a proxy, the request reaches its
// target only through the proxy's CONNECT for the target's host:port.
func TestProxy_TunnelsToTheTarget(t *testing.T) {
	_, p, g, base := proxied(t, "127.0.0.1")
	res, err := g.Client().Get(base + "/token")
	if err != nil {
		t.Fatalf("through the proxy: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", res.StatusCode)
	}
	if got := p.tunnels(); len(got) != 1 || got[0] != strings.TrimPrefix(base, "https://") {
		t.Fatalf("tunnels asked: %v", got)
	}
}

// TestProxy_RefusesANonPublicTargetBeforeAsking: a target whose name
// resolves to a private or metadata address is refused before the proxy
// is asked for anything.
func TestProxy_RefusesANonPublicTargetBeforeAsking(t *testing.T) {
	for _, answer := range []string{"10.0.0.1", "169.254.169.254", "0.1.2.3", "2002:7f00:1::1"} {
		_, p, g, base := proxied(t, answer)
		g.AllowLoopback = false
		_, err := g.Client().Get(base + "/token")
		var blocked *BlockedAddressError
		if !errors.As(err, &blocked) {
			t.Fatalf("%s: err = %v, want BlockedAddressError", answer, err)
		}
		if got := p.tunnels(); len(got) != 0 {
			t.Fatalf("%s: the proxy was asked for %v", answer, got)
		}
	}
}

// TestProxy_CarriesHTTPSOnly: with a proxy, a plain http request is
// refused before anything is dialled, whether or not HTTPSOnly is set, so
// nothing reaches the proxy as a forwarded request.
func TestProxy_CarriesHTTPSOnly(t *testing.T) {
	_, p, g, base := proxied(t, "127.0.0.1")
	if res, err := g.Client().Get(strings.Replace(base, "https://", "http://", 1)); err == nil {
		_ = res.Body.Close()
		t.Fatal("a plain http request went out through the proxy")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refused != 0 || len(p.asked) != 0 {
		t.Fatalf("the proxy saw %d forwards and %v tunnels", p.refused, p.asked)
	}
}

// TestProxy_FollowsNoRedirectAndIgnoresTheEnvironment: a redirect ends the
// request, and a proxy named in the environment is never asked, with the
// guard's own proxy set or not.
func TestProxy_FollowsNoRedirectAndIgnoresTheEnvironment(t *testing.T) {
	rogue := newConnectProxy(t, map[string]string{})
	t.Setenv("HTTPS_PROXY", rogue.URL)
	t.Setenv("HTTP_PROXY", rogue.URL)
	_, p, g, base := proxied(t, "127.0.0.1")
	res, err := g.Client().Get(base + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status %d: the redirect was followed", res.StatusCode)
	}
	if len(p.tunnels()) != 1 || len(rogue.tunnels()) != 0 {
		t.Fatalf("own proxy %v, environment's %v", p.tunnels(), rogue.tunnels())
	}
}

// TestProxy_DialsOnlyTheProxy: the proxied dialler refuses every address
// but the proxy's own.
func TestProxy_DialsOnlyTheProxy(t *testing.T) {
	pu, _ := url.Parse("http://agentry-egress-proxy:3128")
	g := Guard{Proxy: pu}
	if _, err := g.dialProxy(context.Background(), "tcp", "93.184.216.34:443"); err == nil || !strings.Contains(err.Error(), "only the egress proxy") {
		t.Fatalf("dial elsewhere: %v", err)
	}
	if got := g.proxyAddr(); got != "agentry-egress-proxy:3128" {
		t.Fatalf("proxy address %q", got)
	}
	pu, _ = url.Parse("http://proxy.internal")
	if got := (Guard{Proxy: pu}).proxyAddr(); got != "proxy.internal:80" {
		t.Fatalf("default port: %q", got)
	}
}

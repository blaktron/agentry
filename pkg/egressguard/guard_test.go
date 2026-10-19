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
		{"100.63.255.255", true},       // just below 100.64.0.0/10
		{"100.64.0.0", false},          // CGNAT, bottom of the range
		{"100.127.255.255", false},     // CGNAT, top of the range
		{"100.128.0.1", true},          // just above 100.64.0.0/10
		{"100.0.0.1", true},            // 100/8 outside the CGNAT block is public
		{"255.255.255.255", false},     // limited broadcast is not global unicast
		{"2002:ac10:1::1", false},      // 6to4 embedding 172.16.0.1
		{"2002:c0a8:101::1", false},    // 6to4 embedding 192.168.1.1
		{"2002:a9fe:a9fe::1", false},   // 6to4 embedding the 169.254.169.254 metadata address
		{"64:ff9b::ac10:1", false},     // NAT64 embedding 172.16.0.1
		{"64:ff9b::a9fe:a9fe", false},  // NAT64 embedding the metadata address
		{"::ac10:1", false},            // IPv4-compatible form of 172.16.0.1
		{"::a9fe:a9fe", false},         // IPv4-compatible form of the metadata address
		{"2001:a00:1::1", true},        // starts like 6to4 (0x20) but is not 2002::/16: not read as 10.0.0.1
		{"2a02:a00:1::1", true},        // second byte 0x02 but not 2002::/16: not read as 10.0.0.1
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := g.IsAllowedIP(ip); got != c.allowed {
			t.Errorf("IsAllowedIP(%s) = %v, want %v", c.ip, got, c.allowed)
		}
	}
	if g.IsAllowedIP(netip.Addr{}) {
		t.Error("the zero address is not a valid destination")
	}
}

func TestGuard_LoopbackSeam(t *testing.T) {
	if (Guard{}).IsAllowedIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("strict guard must block loopback")
	}
	if !(Guard{AllowLoopback: true}).IsAllowedIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("test seam should allow loopback")
	}
	if !(Guard{AllowLoopback: true}).IsAllowedIP(netip.MustParseAddr("::1")) {
		t.Fatal("test seam should allow the v6 loopback too")
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
		_, err := g.DialContext(context.Background(), "tcp", addr)
		var blocked *BlockedAddressError
		if !errors.As(err, &blocked) {
			t.Errorf("dial %s: err = %v, want BlockedAddressError", addr, err)
		}
	}
	// An address that names no port is a malformed destination, not one the
	// guard judged.
	_, err := g.DialContext(context.Background(), "tcp", "10.0.0.1")
	var addrErr *net.AddrError
	if !errors.As(err, &addrErr) {
		t.Errorf("dial without a port: err = %v, want *net.AddrError", err)
	}
}

// TestGuard_DialPinsTheResolvedAddress exercises the resolve-then-check-then-pin
// half of DialContext against a resolver the test controls: the "DNS rebinding
// defeated" claim is that a hostname's answer is checked
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
		"firstbad.example":  {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8")},
		"empty.example":     {},
	}
	// The address each refusal names: the first non-public candidate, or
	// "none" for an answer with no address at all.
	wantIP := map[string]string{
		"private.example":   "10.0.0.1",
		"padded.example":    "169.254.169.254",
		"zeronet.example":   "0.1.2.3",
		"sixtofour.example": "2002:7f00:1::1",
		"firstbad.example":  "10.0.0.1",
		"empty.example":     "none",
	}
	lookupFailure := errors.New("resolver unavailable")
	g := Guard{LookupNetIP: func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := answers[host]; ok {
			return a, nil
		}
		if host == "broken.example" {
			return nil, lookupFailure
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
		if blocked.IP != wantIP[host] {
			t.Errorf("dial %s: blocked address = %q, want %q", host, blocked.IP, wantIP[host])
		}
		wantText := fmt.Sprintf("egress: blocked non-public address for %q (%s)", host, wantIP[host])
		if err.Error() != wantText {
			t.Errorf("dial %s: error text %q, want %q", host, err.Error(), wantText)
		}
	}

	// A resolver failure comes back as itself, not as a verdict on an address.
	_, err := g.DialContext(context.Background(), "tcp", "broken.example:443")
	var blockedByFailure *BlockedAddressError
	if !errors.Is(err, lookupFailure) || errors.As(err, &blockedByFailure) {
		t.Errorf("dial after a resolver failure: err = %v, want the resolver's own error", err)
	}

	// The system resolver is the default: a name it answers with loopback is
	// refused for that address, not for an empty answer.
	_, err = Guard{}.DialContext(context.Background(), "tcp", "localhost:1")
	var viaSystem *BlockedAddressError
	if !errors.As(err, &viaSystem) || (viaSystem.IP != "127.0.0.1" && viaSystem.IP != "::1") {
		t.Errorf("dial localhost through the system resolver: err = %v, want a loopback BlockedAddressError", err)
	}

	// Every candidate public: the dial goes to the first checked literal. A
	// loopback httptest listener stands in for it through the test seam, and
	// the resolver answers a name the listener never registered — proof the
	// connect used the literal, not a second lookup.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	lis := netip.MustParseAddrPort(ts.Listener.Addr().String())
	pinned := Guard{AllowLoopback: true, LookupNetIP: func(context.Context, string) ([]netip.Addr, error) {
		// A second candidate that clears the guard but nothing listens on:
		// the dial must go to the first.
		return []netip.Addr{lis.Addr(), netip.MustParseAddr("127.0.0.2")}, nil
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

	// The standard library never proxies a loopback destination, so the
	// request above would not take the environment's proxy even if the client
	// asked for it. A name that resolves to the loopback server is not exempt,
	// and the client itself names no proxy function.
	port := netip.MustParseAddrPort(ts.Listener.Addr().String()).Port()
	named := Guard{AllowLoopback: true, TLS: tlsTrusting(ts), LookupNetIP: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}.Client()
	if tr, ok := named.Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatalf("the client's transport names a proxy function: %T", named.Transport)
	}
	resp, err = named.Get(fmt.Sprintf("https://example.com:%d/", port))
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	_ = resp.Body.Close()
	if proxied || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("the request by name took the environment's proxy (status %d, proxied %v)", resp.StatusCode, proxied)
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
	// The refusal says why, and never repeats a password carried in the URL.
	withSecret := strings.Replace(ts.URL, "http://", "http://user:hunter2@", 1)
	_, err := (Guard{AllowLoopback: true, HTTPSOnly: true}).Client().Get(withSecret)
	if err == nil || !strings.Contains(err.Error(), "https only") {
		t.Fatalf("an http request under HTTPSOnly: err = %v, want the https-only refusal", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("the refusal repeats the URL's password: %v", err)
	}
	// Every scheme but https is refused by the guard itself, not left to
	// the transport.
	if _, err := (Guard{AllowLoopback: true, HTTPSOnly: true}).Client().Get("ftp://example.com/"); err == nil || !strings.Contains(err.Error(), "https only") {
		t.Fatalf("an ftp request under HTTPSOnly: err = %v, want the https-only refusal", err)
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
	if DefaultTimeout != 10*time.Second {
		t.Fatalf("DefaultTimeout = %v, want 10s", DefaultTimeout)
	}
	// A negative timeout is no timeout: it falls back to the default rather
	// than disabling the bound.
	if got := (Guard{Timeout: -time.Second}).Client().Timeout; got != DefaultTimeout {
		t.Fatalf("negative timeout became %v, want %v", got, DefaultTimeout)
	}
}

// TestClient_TransportBounds: the transport bounds the TLS handshake and the
// response headers by the guard's timeout, takes no environment proxy, and
// keeps no connection for reuse, so each request is dialled and checked anew.
func TestClient_TransportBounds(t *testing.T) {
	for _, want := range []time.Duration{DefaultTimeout, 20 * time.Second} {
		var g Guard
		if want != DefaultTimeout {
			g.Timeout = want
		}
		tr, ok := g.Client().Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport is %T", g.Client().Transport)
		}
		if tr.TLSHandshakeTimeout != want || tr.ResponseHeaderTimeout != want {
			t.Errorf("handshake %v, response header %v, want both %v", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, want)
		}
		if tr.Proxy != nil || !tr.DisableKeepAlives {
			t.Errorf("proxy func set %v, keep-alives disabled %v", tr.Proxy != nil, tr.DisableKeepAlives)
		}
	}
	var mu sync.Mutex
	conns := 0
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	ts.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			mu.Lock()
			conns++
			mu.Unlock()
		}
	}
	ts.StartTLS()
	defer ts.Close()
	c := Guard{AllowLoopback: true, TLS: tlsTrusting(ts)}.Client()
	for range 2 {
		resp, err := c.Get(ts.URL)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		_ = resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if conns != 2 {
		t.Fatalf("two requests used %d connections, want 2 (no reuse)", conns)
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

// proxied starts a TLS server on loopback, which the guard's resolver seam
// names example.com (its certificate's name), and returns a CONNECT proxy
// that tunnels to it, a guard through that proxy and the server's base.
func proxied(t *testing.T, answer string) (*connectProxy, Guard, string) {
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
		LookupNetIP: func(_ context.Context, host string) ([]netip.Addr, error) {
			// The target's name alone, never host:port.
			if host != "example.com" {
				return nil, fmt.Errorf("lookup of %q, want example.com", host)
			}
			return []netip.Addr{netip.MustParseAddr(answer)}, nil
		},
	}
	return p, g, "https://" + target
}

// TestProxy_TunnelsToTheTarget: with a proxy, the request reaches its
// target only through the proxy's CONNECT for the target's host:port.
func TestProxy_TunnelsToTheTarget(t *testing.T) {
	p, g, base := proxied(t, "127.0.0.1")
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

	// The address policy judges the target, not the proxy: a guard that
	// refuses loopback still reaches its (here loopback) proxy and a public
	// target through it.
	p2, g2, base2 := proxied(t, "93.184.216.34")
	g2.AllowLoopback = false
	res, err = g2.Client().Get(base2 + "/token")
	if err != nil {
		t.Fatalf("through a loopback proxy under the strict guard: %v", err)
	}
	_ = res.Body.Close()
	if got := p2.tunnels(); len(got) != 1 {
		t.Fatalf("tunnels asked under the strict guard: %v", got)
	}
}

// TestProxy_RefusesANonPublicTargetBeforeAsking: a target whose name
// resolves to a private or metadata address is refused before the proxy
// is asked for anything.
func TestProxy_RefusesANonPublicTargetBeforeAsking(t *testing.T) {
	for _, answer := range []string{"10.0.0.1", "169.254.169.254", "0.1.2.3", "2002:7f00:1::1"} {
		p, g, base := proxied(t, answer)
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
	p, g, base := proxied(t, "127.0.0.1")
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
	p, g, base := proxied(t, "127.0.0.1")
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
	pu, _ = url.Parse("https://proxy.internal")
	if got := (Guard{Proxy: pu}).proxyAddr(); got != "proxy.internal:443" {
		t.Fatalf("default https port: %q", got)
	}
}

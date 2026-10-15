// Package egressguard is the core's SSRF egress guard: every fetch the
// registry makes to an address someone else chose (a webhook endpoint, an
// OIDC issuer, a README image, an MCP server's vendor) goes through it. A
// candidate address must be public unicast, the address dialled is the one
// checked (no second lookup between the check and the connect), no
// redirect is followed and no proxy is taken from the environment.
//
// It lives in pkg/ so that modules outside the core use this one
// implementation rather than a copy: the enterprise build's vault vendor
// client and the CLI's OAuth fetches. internal/webhook keeps its names as
// aliases of these.
package egressguard

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// DefaultTimeout bounds one request when a Guard names no Timeout: the
// webhook delivery's 10 s.
const DefaultTimeout = 10 * time.Second

// BlockedAddressError is the guarded dialer's refusal of a destination that
// resolves to a non-public address, or to none.
type BlockedAddressError struct {
	Host string
	IP   string
}

func (e *BlockedAddressError) Error() string {
	return fmt.Sprintf("egress: blocked non-public address for %q (%s)", e.Host, e.IP)
}

// Guard is the SSRF egress policy. The zero value is production's.
//
// AllowLoopback is a test-only seam so a loopback httptest server can be
// reached; production leaves it false. LookupNetIP is the resolver seam;
// nil means net.DefaultResolver. Tests use it to answer a name with an
// address of their choosing, the only way to exercise the resolve-then-pin
// half of DialContext. TLS is the client's TLS configuration: nil in
// production (system roots), a pool trusting an httptest certificate in a
// test. Timeout bounds one request (DefaultTimeout when zero). HTTPSOnly
// refuses a request that is not https before anything is dialled, for a
// caller whose every destination must be (an OAuth vendor).
//
// Proxy, when set, is a fixed CONNECT proxy the operator names:
// production's worker reaches vendors' token endpoints only through its
// allowlisting egress proxy. The client then dials that proxy's address
// and nothing else, asks it for a tunnel to the target, and before asking
// resolves the target's name and refuses it if any answer is not public
// unicast; only https is carried, whatever HTTPSOnly says. The proxy
// resolves the name again when it opens the tunnel, so this check is not
// pinned the way a direct dial is: the proxy's own exact-host allowlist is
// what bounds where a tunnel goes. The environment's proxy settings are
// never read, with or without it.
type Guard struct {
	AllowLoopback bool
	LookupNetIP   func(ctx context.Context, host string) ([]netip.Addr, error)
	TLS           *tls.Config
	Timeout       time.Duration
	HTTPSOnly     bool
	Proxy         *url.URL
}

// IsAllowedIP reports whether ip is a public unicast address safe to reach.
// It blocks loopback, RFC1918 / RFC4193 private ranges, link-local (incl. the
// 169.254.169.254 cloud metadata endpoint), multicast, unspecified, the whole
// of 0.0.0.0/8, and any non-global-unicast address. IPv4-mapped IPv6 is
// unmapped first so ::ffff:10.0.0.1 cannot smuggle a private v4 address past
// the check, and an IPv6 address that embeds an IPv4 one (6to4, NAT64, the
// deprecated IPv4-compatible form) is judged by the address it embeds.
func (g Guard) IsAllowedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if v4, ok := embeddedIPv4(ip); ok {
		// 2002:7f00:1::1 is 127.0.0.1 to a 6to4 relay and 64:ff9b::a00:1 is
		// 10.0.0.1 to a NAT64 gateway: on a host that routes those prefixes
		// the packet lands where the embedded address says, so the embedded
		// address is what the policy has to judge.
		return g.IsAllowedIP(v4)
	}
	if ip.IsLoopback() {
		return g.AllowLoopback
	}
	if ip.IsPrivate() || // RFC1918 (10/8, 172.16/12, 192.168/16) + RFC4193 (fc00::/7)
		ip.IsLinkLocalUnicast() || // 169.254/16 (incl. metadata 169.254.169.254) + fe80::/10
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		b := ip.As4()
		// 0.0.0.0/8 is "this network" (RFC 1122 §3.2.1.3). IsUnspecified
		// covers only 0.0.0.0 itself, and Linux routes the entire /8 to the
		// loopback interface, so 0.1.2.3:5432 is the host's own Postgres.
		if b[0] == 0 {
			return false
		}
		// Carrier-grade NAT 100.64.0.0/10 (RFC6598): not routable, treat as private.
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}

// embeddedIPv4 returns the IPv4 address an IPv6 address carries under one of
// the transition schemes that route to it: 6to4 (2002::/16, RFC 3056, the v4
// address in bits 16-47), the NAT64 well-known prefix (64:ff9b::/96, RFC
// 6052, the v4 address in the low 32 bits) and the deprecated IPv4-compatible
// form (::/96). The NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215) is
// reported as the unspecified address so the caller refuses it outright: it
// is never routable across the public internet. IPv4-mapped addresses are
// not handled here; the caller unmaps those first.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() || ip.Is4In6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case b[0] == 0x20 && b[1] == 0x02:
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0 && b[5] == 1:
		return netip.IPv4Unspecified(), true
	case b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && [8]byte(b[4:12]) == [8]byte{}:
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case [12]byte(b[:12]) == [12]byte{} && !ip.IsUnspecified() && !ip.IsLoopback():
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// checked resolves host, a name or a literal, and returns its addresses if
// every one is public (fail closed on the first that is not: an attacker who
// controls DNS could otherwise pad the answer with one public address).
func (g Guard) checked(ctx context.Context, host string) ([]netip.Addr, error) {
	var candidates []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		candidates = []netip.Addr{ip}
	} else {
		ips, err := g.lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		candidates = ips
	}
	if len(candidates) == 0 {
		return nil, &BlockedAddressError{Host: host, IP: "none"}
	}
	for _, ip := range candidates {
		if !g.IsAllowedIP(ip) {
			return nil, &BlockedAddressError{Host: host, IP: ip.String()}
		}
	}
	return candidates, nil
}

// DialContext resolves the host, verifies every candidate address, and dials a
// verified address directly (not the hostname) so a DNS answer cannot change
// between the check and the connect (TOCTOU / DNS-rebinding defense). Because
// this runs on every attempt, re-resolution per attempt is inherent.
// It is exported for a caller that must build its own transport; Client is
// the usual way in.
func (g Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	candidates, err := g.checked(ctx, host)
	if err != nil {
		return nil, err
	}
	// All candidates cleared; dial the first verified address explicitly.
	var dialer net.Dialer
	target := net.JoinHostPort(candidates[0].String(), port)
	return dialer.DialContext(ctx, network, target)
}

// proxyAddr is the proxy's host:port, its scheme's port when it names none.
func (g Guard) proxyAddr() string {
	port := g.Proxy.Port()
	if port == "" {
		port = "80"
		if g.Proxy.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(g.Proxy.Hostname(), port)
}

// dialProxy dials the operator's proxy and refuses any other address: with
// a proxy, nothing but the proxy is ever dialled.
func (g Guard) dialProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr != g.proxyAddr() {
		return nil, fmt.Errorf("egress: refused to dial %s: only the egress proxy %s is dialled", addr, g.proxyAddr())
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

func (g Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.LookupNetIP != nil {
		return g.LookupNetIP(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Client is an HTTP client bound to the guard: the checked dialer, no
// redirect followed, no proxy from the environment, no connection kept for
// reuse, and the guard's timeout on the whole request, the TLS handshake and
// the response's headers.
func (g Guard) Client() *http.Client {
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	t := &http.Transport{
		DialContext:           g.DialContext,
		TLSClientConfig:       g.TLS,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		Proxy:                 nil, // never honor proxy env for egress
	}
	var rt http.RoundTripper = t
	if g.Proxy != nil {
		t.Proxy = http.ProxyURL(g.Proxy)
		t.DialContext = g.dialProxy
		rt = checkedTarget{guard: g, inner: rt}
	}
	if g.HTTPSOnly || g.Proxy != nil {
		rt = httpsOnly{inner: rt}
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects
		},
		Transport: rt,
	}
}

// checkedTarget resolves a proxied request's target and refuses it before
// the proxy is asked for a tunnel when any of its addresses is not public.
type checkedTarget struct {
	guard Guard
	inner http.RoundTripper
}

func (t checkedTarget) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, err := t.guard.checked(r.Context(), r.URL.Hostname()); err != nil {
		return nil, err
	}
	return t.inner.RoundTrip(r)
}

// httpsOnly refuses any request that is not https before it dials.
type httpsOnly struct{ inner http.RoundTripper }

func (t httpsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, fmt.Errorf("egress: refused to reach %s: https only", r.URL.Redacted())
	}
	return t.inner.RoundTrip(r)
}

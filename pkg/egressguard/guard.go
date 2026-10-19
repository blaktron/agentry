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

// IsAllowedIP reports whether ip is a public unicast address worth reaching.
// It refuses the ranges the IANA IPv4 and IPv6 special-purpose registries
// list as not globally reachable (see specialPurpose), the multicast ranges,
// loopback unless the test seam allows it, and any IPv6 address outside the
// global unicast space 2000::/3. IPv4-mapped IPv6 is unmapped first so
// ::ffff:10.0.0.1 cannot smuggle a private v4 address past the check, and an
// IPv6 address that embeds an IPv4 one (6to4, NAT64, IPv4-translated, ISATAP)
// is judged by the address it embeds.
func (g Guard) IsAllowedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	// A zoned address is never inside a netip.Prefix, so the zone must go
	// before any range is consulted.
	ip = ip.WithZone("").Unmap()
	if v4, ok := isatapIPv4(ip); ok && !g.IsAllowedIP(v4) {
		// An ISATAP address is an ordinary address under its own prefix that
		// also names a tunnel endpoint: it is refused when either is. The
		// identifier is checked first because it can sit under a 6to4 prefix.
		return false
	}
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
	if inSpecialPurpose(ip, specialPurpose) {
		return false
	}
	if ip.Is6() && !globalUnicastSpace.Contains(ip) {
		return false
	}
	// Backstop, so that an address the table and the 2000::/3 check both miss
	// still has to be one the standard library calls global unicast.
	return ip.IsGlobalUnicast()
}

// specialRange is one row of the IANA special-purpose registries that is not
// globally reachable.
type specialRange struct {
	prefix netip.Prefix
	// source is the registry entry, for a reader of the table.
	source string
}

// globalUnicastSpace is the part of the IPv6 address space the IANA has
// allocated for global unicast use (RFC 4291); an address outside it is not
// assigned to any public host.
var globalUnicastSpace = netip.MustParsePrefix("2000::/3")

// specialPurpose lists the IANA special-purpose ranges the guard refuses.
// 127.0.0.0/8 and ::1/128 are not here: loopback is the guard's test seam.
// 2002::/16 (6to4), 64:ff9b::/96 (NAT64), ::ffff:0:0:0/96 (IPv4-translated)
// and ISATAP identifiers are judged by the IPv4 address they carry, see
// embeddedIPv4 and isatapIPv4; ::/96 (IPv4-compatible, deprecated) lies
// outside the global unicast space and is refused by that check. Ranges with
// globally reachable sub-allocations (192.0.0.0/24 and 2001::/23 hold anycast
// service addresses) are refused whole.
var specialPurpose = []specialRange{
	// https://www.iana.org/assignments/iana-ipv4-special-registry/
	{netip.MustParsePrefix("0.0.0.0/8"), `"This network" (RFC 791)`},
	{netip.MustParsePrefix("10.0.0.0/8"), "Private-Use (RFC 1918)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "Shared Address Space (RFC 6598)"},
	{netip.MustParsePrefix("169.254.0.0/16"), "Link Local (RFC 3927)"},
	{netip.MustParsePrefix("172.16.0.0/12"), "Private-Use (RFC 1918)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF Protocol Assignments (RFC 6890)"},
	{netip.MustParsePrefix("192.0.2.0/24"), "Documentation, TEST-NET-1 (RFC 5737)"},
	{netip.MustParsePrefix("192.88.99.0/24"), "Deprecated 6to4 Relay Anycast (RFC 7526)"},
	{netip.MustParsePrefix("192.168.0.0/16"), "Private-Use (RFC 1918)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "Benchmarking (RFC 2544)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "Documentation, TEST-NET-2 (RFC 5737)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "Documentation, TEST-NET-3 (RFC 5737)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "Multicast (RFC 5771)"},
	{netip.MustParsePrefix("240.0.0.0/4"), "Reserved and Limited Broadcast (RFC 1112, RFC 8190)"},
	// https://www.iana.org/assignments/iana-ipv6-special-registry/
	{netip.MustParsePrefix("::/128"), "Unspecified Address (RFC 4291)"},
	{netip.MustParsePrefix("100::/64"), "Discard-Only Address Block (RFC 6666)"},
	{netip.MustParsePrefix("100:0:0:1::/64"), "Dummy IPv6 Prefix (RFC 9780)"},
	{netip.MustParsePrefix("2001::/23"), "IETF Protocol Assignments, with Teredo, benchmarking and ORCHID"},
	{netip.MustParsePrefix("2001:db8::/32"), "Documentation (RFC 3849)"},
	{netip.MustParsePrefix("3fff::/20"), "Documentation (RFC 9637)"},
	{netip.MustParsePrefix("5f00::/16"), "Segment Routing SIDs (RFC 9602)"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "Local-Use IPv4/IPv6 Translation (RFC 8215)"},
	{netip.MustParsePrefix("fc00::/7"), "Unique-Local (RFC 4193)"},
	{netip.MustParsePrefix("fe80::/10"), "Link-Local Unicast (RFC 4291)"},
	{netip.MustParsePrefix("fec0::/10"), "Deprecated Site-Local Unicast (RFC 3879)"},
	{netip.MustParsePrefix("ff00::/8"), "Multicast (RFC 4291)"},
}

func inSpecialPurpose(ip netip.Addr, ranges []specialRange) bool {
	for _, r := range ranges {
		if r.prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// embeddedIPv4 returns the IPv4 address an IPv6 address carries under one of
// the transition schemes that route to it: 6to4 (2002::/16, RFC 3056, the v4
// address in bits 16-47), the NAT64 well-known prefix (64:ff9b::/96, RFC
// 6052, the v4 address in the low 32 bits) and the IPv4-translated form
// (::ffff:0:0:0/96, RFC 2765, the v4 address in the low 32 bits). The
// deprecated IPv4-compatible form (::/96) and the NAT64 local-use prefix
// (64:ff9b:1::/48) are not here: both lie outside the global unicast space and
// are refused outright. IPv4-mapped addresses are not handled here; the
// caller unmaps those first.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() || ip.Is4In6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case b[0] == 0x20 && b[1] == 0x02:
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && [8]byte(b[4:12]) == [8]byte{}:
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case [8]byte(b[:8]) == [8]byte{} && b[8] == 0xff && b[9] == 0xff && b[10] == 0 && b[11] == 0:
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// isatapIPv4 returns the IPv4 address an ISATAP interface identifier carries
// (RFC 5214: 0000:5efe or 0200:5efe followed by the v4 address, under any
// /64 prefix).
func isatapIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() || ip.Is4In6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	if (b[8] == 0x00 || b[8] == 0x02) && b[9] == 0 && b[10] == 0x5e && b[11] == 0xfe {
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

// Package webhook implements org-configurable webhooks (§9.3): HMAC-SHA256
// signed delivery through the async queue with 5× exponential backoff, and the
// T-08 SSRF egress guard (https-only, re-resolve to public unicast per
// attempt, block private/link-local/metadata ranges, no redirect following,
// 10s timeout).
package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// DeliveryTimeout bounds a single delivery attempt (§9.3).
const DeliveryTimeout = 10 * time.Second

// ErrBlockedAddress is returned by the guarded dialer when a destination
// resolves to a non-public address (T-08).
type ErrBlockedAddress struct {
	Host string
	IP   string
}

func (e *ErrBlockedAddress) Error() string {
	return fmt.Sprintf("webhook: blocked non-public address for %q (%s)", e.Host, e.IP)
}

// Guard is the SSRF egress policy. AllowLoopback is a test-only seam so a
// loopback httptest server can receive a delivery; production leaves it false.
// LookupNetIP is the resolver seam; nil means net.DefaultResolver. Tests use
// it to answer a name with an address of their choosing, which is the only
// way to exercise the resolve-then-pin half of dialContext.
type Guard struct {
	AllowLoopback bool
	LookupNetIP   func(ctx context.Context, host string) ([]netip.Addr, error)
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

// dialContext resolves the host, verifies every candidate address, and dials a
// verified address directly (not the hostname) so a DNS answer cannot change
// between the check and the connect (TOCTOU / DNS-rebinding defense). Because
// this runs on every attempt, re-resolution per attempt (§9.3) is inherent.
func (g Guard) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
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
		return nil, &ErrBlockedAddress{Host: host, IP: "none"}
	}
	var dialer net.Dialer
	for _, ip := range candidates {
		if !g.IsAllowedIP(ip) {
			// Fail closed on the first non-public address: an attacker who
			// controls DNS could otherwise pad the answer with one public IP.
			return nil, &ErrBlockedAddress{Host: host, IP: ip.String()}
		}
	}
	// All candidates cleared; dial the first verified address explicitly.
	target := net.JoinHostPort(candidates[0].String(), port)
	return dialer.DialContext(ctx, network, target)
}

func (g Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.LookupNetIP != nil {
		return g.LookupNetIP(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// NewHTTPClient builds a delivery client bound to the guard: no redirect
// following, the SSRF-checked dialer, and DeliveryTimeout. tlsConfig is nil in
// production (system roots); tests pass a pool trusting the httptest cert.
func NewHTTPClient(g Guard, tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Timeout: DeliveryTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects (T-08)
		},
		Transport: &http.Transport{
			DialContext:           g.dialContext,
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   DeliveryTimeout,
			ResponseHeaderTimeout: DeliveryTimeout,
			DisableKeepAlives:     true,
			Proxy:                 nil, // never honor proxy env for egress
		},
	}
}

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
type Guard struct {
	AllowLoopback bool
}

// IsAllowedIP reports whether ip is a public unicast address safe to reach.
// It blocks loopback, RFC1918 / RFC4193 private ranges, link-local (incl. the
// 169.254.169.254 cloud metadata endpoint), multicast, unspecified, and any
// non-global-unicast address. IPv4-mapped IPv6 is unmapped first so
// ::ffff:10.0.0.1 cannot smuggle a private v4 address past the check.
func (g Guard) IsAllowedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
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
	// Carrier-grade NAT 100.64.0.0/10 (RFC6598): not routable, treat as private.
	if ip.Is4() && ip.As4()[0] == 100 {
		b := ip.As4()
		if b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	return ip.IsGlobalUnicast()
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
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
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

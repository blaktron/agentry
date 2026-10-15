// Package webhook implements org-configurable webhooks: HMAC-SHA256
// signed delivery through the async queue with 5× exponential backoff, and the
// SSRF egress guard (https-only, re-resolve to public unicast per
// attempt, block private/link-local/metadata ranges, no redirect following,
// 10s timeout).
package webhook

import (
	"crypto/tls"
	"net/http"

	"github.com/blaktron/agentry/pkg/egressguard"
)

// DeliveryTimeout bounds a single delivery attempt.
const DeliveryTimeout = egressguard.DefaultTimeout

// ErrBlockedAddress is returned by the guarded dialer when a destination
// resolves to a non-public address. The guard itself is
// pkg/egressguard's; these names are its aliases, so the core's callers
// and an extension's share one implementation.
type ErrBlockedAddress = egressguard.BlockedAddressError

// Guard is the SSRF egress policy (pkg/egressguard.Guard).
type Guard = egressguard.Guard

// NewHTTPClient builds a delivery client bound to the guard: no redirect
// following, the SSRF-checked dialer, and DeliveryTimeout unless the guard
// names its own. tlsConfig is nil in production (system roots); tests pass a
// pool trusting the httptest cert.
func NewHTTPClient(g Guard, tlsConfig *tls.Config) *http.Client {
	g.TLS = tlsConfig
	if g.Timeout <= 0 {
		g.Timeout = DeliveryTimeout
	}
	return g.Client()
}

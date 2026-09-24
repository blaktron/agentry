package api

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/ratelimit"
)

// limitClasses holds the computed §19 rate classes from config.
type limitClasses struct {
	authed      rate.Limit
	authedBurst int
	anon        rate.Limit
	anonBurst   int
	login       rate.Limit
	loginBurst  int
}

func classesFromConfig(l config.Limits) limitClasses {
	return limitClasses{
		authed:      ratelimit.PerHour(l.AuthedPerHour),
		authedBurst: l.AuthedBurstPerMin,
		anon:        ratelimit.PerMinute(l.AnonymousPerMin),
		anonBurst:   l.AnonymousPerMin,
		login:       ratelimit.PerMinute(l.LoginPerMin),
		loginBurst:  l.LoginPerMin,
	}
}

// limitResult is one rate-limit decision plus the numbers the §9.1
// RateLimit-* headers report back to the caller.
type limitResult = ratelimit.Result

// allowLogin applies the §19 login/register class limit (per client IP),
// writes the §9.1 RateLimit-* headers, and on refusal writes the 429 problem.
// Credential-establishing endpoints — register, login, SSO/social start and
// callback, the SSO landing — sit outside the chokepoint, so this is the one
// budget standing between them and a password-spraying client.
func (s *Server) allowLogin(w http.ResponseWriter, r *http.Request) bool {
	res := s.limits.Allow("login", clientIP(r), s.classes.login, s.classes.loginBurst)
	writeRateLimitHeaders(w, res)
	if !res.OK {
		s.rateLimited(r, "login")
		problemTooMany(w, r, "Too many sign-in and registration attempts. Wait for the Retry-After interval.")
		return false
	}
	return true
}

// writeRateLimitHeaders emits the §9.1 RateLimit-* trio, plus Retry-After
// when the request was refused. Headers are set before the response body so
// they land on 2xx and 429 alike — a client should not have to be throttled
// to learn its budget.
func writeRateLimitHeaders(w http.ResponseWriter, res limitResult) {
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(res.Limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))
	reset := int(res.Reset.Round(time.Second) / time.Second)
	if reset < 1 {
		reset = 1
	}
	h.Set("RateLimit-Reset", strconv.Itoa(reset))
	if !res.OK {
		h.Set("Retry-After", strconv.Itoa(reset))
	}
}

// rateLimited names a refusal for the log contract (docs/logging.md):
// `event=http.rate_limited` with the class that refused, on the request's
// id; the address and the actor are on the request's access line.
func (s *Server) rateLimited(r *http.Request, class string) {
	s.log.InfoContext(r.Context(), "rate limited", logevent.HTTPRateLimited.Attr(), "class", class, "route", routeClass(r))
}

// clientIP is the caller's address as resolved once by withMiddleware, and
// the key every per-IP §19 budget and audit record uses. Outside the
// middleware stack (a handler mounted directly on a bare mux) it falls back to
// the peer address rather than guessing at a header nobody validated.
func clientIP(r *http.Request) string {
	if ip := auth.ClientIPFrom(r.Context()); ip != "" {
		return ip
	}
	return peerIP(r)
}

// proxyTrust is who may speak for a client in X-Forwarded-For: hops
// trusted hops (http.trustedProxies), connecting from one of from
// (http.trustedProxyCIDRs) when that list is set.
type proxyTrust struct {
	hops int
	from []netip.Prefix
}

// newProxyTrust builds the trust decision from the listener config. The
// list was validated at load; an entry that still fails to parse turns the
// trust off rather than widening it.
func newProxyTrust(c config.HTTP) proxyTrust {
	from, err := config.ParseCIDRs(c.TrustedProxyCIDRs)
	if err != nil {
		return proxyTrust{}
	}
	return proxyTrust{hops: c.TrustedProxies, from: from}
}

// peerTrusted reports whether r's TCP peer is a hop whose forwarded headers
// this server believes: any peer when a hop count is set without a list (the
// hop count alone, as before agentry#429), only a listed one when the list
// is set, and none when the hop count is 0.
func (t proxyTrust) peerTrusted(r *http.Request) bool {
	if t.hops <= 0 {
		return false
	}
	if len(t.from) == 0 {
		return true
	}
	a, err := netip.ParseAddr(peerIP(r))
	return err == nil && config.InCIDRs(t.from, a)
}

// clientIPWithProxies resolves the caller's address from the peer address and
// X-Forwarded-For.
//
// With http.trustedProxyCIDRs set, a request whose TCP peer is outside the
// listed ranges resolves to that peer and its header is ignored: the trust
// is keyed on who connected, as nginx's set_real_ip_from is, so a client
// that reaches agentryd directly cannot pick its own address whatever the
// hop count says (agentry#429).
//
// With http.trustedProxies at 0 (the default, and correct for a directly
// addressed agentryd) this is the peer address and X-Forwarded-For is ignored
// entirely: the header is client-supplied, so trusting it unconditionally
// would let anyone pick their own rate-limit bucket — and, worse, spend any
// other client's, since sharing a bucket means being able to exhaust it.
//
// Behind N trusted hops (CloudFront → ALB → agentryd is 2), the last N-1
// entries of X-Forwarded-For were appended by infrastructure we control (the
// peer itself never appears in the header), so the entry before them is the
// furthest address a trusted hop vouched for. Anything earlier in the list was
// written by the client and is ignored.
func clientIPWithProxies(r *http.Request, trust proxyTrust) string {
	peer := peerIP(r)
	if !trust.peerTrusted(r) {
		return peer
	}
	trusted := trust.hops
	fwd := parseForwardedFor(r.Header.Values("X-Forwarded-For"))
	// The peer itself is one of the trusted hops and never appears in the
	// header, so N trusted hops means N-1 trusted entries at the tail.
	idx := len(fwd) - trusted
	if idx < 0 {
		// Fewer entries than hops: the chain is shorter than configured —
		// a health check, a direct connection that bypassed the edge, or
		// a hop count set one too high. Whatever is in the header then
		// was not written by a hop this server trusts, so the peer is
		// the only address a client cannot have chosen. Falling back to
		// the oldest entry, as this once did, let a client on a direct
		// connection name a fresh address per request and land in a
		// fresh rate-limit bucket each time (security review 2026-09-20
		// §5.8.2).
		return peer
	}
	return fwd[idx]
}

// parseForwardedFor flattens X-Forwarded-For headers into a list of valid IPs,
// oldest first. Entries that are not IPs are dropped rather than used as a
// bucket key: a garbage value is a key too, and an attacker who can choose it
// can choose which bucket to spend.
func parseForwardedFor(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			host := strings.TrimSpace(part)
			if host == "" {
				continue
			}
			// Tolerate the "ip:port" form some proxies emit.
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

// peerIP is the transport-level remote address.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/ratelimit"
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
		problemTooMany(w, r, "try again later")
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

// clientIP is the caller's address as resolved once by withMiddleware, and
// the key every per-IP §19 budget and audit record uses. Outside the
// middleware stack (a handler mounted directly on a bare mux) it falls back to
// the peer address rather than guessing at a header nobody validated.
func clientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok && ip != "" {
		return ip
	}
	return peerIP(r)
}

// clientIPWithProxies resolves the caller's address from the peer address and
// X-Forwarded-For.
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
func clientIPWithProxies(r *http.Request, trusted int) string {
	peer := peerIP(r)
	if trusted <= 0 {
		return peer
	}
	fwd := parseForwardedFor(r.Header.Values("X-Forwarded-For"))
	// The peer itself is one of the trusted hops and never appears in the
	// header, so N trusted hops means N-1 trusted entries at the tail.
	idx := len(fwd) - trusted
	if idx < 0 {
		// Fewer entries than hops: the chain is shorter than configured
		// (a health check, or a direct connection that bypassed the edge).
		// Fall back to the oldest entry we have, or the peer.
		if len(fwd) == 0 {
			return peer
		}
		idx = 0
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

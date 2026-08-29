package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
)

// rateLimits implements the §19 API rate quotas with in-memory token buckets
// (the D-06 fallback; a Redis-backed implementation replaces this on SaaS
// multi-node deployments behind the same interface).
type rateLimits struct {
	mu      sync.Mutex
	buckets map[string]*bucketEntry
}

type bucketEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

func newRateLimits() *rateLimits {
	rl := &rateLimits{buckets: map[string]*bucketEntry{}}
	go rl.gcLoop()
	return rl
}

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
		authed:      rate.Limit(float64(l.AuthedPerHour) / 3600.0),
		authedBurst: l.AuthedBurstPerMin,
		anon:        rate.Limit(float64(l.AnonymousPerMin) / 60.0),
		anonBurst:   l.AnonymousPerMin,
		login:       rate.Limit(float64(l.LoginPerMin) / 60.0),
		loginBurst:  l.LoginPerMin,
	}
}

// limitResult is one rate-limit decision plus the numbers the §9.1
// RateLimit-* headers report back to the caller.
type limitResult struct {
	OK bool
	// Limit is the burst budget for the class (the quota the headers describe).
	Limit int
	// Remaining is the whole tokens left after this request.
	Remaining int
	// Reset is how long until at least one more token exists.
	Reset time.Duration
}

// allowLogin applies the §19 login/register class limit (per client IP),
// writes the §9.1 RateLimit-* headers, and on refusal writes the 429 problem.
// Credential-establishing endpoints — register, login, SSO/social start and
// callback, the SSO landing — sit outside the chokepoint, so this is the one
// budget standing between them and a password-spraying client.
func (s *Server) allowLogin(w http.ResponseWriter, r *http.Request) bool {
	res := s.limits.allowWithHeaders("login", clientIP(r), s.classes.login, s.classes.loginBurst)
	writeRateLimitHeaders(w, res)
	if !res.OK {
		problemTooMany(w, r, "try again later")
		return false
	}
	return true
}

// allowWithHeaders checks-and-consumes one token for the class+key pair. Both the decision and
// the numbers come from the same locked read, so the headers can never
// describe a different moment than the decision they accompany.
func (rl *rateLimits) allowWithHeaders(class, key string, lim rate.Limit, burst int) limitResult {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	k := class + "|" + key
	e, ok := rl.buckets[k]
	if !ok {
		e = &bucketEntry{lim: rate.NewLimiter(lim, burst)}
		rl.buckets[k] = e
	}
	e.seen = now
	res := limitResult{OK: e.lim.AllowN(now, 1), Limit: burst}

	remaining := int(e.lim.TokensAt(now))
	if remaining < 0 {
		remaining = 0
	}
	res.Remaining = remaining
	// Time to the next whole token. A zero rate never refills; report the
	// window so clients back off rather than hot-looping.
	if r := float64(e.lim.Limit()); r > 0 {
		need := 1 - (e.lim.TokensAt(now) - float64(remaining))
		if need < 0 {
			need = 0
		}
		res.Reset = time.Duration(need / r * float64(time.Second))
	} else {
		res.Reset = time.Hour
	}
	if res.Reset < time.Second {
		res.Reset = time.Second
	}
	return res
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

func (rl *rateLimits) gcLoop() {
	for {
		time.Sleep(10 * time.Minute)
		cutoff := time.Now().Add(-30 * time.Minute)
		rl.mu.Lock()
		for k, e := range rl.buckets {
			if e.seen.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the peer IP (ALB/CloudFront X-Forwarded-For handling is
// an M7 edge concern; direct connections here).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

package api

import (
	"net"
	"net/http"
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

// allow checks-and-consumes one token for the class+key pair.
func (rl *rateLimits) allow(class, key string, lim rate.Limit, burst int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	k := class + "|" + key
	e, ok := rl.buckets[k]
	if !ok {
		e = &bucketEntry{lim: rate.NewLimiter(lim, burst)}
		rl.buckets[k] = e
	}
	e.seen = time.Now()
	return e.lim.Allow()
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

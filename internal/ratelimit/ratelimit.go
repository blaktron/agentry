// Package ratelimit is the shared in-memory token-bucket store behind the
// quotas: the API rate classes, the per-org webhook delivery rate, and the
// per-repo git push budget.
//
// This is the single-node store — correct on one node, approximate across
// replicas, since each process keeps its own buckets. A Redis-backed store
// can replace it behind the same Allow signature on multi-node hosting.
// Where that approximation matters (an N-replica deployment grants roughly N× the
// budget), the call site says so.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DefaultIdleTTL is how long an untouched bucket is kept.
//
// It must be at least as long as the widest window any caller enforces.
// A bucket evicted early is recreated full, which would let a caller reset a
// budget by going quiet — for a 60-per-hour quota, a 30-minute TTL would hand
// back a full budget after a 30-minute pause. At or beyond the window the
// eviction is harmless, because a bucket idle that long has refilled anyway.
const DefaultIdleTTL = 2 * time.Hour

// Result is one decision plus the numbers the RateLimit-* headers report.
type Result struct {
	OK bool
	// Limit is the burst budget for the class (the quota the headers describe).
	Limit int
	// Remaining is the whole tokens left after this request.
	Remaining int
	// Reset is how long until at least one more token exists.
	Reset time.Duration
}

// Buckets is a keyed set of token buckets with idle eviction.
type Buckets struct {
	mu      sync.Mutex
	buckets map[string]*entry
	idleTTL time.Duration
	// stop closes the gc goroutine. Closing is idempotent via stopOnce, so a
	// double Close (defer plus an explicit shutdown path) cannot panic.
	stop     chan struct{}
	stopOnce sync.Once
	// now is the clock, injectable for tests.
	now func() time.Time
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// New creates a bucket store and starts its garbage collector. Call Close to
// stop it: the goroutine holds a reference to every bucket, so a store that is
// created per server and never closed leaks both the goroutine and the map.
func New(idleTTL time.Duration) *Buckets {
	if idleTTL <= 0 {
		idleTTL = DefaultIdleTTL
	}
	b := &Buckets{
		buckets: map[string]*entry{},
		idleTTL: idleTTL,
		stop:    make(chan struct{}),
		now:     time.Now,
	}
	go b.gcLoop(idleTTL / 3)
	return b
}

// Close stops the garbage collector. Safe to call more than once, and safe on
// a nil receiver.
func (b *Buckets) Close() error {
	if b == nil {
		return nil
	}
	b.stopOnce.Do(func() { close(b.stop) })
	return nil
}

// Allow checks and consumes one token for the class+key pair. Both the
// decision and the reported numbers come from the same locked read, so the
// headers can never describe a different moment than the decision they
// accompany.
func (b *Buckets) Allow(class, key string, lim rate.Limit, burst int) Result {
	return b.AllowN(class, key, lim, burst, 1)
}

// AllowN consumes n tokens.
func (b *Buckets) AllowN(class, key string, lim rate.Limit, burst int, n int) Result {
	if burst <= 0 {
		// A zero burst can never admit anything; treat it as "no budget"
		// rather than dividing by it below.
		return Result{OK: false, Limit: 0, Remaining: 0, Reset: time.Second}
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	k := class + "|" + key
	e, ok := b.buckets[k]
	if !ok {
		e = &entry{lim: rate.NewLimiter(lim, burst)}
		b.buckets[k] = e
	}
	e.seen = now
	res := Result{OK: e.lim.AllowN(now, n), Limit: burst}

	remaining := int(e.lim.TokensAt(now))
	if remaining < 0 {
		remaining = 0
	}
	res.Remaining = remaining
	// Time to the next whole token. A zero rate never refills; report an hour
	// so clients back off rather than hot-looping.
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

// Len reports how many buckets are held (tests, and a cheap leak check).
func (b *Buckets) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buckets)
}

func (b *Buckets) gcLoop(every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			b.evictIdle()
		}
	}
}

func (b *Buckets) evictIdle() {
	cutoff := b.now().Add(-b.idleTTL)
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, e := range b.buckets {
		if e.seen.Before(cutoff) {
			delete(b.buckets, k)
		}
	}
}

// PerHour converts an hourly budget to a rate.Limit.
func PerHour(n int) rate.Limit { return rate.Limit(float64(n) / 3600.0) }

// PerMinute converts a per-minute budget to a rate.Limit.
func PerMinute(n int) rate.Limit { return rate.Limit(float64(n) / 60.0) }

// PerSecond converts a per-second budget to a rate.Limit.
func PerSecond(n float64) rate.Limit { return rate.Limit(n) }

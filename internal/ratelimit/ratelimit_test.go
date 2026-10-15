package ratelimit

import (
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// withClock returns a store whose clock the test drives, so rate behaviour is
// asserted deterministically rather than by sleeping.
func withClock(t *testing.T, idleTTL time.Duration) (*Buckets, func(time.Duration)) {
	t.Helper()
	b := New(idleTTL)
	t.Cleanup(func() { _ = b.Close() })
	now := time.Now()
	b.now = func() time.Time { return now }
	return b, func(d time.Duration) { now = now.Add(d) }
}

// Quota: 5 webhook deliveries/s per org, with a one-second bucket.
func TestPerSecondBudgetRefillsOverTime(t *testing.T) {
	b, advance := withClock(t, time.Hour)
	lim, burst := PerSecond(5), 1

	if !b.Allow("webhook", "org-a", lim, burst).OK {
		t.Fatal("the first delivery was refused")
	}
	if b.Allow("webhook", "org-a", lim, burst).OK {
		t.Fatal("a second delivery in the same instant was allowed past a burst of 1")
	}
	// 5/s means a token every 200ms.
	advance(200 * time.Millisecond)
	if !b.Allow("webhook", "org-a", lim, burst).OK {
		t.Fatal("no token after 200ms at 5/s")
	}
	// A different org has its own budget: the limit is per org, not global.
	if !b.Allow("webhook", "org-b", lim, burst).OK {
		t.Fatal("a second org inherited the first one's exhausted bucket")
	}
}

// Quota: 60 pushes/h per repo, burst equal to the whole hourly budget so a run
// of commits is not paced one per minute.
func TestPerHourBudgetExhaustsAndRecovers(t *testing.T) {
	b, advance := withClock(t, 2*time.Hour)
	lim, burst := PerHour(60), 60

	for i := range 60 {
		if !b.Allow("push", "repo-1", lim, burst).OK {
			t.Fatalf("push %d within the hourly budget was refused", i+1)
		}
	}
	res := b.Allow("push", "repo-1", lim, burst)
	if res.OK {
		t.Fatal("the 61st push in an hour was allowed")
	}
	if res.Reset <= 0 {
		t.Fatal("a refusal must say when the next token arrives")
	}
	// One token per minute at 60/h.
	advance(time.Minute)
	if !b.Allow("push", "repo-1", lim, burst).OK {
		t.Fatal("no token a minute after exhausting a 60/h budget")
	}
}

// A bucket evicted before its window expires comes back full, which would let
// a caller reset an hourly budget by going quiet. DefaultIdleTTL exists to
// prevent exactly that, and it must stay at or above the widest window.
func TestIdleTTLIsNotShorterThanAnEnforcedWindow(t *testing.T) {
	if DefaultIdleTTL < time.Hour {
		t.Fatalf("DefaultIdleTTL is %s; the git push quota is enforced over an hour, "+
			"so a shorter TTL hands back a full budget after a pause", DefaultIdleTTL)
	}
}

func TestEvictionDropsOnlyIdleBuckets(t *testing.T) {
	b, advance := withClock(t, time.Hour)
	lim := PerHour(60)

	b.Allow("push", "old", lim, 60)
	advance(90 * time.Minute)
	b.Allow("push", "fresh", lim, 60)
	if b.Len() != 2 {
		t.Fatalf("Len = %d, want 2 before eviction", b.Len())
	}

	b.evictIdle()
	if b.Len() != 1 {
		t.Fatalf("Len = %d after eviction, want 1 (the idle bucket dropped)", b.Len())
	}
	// The surviving bucket must be the recently used one.
	if _, ok := b.buckets["push|fresh"]; !ok {
		t.Error("eviction dropped the recently used bucket")
	}
}

// A zero burst can admit nothing; it must refuse rather than divide by it.
func TestZeroBurstRefusesWithoutPanicking(t *testing.T) {
	b, _ := withClock(t, time.Hour)
	res := b.Allow("c", "k", PerSecond(5), 0)
	if res.OK {
		t.Error("a zero burst admitted a request")
	}
	if res.Reset <= 0 {
		t.Error("a refusal with no budget still needs a Retry-After")
	}
}

// A zero rate never refills; reporting Reset=0 would have clients hot-loop.
func TestZeroRateReportsABackoff(t *testing.T) {
	b, _ := withClock(t, time.Hour)
	b.Allow("c", "k", 0, 1) // consume the single token
	res := b.Allow("c", "k", 0, 1)
	if res.OK {
		t.Fatal("a zero-rate bucket refilled")
	}
	if res.Reset < time.Second {
		t.Errorf("Reset = %s, want a real backoff", res.Reset)
	}
}

func TestClassesAreIndependent(t *testing.T) {
	b, _ := withClock(t, time.Hour)
	lim, burst := PerSecond(1), 1
	if !b.Allow("push", "same-key", lim, burst).OK {
		t.Fatal("first class refused")
	}
	// Same key, different class: a repo's push budget is not a webhook budget.
	if !b.Allow("webhook", "same-key", lim, burst).OK {
		t.Error("a second class shared the first one's bucket")
	}
}

func TestAllowNConsumesMultiple(t *testing.T) {
	b, _ := withClock(t, time.Hour)
	if !b.AllowN("c", "k", PerHour(60), 60, 60).OK {
		t.Fatal("consuming the whole burst at once was refused")
	}
	if b.Allow("c", "k", PerHour(60), 60).OK {
		t.Error("a token remained after the whole burst was consumed")
	}
}

func TestConcurrentAllowIsRaceFree(t *testing.T) {
	b := New(time.Hour)
	t.Cleanup(func() { _ = b.Close() })
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Allow("c", "shared", rate.Limit(1000), 1000)
		}()
	}
	wg.Wait()
	if b.Len() != 1 {
		t.Errorf("Len = %d, want 1 shared bucket", b.Len())
	}
}

func TestConversionHelpers(t *testing.T) {
	if got := PerHour(3600); got != rate.Limit(1) {
		t.Errorf("PerHour(3600) = %v, want 1/s", got)
	}
	if got := PerMinute(60); got != rate.Limit(1) {
		t.Errorf("PerMinute(60) = %v, want 1/s", got)
	}
	if got := PerSecond(5); got != rate.Limit(5) {
		t.Errorf("PerSecond(5) = %v, want 5/s", got)
	}
}

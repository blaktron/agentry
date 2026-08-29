package api

// The §9.1 RateLimit-* reporting and the §9.1 limit/offset clamping. These
// are in-package tests because the limiter and the clamp helpers are
// deliberately unexported — the contract they serve is the HTTP surface, but
// the arithmetic is worth pinning directly.

import (
	"encoding/base64"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

func mustUUID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func encodeCursorRaw(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestRateLimitHeadersCountDownAndRefuse(t *testing.T) {
	rl := &rateLimits{buckets: map[string]*bucketEntry{}}
	// One request per second, burst of 3.
	const burst = 3
	lim := rate.Limit(1)

	for i := 0; i < burst; i++ {
		res := rl.allowWithHeaders("authed", "u1", lim, burst)
		if !res.OK {
			t.Fatalf("request %d within the burst was refused", i+1)
		}
		if res.Limit != burst {
			t.Fatalf("RateLimit-Limit = %d, want %d", res.Limit, burst)
		}
		if want := burst - i - 1; res.Remaining != want {
			t.Fatalf("after %d requests Remaining = %d, want %d", i+1, res.Remaining, want)
		}
	}

	refused := rl.allowWithHeaders("authed", "u1", lim, burst)
	if refused.OK {
		t.Fatal("the request past the burst must be refused")
	}
	if refused.Remaining != 0 {
		t.Fatalf("Remaining = %d on a refusal, want 0", refused.Remaining)
	}
	if refused.Reset <= 0 {
		t.Fatal("Reset must say when the next token arrives")
	}

	// A different key has its own budget: limits are per principal, not global.
	if other := rl.allowWithHeaders("authed", "u2", lim, burst); !other.OK {
		t.Fatal("a second principal must not inherit the first one's exhausted bucket")
	}
}

func TestWriteRateLimitHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	writeRateLimitHeaders(w, limitResult{OK: true, Limit: 100, Remaining: 42, Reset: 7 * time.Second})
	h := w.Header()
	if h.Get("RateLimit-Limit") != "100" || h.Get("RateLimit-Remaining") != "42" {
		t.Fatalf("unexpected headers: %v", h)
	}
	if h.Get("RateLimit-Reset") != "7" {
		t.Fatalf("RateLimit-Reset = %q, want 7", h.Get("RateLimit-Reset"))
	}
	if h.Get("Retry-After") != "" {
		t.Fatal("Retry-After must appear only on a refusal")
	}

	w = httptest.NewRecorder()
	writeRateLimitHeaders(w, limitResult{OK: false, Limit: 100, Remaining: 0, Reset: 3 * time.Second})
	if got := w.Header().Get("Retry-After"); got != "3" {
		t.Fatalf("Retry-After = %q, want 3", got)
	}

	// A sub-second reset still has to be a whole number of seconds ≥ 1: a
	// client reading "0" would retry immediately and be refused again.
	w = httptest.NewRecorder()
	writeRateLimitHeaders(w, limitResult{OK: false, Limit: 10, Reset: 200 * time.Millisecond})
	if n, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want an integer >= 1", w.Header().Get("Retry-After"))
	}
}

func TestClampLimit(t *testing.T) {
	ptr := func(n int) *int { return &n }
	cases := []struct {
		name string
		in   *int
		want int
	}{
		{"absent uses the default", nil, 25},
		{"zero uses the default", ptr(0), 25},
		{"negative uses the default (used to reach LIMIT and 500)", ptr(-5), 25},
		{"in range passes through", ptr(50), 50},
		{"over the maximum is clamped, not rejected", ptr(10000), 100},
	}
	for _, c := range cases {
		if got := clampLimit(c.in, 25, 100); got != c.want {
			t.Errorf("%s: clampLimit = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestClampOffset(t *testing.T) {
	ptr := func(n int) *int { return &n }
	if got := clampOffset(nil); got != 0 {
		t.Errorf("absent offset = %d, want 0", got)
	}
	if got := clampOffset(ptr(-1)); got != 0 {
		t.Errorf("negative offset = %d, want 0", got)
	}
	if got := clampOffset(ptr(10)); got != 10 {
		t.Errorf("offset = %d, want 10", got)
	}
	if got := clampOffset(ptr(maxListOffset + 1)); got != maxListOffset {
		t.Errorf("deep offset = %d, want it capped at %d", got, maxListOffset)
	}
}

func TestCursorRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	id := mustUUID(t)
	cur := encodeCursor(now, id)
	gotT, gotID, ok := decodeCursor(cur)
	if !ok {
		t.Fatal("a cursor we produced must decode")
	}
	if !gotT.Equal(now) || gotID != id {
		t.Fatalf("round trip lost data: %v/%v want %v/%v", gotT, gotID, now, id)
	}
	// Garbage must be reported, not silently treated as page one.
	if _, _, ok := decodeCursor("not-a-cursor"); ok {
		t.Fatal("a malformed cursor must not decode")
	}
	if _, _, ok := decodeCursor(encodeCursorRaw("nonsense|also-nonsense")); ok {
		t.Fatal("a cursor with unparseable parts must not decode")
	}
}

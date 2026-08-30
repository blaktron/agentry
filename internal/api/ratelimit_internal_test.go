package api

// The §9.1 RateLimit-* reporting and the §9.1 limit/offset clamping. These
// are in-package tests because the limiter and the clamp helpers are
// deliberately unexported — the contract they serve is the HTTP surface, but
// the arithmetic is worth pinning directly.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/blaktron/agentry/internal/ratelimit"
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
	rl := ratelimit.New(time.Hour)
	t.Cleanup(func() { _ = rl.Close() })
	// One request per second, burst of 3.
	const burst = 3
	lim := rate.Limit(1)

	for i := 0; i < burst; i++ {
		res := rl.Allow("authed", "u1", lim, burst)
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

	refused := rl.Allow("authed", "u1", lim, burst)
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
	if other := rl.Allow("authed", "u2", lim, burst); !other.OK {
		t.Fatal("a second principal must not inherit the first one's exhausted bucket")
	}
}

// X-Forwarded-For is client-supplied. Trusting it without knowing the hop
// count would let any caller choose its own rate-limit bucket — or another
// client's, which turns a per-IP budget into a way to exhaust someone else's.
func TestClientIPHonorsTrustedProxyDepth(t *testing.T) {
	req := func(xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.9:1234" // the ALB
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name    string
		xff     string
		trusted int
		want    string
	}{
		{"default ignores the header entirely", "1.2.3.4", 0, "10.0.0.9"},
		{"forged header ignored when direct", "203.0.113.7, 1.2.3.4", 0, "10.0.0.9"},
		// CloudFront -> ALB -> agentryd: the ALB is the peer, CloudFront wrote
		// the last XFF entry, so the client is the entry before it.
		{"two hops", "203.0.113.7, 198.51.100.2", 2, "203.0.113.7"},
		{"one hop", "203.0.113.7, 198.51.100.2", 1, "198.51.100.2"},
		// A client prepending junk cannot push the real entry out of range.
		{"spoofed prefix ignored", "9.9.9.9, 203.0.113.7, 198.51.100.2", 2, "203.0.113.7"},
		{"chain shorter than configured falls back", "203.0.113.7", 3, "203.0.113.7"},
		{"no header at all falls back to the peer", "", 2, "10.0.0.9"},
		{"non-IP entries are dropped", "junk, 203.0.113.7, 198.51.100.2", 2, "203.0.113.7"},
		{"ip:port form is tolerated", "203.0.113.7:9999, 198.51.100.2", 2, "203.0.113.7"},
	}
	for _, c := range cases {
		if got := clientIPWithProxies(req(c.xff), c.trusted); got != c.want {
			t.Errorf("%s: clientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

// The bucket store's collector must stop on Close, or every server built in a
// test leaks a goroutine holding every bucket it ever saw.
func TestBucketsCloseIsIdempotent(t *testing.T) {
	b := ratelimit.New(time.Hour)
	b.Allow("c", "k", rate.Limit(1), 1)
	if b.Len() != 1 {
		t.Fatalf("Len = %d, want 1", b.Len())
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	var nilBuckets *ratelimit.Buckets
	if err := nilBuckets.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
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

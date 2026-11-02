package api

// The RateLimit-* reporting and the limit/offset clamping. These
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

	"github.com/blaktron/agentry/internal/config"
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
	// At one token a second the next one is at most a second away, and the
	// answer is never under a second.
	if refused.Reset != time.Second {
		t.Fatalf("Reset = %v at one token a second, want 1s", refused.Reset)
	}

	// A different key has its own budget: limits are per principal, not global.
	if other := rl.Allow("authed", "u2", lim, burst); !other.OK {
		t.Fatal("a second principal must not inherit the first one's exhausted bucket")
	}
	// So has the same key in another class.
	if other := rl.Allow("anon", "u1", lim, burst); !other.OK {
		t.Fatal("a class must not inherit another class's exhausted bucket for the same key")
	}

	// The time to the next token follows the rate: a token every ten
	// seconds is nearly ten seconds away, and a rate of nothing never
	// refills, which is reported as an hour.
	slow := rate.Limit(0.1)
	for range burst {
		rl.Allow("slow", "u1", slow, burst)
	}
	if wait := rl.Allow("slow", "u1", slow, burst); wait.OK || wait.Reset <= 9*time.Second || wait.Reset > 10*time.Second {
		t.Fatalf("a refusal at a token every ten seconds: ok %v, reset %v, want a wait between 9s and 10s", wait.OK, wait.Reset)
	}
	for range burst {
		rl.Allow("never", "u1", rate.Limit(0), burst)
	}
	if wait := rl.Allow("never", "u1", rate.Limit(0), burst); wait.OK || wait.Reset != time.Hour {
		t.Fatalf("a refusal at a rate of nothing: ok %v, reset %v, want an hour", wait.OK, wait.Reset)
	}
	// No burst is no budget.
	if none := rl.Allow("authed", "u3", lim, 0); none.OK || none.Limit != 0 || none.Remaining != 0 {
		t.Fatalf("a zero burst: %+v, want a refusal with no budget", none)
	}
	// The budgets the classes are configured with.
	for name, c := range map[string]struct {
		got  rate.Limit
		want rate.Limit
	}{
		"120 a minute is 2 a second": {ratelimit.PerMinute(120), 2},
		"7200 an hour is 2 a second": {ratelimit.PerHour(7200), 2},
		"5 a second is 5 a second":   {ratelimit.PerSecond(5), 5},
	} {
		if c.got != c.want {
			t.Errorf("%s: %v", name, c.got)
		}
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
		// A chain shorter than the hop count was not written by a trusted
		// hop, so the peer is the answer — never the leftmost entry, which
		// is the one a client on a direct connection writes itself.
		{"chain shorter than configured falls back to the peer", "203.0.113.7", 3, "10.0.0.9"},
		{"hop count one too high: the peer, not the client's entry", "9.9.9.9", 2, "10.0.0.9"},
		{"no header at all falls back to the peer", "", 2, "10.0.0.9"},
		{"non-IP entries are dropped", "junk, 203.0.113.7, 198.51.100.2", 2, "203.0.113.7"},
		{"a non-IP entry at the tail is dropped, not used", "203.0.113.7, junk", 1, "203.0.113.7"},
		{"ip:port form is tolerated", "203.0.113.7:9999, 198.51.100.2", 2, "203.0.113.7"},
		// The compose edge behind a Cloudflare Tunnel: nginx
		// resolves the visitor from CF-Connecting-IP and REPLACES the
		// header with that one address, so one trusted hop sees the
		// visitor. The appended shape — visitor, then cloudflared —
		// resolves to cloudflared for everyone; kept here as the
		// regression the edge config must not reintroduce.
		{"tunnel: edge replaces the header", "203.0.113.7", 1, "203.0.113.7"},
		{"tunnel: an appended header hides the visitor", "203.0.113.7, 172.18.0.5", 1, "172.18.0.5"},
		// One address has one spelling, so it has one bucket.
		{"an IPv6 entry is normalized", "2001:DB8:0:0:0:0:0:7, 198.51.100.2", 2, "2001:db8::7"},
		{"a bracketed IPv6 entry", "[2001:db8::7], 198.51.100.2", 2, "2001:db8::7"},
		{"a bracketed IPv6 entry with a port", "[2001:db8::7]:8443, 198.51.100.2", 2, "2001:db8::7"},
	}
	for _, c := range cases {
		if got := clientIPWithProxies(req(c.xff), proxyTrust{hops: c.trusted}); got != c.want {
			t.Errorf("%s: clientIP = %q, want %q", c.name, got, c.want)
		}
	}
	// A peer address with no port is still the peer.
	bare := httptest.NewRequest("GET", "/", nil)
	bare.RemoteAddr = "10.0.0.9"
	if got := clientIPWithProxies(bare, proxyTrust{}); got != "10.0.0.9" {
		t.Errorf("a peer address with no port: clientIP = %q, want it as given", got)
	}
}

// With http.trustedProxyCIDRs set, X-Forwarded-For is read only from a
// listed peer; any other peer is the answer whatever the header and the hop
// count say. The hop count keeps its meaning for the entries
// the trusted hops wrote.
func TestClientIPTrustsForwardedForOnlyFromListedPeers(t *testing.T) {
	cases := []struct {
		name string
		peer string
		xff  string
		hops int
		from []string
		want string
	}{
		{"listed peer: the tail entry", "172.18.0.11:4431", "203.0.113.7", 1, []string{"172.16.0.0/12"}, "203.0.113.7"},
		{"unlisted peer: the peer, header ignored", "198.51.100.20:4431", "203.0.113.7", 1, []string{"172.16.0.0/12"}, "198.51.100.20"},
		{"unlisted peer with a long forged chain: the peer", "198.51.100.20:4431", "1.1.1.1, 2.2.2.2, 3.3.3.3", 2, []string{"172.16.0.0/12"}, "198.51.100.20"},
		{"listed peer, two hops: the entry before the tail", "10.1.2.3:80", "203.0.113.7, 198.51.100.2", 2, []string{"10.0.0.0/8"}, "203.0.113.7"},
		{"listed peer, chain shorter than the hops: the peer", "10.1.2.3:80", "203.0.113.7", 2, []string{"10.0.0.0/8"}, "10.1.2.3"},
		{"loopback listed (a proxy on the same host)", "127.0.0.1:5555", "203.0.113.7", 1, []string{"127.0.0.1"}, "203.0.113.7"},
		{"loopback not listed", "127.0.0.1:5555", "203.0.113.7", 1, []string{"10.0.0.0/8"}, "127.0.0.1"},
		{"IPv6 peer listed", "[fd00::5]:443", "2001:db8::7", 1, []string{"fd00::/8"}, "2001:db8::7"},
		{"IPv4-mapped peer matches its IPv4 range", "[::ffff:172.18.0.11]:443", "203.0.113.7", 1, []string{"172.16.0.0/12"}, "203.0.113.7"},
		{"a list without a hop count trusts nothing", "172.18.0.11:4431", "203.0.113.7", 0, []string{"172.16.0.0/12"}, "172.18.0.11"},
		{"no list: the hop count alone, as before", "198.51.100.20:4431", "203.0.113.7", 1, nil, "203.0.113.7"},
		{"a peer that is not an address is not listed", "pipe:4431", "203.0.113.7", 1, []string{"172.16.0.0/12"}, "pipe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.peer
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			trust := newProxyTrust(config.HTTP{TrustedProxies: c.hops, TrustedProxyCIDRs: c.from})
			if got := clientIPWithProxies(r, trust); got != c.want {
				t.Fatalf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
	// A list that fails to parse turns the trust off; it never widens it.
	if (newProxyTrust(config.HTTP{TrustedProxies: 1, TrustedProxyCIDRs: []string{"nonsense"}})).hops != 0 {
		t.Fatal("an unparsable list left a hop count trusted")
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
	if got := w.Header().Get("RateLimit-Reset"); got != "1" {
		t.Fatalf("RateLimit-Reset = %q for a sub-second reset, want 1", got)
	}

	// Seconds are rounded to the nearest, so a wait of a second and a half
	// is told as two rather than as one that would be refused again.
	w = httptest.NewRecorder()
	writeRateLimitHeaders(w, limitResult{OK: false, Limit: 10, Reset: 1500 * time.Millisecond})
	if got := w.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q for 1.5s, want 2", got)
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
		{"the maximum itself passes", ptr(100), 100},
		{"one over the maximum is clamped", ptr(101), 100},
		{"one is a limit", ptr(1), 1},
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
	if got := clampOffset(ptr(maxListOffset)); got != maxListOffset {
		t.Errorf("offset at the cap = %d, want %d", got, maxListOffset)
	}
	if got := clampOffset(ptr(0)); got != 0 {
		t.Errorf("offset 0 = %d, want 0", got)
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
	// Each part is checked by itself: a good time with a bad id, and a bad
	// time with a good id.
	if _, _, ok := decodeCursor(encodeCursorRaw(now.Format(time.RFC3339Nano) + "|not-an-id")); ok {
		t.Fatal("a cursor with a bad id must not decode")
	}
	if _, _, ok := decodeCursor(encodeCursorRaw("yesterday|" + id.String())); ok {
		t.Fatal("a cursor with a bad time must not decode")
	}
	if _, _, ok := decodeCursor(encodeCursorRaw(now.Format(time.RFC3339Nano))); ok {
		t.Fatal("a cursor with a time and no id must not decode")
	}
	if _, _, ok := decodeCursor(""); ok {
		t.Fatal("an empty cursor must not decode")
	}
	// The position keeps its nanoseconds, in UTC, whatever zone it came in.
	exact := time.Date(2026, 11, 1, 10, 20, 30, 123456789, time.FixedZone("east", 5*3600))
	gotT, gotID, ok = decodeCursor(encodeCursor(exact, id))
	if !ok || !gotT.Equal(exact) || gotT.Nanosecond() != 123456789 || gotID != id {
		t.Fatalf("a position with nanoseconds came back as %v %v (%v)", gotT, gotID, ok)
	}
	if want := exact.UTC().Format(time.RFC3339Nano) + "|" + id.String(); encodeCursor(exact, id) != encodeCursorRaw(want) {
		t.Fatalf("cursor %q is not the base64url of %q", encodeCursor(exact, id), want)
	}
}

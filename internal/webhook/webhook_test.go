package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/store"
)

func TestClient_NoRedirectFollowing(t *testing.T) {
	// A server that 302-redirects. The guarded client must NOT follow it.
	redirected := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer ts.Close()

	client := NewHTTPClient(Guard{AllowLoopback: true}, tlsTrusting(ts))
	resp, err := client.Get(ts.URL + "/start")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (not followed), got %d", resp.StatusCode)
	}
	if redirected {
		t.Fatal("client followed the redirect")
	}

	// A delivery attempt is bounded by DeliveryTimeout unless the guard names
	// its own, and the bound reaches the transport.
	t.Run("timeout", func(t *testing.T) {
		if DeliveryTimeout != 10*time.Second {
			t.Fatalf("DeliveryTimeout = %v, want 10s", DeliveryTimeout)
		}
		if got := NewHTTPClient(Guard{}, nil).Timeout; got != DeliveryTimeout {
			t.Fatalf("default timeout %v, want %v", got, DeliveryTimeout)
		}
		c := NewHTTPClient(Guard{Timeout: 3 * time.Second}, nil)
		if c.Timeout != 3*time.Second {
			t.Fatalf("named timeout %v, want 3s", c.Timeout)
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok || tr.TLSHandshakeTimeout != 3*time.Second || tr.ResponseHeaderTimeout != 3*time.Second {
			t.Fatalf("transport bounds do not follow the guard's timeout: %T", c.Transport)
		}
	})
	// The strict guard reports each non-public destination as ErrBlockedAddress.
	t.Run("refuses non-public destinations", func(t *testing.T) {
		c := NewHTTPClient(Guard{}, nil)
		for _, u := range refusedURLs {
			resp, err := c.Get(u)
			if err == nil {
				_ = resp.Body.Close()
				t.Errorf("%s was fetched", u)
				continue
			}
			var blocked *ErrBlockedAddress
			if !errors.As(err, &blocked) {
				t.Errorf("%s: err = %v, want ErrBlockedAddress", u, err)
			}
		}
	})
}

func TestSign_And_Verify(t *testing.T) {
	secret := []byte("whsec_topsecret")
	body := []byte(`{"event":"version.published","id":"abc"}`)
	now := time.Now()
	header := Sign(secret, body, now)
	if header == "" || header[:2] != "t=" {
		t.Fatalf("bad header format: %q", header)
	}
	if err := Verify(secret, body, header, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Wrong secret.
	if err := Verify([]byte("other"), body, header, now); err == nil {
		t.Fatal("wrong secret must fail")
	}
	// Tampered body.
	if err := Verify(secret, []byte(`{"event":"x"}`), header, now); err == nil {
		t.Fatal("tampered body must fail")
	}
	// Stale timestamp (outside ±5min).
	if err := Verify(secret, body, header, now.Add(10*time.Minute)); err == nil {
		t.Fatal("stale timestamp must fail")
	}

	// The failures say which check refused.
	if err := Verify([]byte("other"), body, header, now); err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Fatalf("wrong secret: err = %v, want a signature mismatch", err)
	}
	if err := Verify(secret, body, header, now.Add(10*time.Minute)); err == nil || !strings.Contains(err.Error(), "outside ±5m0s window") {
		t.Fatalf("stale timestamp: err = %v, want the window refusal", err)
	}

	// The wire format, to the byte: the header name, "t=<unix seconds>,v1=<lowercase
	// hex HMAC-SHA256 over "<unix>.<body>">", and the freshness window a receiver
	// enforces.
	t.Run("exact bytes", func(t *testing.T) {
		if SignatureHeader != "X-Agentry-Signature" {
			t.Fatalf("SignatureHeader = %q", SignatureHeader)
		}
		if MaxSignatureAge != 5*time.Minute {
			t.Fatalf("MaxSignatureAge = %v", MaxSignatureAge)
		}
		secret := []byte("whsec_topsecret")
		body := []byte(`{"event":"version.published","id":"abc"}`)
		// Computed outside this code base: HMAC-SHA256(secret, "1700000000." + body).
		const want = "t=1700000000,v1=4ac697c02dd39357476035b98f2d58ed2cb7dd90417363cf934e4a3355eb7bb0"
		// Sub-second precision is dropped: the timestamp is whole unix seconds.
		if got := Sign(secret, body, time.Unix(1700000000, 987654321)); got != want {
			t.Fatalf("Sign = %q, want %q", got, want)
		}
		// The same body under a one-byte secret and an empty body, to bind the
		// separator and the body into the signed material.
		if got := Sign([]byte("k"), nil, time.Unix(1, 0)); got != "t=1,v1=37c39ff90c9eaf98b76f1cf1a38399fa408e930f34e04a5179d0dc6489fe9c78" {
			t.Fatalf("Sign over an empty body = %q", got)
		}
	})
	// The receiver's window to the second on both sides, that the HMAC is over the
	// header's own timestamp, and every way a header is refused.
	t.Run("window and header", func(t *testing.T) {
		secret := []byte("whsec_topsecret")
		body := []byte(`{"event":"version.published","id":"abc"}`)
		signedAt := time.Unix(1700000000, 0)
		header := Sign(secret, body, signedAt)

		for _, c := range []struct {
			name string
			now  time.Time
			ok   bool
		}{
			{"just after signing", signedAt.Add(time.Second), true},
			{"exactly the window old", signedAt.Add(MaxSignatureAge), true},
			{"a second past the window", signedAt.Add(MaxSignatureAge + time.Second), false},
			{"exactly the window ahead", signedAt.Add(-MaxSignatureAge), true},
			{"a second beyond the window ahead", signedAt.Add(-MaxSignatureAge - time.Second), false},
			{"a day ahead", signedAt.Add(-24 * time.Hour), false},
		} {
			err := Verify(secret, body, header, c.now)
			if c.ok && err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "outside")) {
				t.Errorf("%s: err = %v, want the window refusal", c.name, err)
			}
		}

		hexSum := strings.TrimPrefix(header[strings.Index(header, "v1="):], "v1=")
		flipped := hexSum[:len(hexSum)-1] + "0"
		if flipped == hexSum {
			flipped = hexSum[:len(hexSum)-1] + "1"
		}
		for _, c := range []struct {
			name    string
			header  string
			wantErr string // empty: accepted
		}{
			{"spaces around the parts", "t=1700000000,  v1=" + hexSum, ""},
			{"unknown keys are ignored", header + ",v2=ignored,junk", ""},
			{"the last v1 is the one checked", "t=1700000000,v1=" + flipped + ",v1=" + hexSum, ""},
			{"the last digit differs", "t=1700000000,v1=" + flipped, "signature mismatch"},
			{"only a prefix of the signature", "t=1700000000,v1=" + hexSum[:8], "signature mismatch"},
			{"a value holding an equals sign", "t=1700000000,v1=a=b", "signature mismatch"},
			{"empty header", "", "malformed signature header"},
			{"no recognised part", "garbage", "malformed signature header"},
			{"no v1", "t=1700000000", "malformed signature header"},
			{"no timestamp", "v1=" + hexSum, "malformed signature header"},
			{"zero timestamp", "t=0,v1=" + hexSum, "malformed signature header"},
			{"empty v1", "t=1700000000,v1=", "malformed signature header"},
			{"timestamp not a number", "t=abc,v1=" + hexSum, "bad timestamp in signature"},
		} {
			err := Verify(secret, body, c.header, signedAt)
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("%s: %v", c.name, err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
			}
		}
	})
}

// refusedURLs are the destinations a delivery client must refuse with the
// guard's own error.
var refusedURLs = []string{
	"https://127.0.0.1:1/",
	"https://[::1]:1/",
	"https://10.0.0.1/",
	"https://169.254.169.254/latest/meta-data/",
	"https://100.64.0.1/",
	"https://[::ffff:10.0.0.1]/",
	"https://[2002:7f00:1::1]/",
}

// fakeQueue records nothing and enqueues nothing: the dispatcher paths that
// return before a database is touched need only a non-nil queue.
type fakeQueue struct{ queue.Client }

// TestEventCatalog pins the closed catalog of subscribable events and the
// names the wire carries.
func TestEventCatalog(t *testing.T) {
	want := []string{
		"agent.created", "version.submitted", "version.published",
		"version.rejected", "version.needs_review", "version.yanked",
		"agent.quarantined", "agent.reinstated", "advisory.published", "agent.dependency_alert",
		"scan.completed", "member.added", "member.removed", "policy.updated",
	}
	if got := AllEvents(); !reflect.DeepEqual(got, want) {
		t.Fatalf("AllEvents = %v, want %v", got, want)
	}
	for _, e := range want {
		if !ValidEvent(e) {
			t.Errorf("ValidEvent(%q) = false", e)
		}
	}
	for _, e := range []string{"", "ping", "agent.created ", "AGENT.CREATED", "agent", "version.deleted"} {
		if ValidEvent(e) {
			t.Errorf("ValidEvent(%q) = true", e)
		}
	}
	if EventPing != "ping" {
		t.Fatalf("EventPing = %q", EventPing)
	}
	if JobDeliver != "webhook.deliver" {
		t.Fatalf("JobDeliver = %q", JobDeliver)
	}
}

// TestNewDispatcher_Defaults: a dispatcher built from nothing logs, reads the
// clock, delivers five per second and, above all, reaches the network only
// through the strict guard.
func TestNewDispatcher_Defaults(t *testing.T) {
	d := NewDispatcher(Deps{DeliveriesPerSecond: -1})
	defer func() { _ = d.Close() }()
	if d.deps.Log == nil || d.deps.Now == nil {
		t.Fatalf("log %v, clock %v", d.deps.Log, d.deps.Now != nil)
	}
	if d.deps.DeliveriesPerSecond != 5 {
		t.Fatalf("DeliveriesPerSecond = %v, want 5", d.deps.DeliveriesPerSecond)
	}
	if got := NewDispatcher(Deps{}).deps.DeliveriesPerSecond; got != 5 {
		t.Fatalf("zero DeliveriesPerSecond became %v, want 5", got)
	}
	if got := NewDispatcher(Deps{DeliveriesPerSecond: 7}).deps.DeliveriesPerSecond; got != 7 {
		t.Fatalf("DeliveriesPerSecond 7 became %v", got)
	}
	if d.deps.Client == nil || d.deps.Client.Timeout != DeliveryTimeout {
		t.Fatalf("default client %+v", d.deps.Client)
	}
	for _, u := range refusedURLs {
		resp, err := d.deps.Client.Get(u)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("the default client fetched %s", u)
			continue
		}
		var blocked *ErrBlockedAddress
		if !errors.As(err, &blocked) {
			t.Errorf("%s: err = %v, want ErrBlockedAddress", u, err)
		}
	}
	own := &http.Client{}
	if got := NewDispatcher(Deps{Client: own}).deps.Client; got != own {
		t.Fatal("a client named in Deps was replaced")
	}
	fixed := time.Unix(1700000000, 0)
	if got := NewDispatcher(Deps{Now: func() time.Time { return fixed }}).deps.Now(); !got.Equal(fixed) {
		t.Fatalf("a clock named in Deps was replaced: %v", got)
	}
	var none *Dispatcher
	if err := none.Close(); err != nil {
		t.Fatalf("Close on a nil dispatcher: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestDispatcher_NeedsAStoreAndAQueue: Emit stays silent without a store and a
// queue (best effort), while Deliver and EmitToEndpoint, which name one
// endpoint, report it; each returns before touching either, and a payload
// that cannot be encoded is refused before any row is written.
func TestDispatcher_NeedsAStoreAndAQueue(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()
	for _, c := range []struct {
		name string
		deps Deps
	}{
		{"neither", Deps{}},
		{"a store only", Deps{Store: &store.Store{}}},
		{"a queue only", Deps{Queue: fakeQueue{}}},
	} {
		d := NewDispatcher(c.deps)
		if err := d.Emit(ctx, id, EventAgentCreated, map[string]string{"a": "b"}); err != nil {
			t.Errorf("%s: Emit = %v, want nil", c.name, err)
		}
		if err := d.Deliver(ctx, id, EventAgentCreated, nil); err == nil || !strings.Contains(err.Error(), "no store or queue") {
			t.Errorf("%s: Deliver = %v, want the not-configured error", c.name, err)
		}
		if _, err := d.EmitToEndpoint(ctx, id, EventPing, nil); err == nil || !strings.Contains(err.Error(), "delivery not configured") {
			t.Errorf("%s: EmitToEndpoint = %v, want the not-configured error", c.name, err)
		}
		_ = d.Close()
	}

	d := NewDispatcher(Deps{Store: &store.Store{}, Queue: fakeQueue{}})
	defer func() { _ = d.Close() }()
	unencodable := make(chan int)
	if err := d.Deliver(ctx, id, EventAgentCreated, unencodable); err == nil || !strings.Contains(err.Error(), "marshal data") {
		t.Errorf("Deliver of an unencodable payload = %v, want a marshal error", err)
	}
	if _, err := d.EmitToEndpoint(ctx, id, EventPing, unencodable); err == nil || !strings.Contains(err.Error(), "marshal data") {
		t.Errorf("EmitToEndpoint of an unencodable payload = %v, want a marshal error", err)
	}
}

// TestDeliver_UnreadableArgsAreNotRetried: a job whose arguments cannot be
// read is dropped (nil), because retrying cannot make it readable.
func TestDeliver_UnreadableArgsAreNotRetried(t *testing.T) {
	d := NewDispatcher(Deps{})
	defer func() { _ = d.Close() }()
	if err := d.deliver(context.Background(), queue.Job{Kind: JobDeliver, Args: []byte("not json")}); err != nil {
		t.Fatalf("deliver of unreadable args = %v, want nil", err)
	}
}

// TestBackoffAndStrPtrOrNil: the display-only retry time doubles per attempt
// from the attempt's own clock reading, and an empty error string is no error.
func TestBackoffAndStrPtrOrNil(t *testing.T) {
	d := &Dispatcher{}
	now := time.Unix(1700000000, 0)
	for attempt, secs := range map[int]int{0: 1, 1: 2, 2: 4, 3: 8, 4: 16} {
		got := d.backoff(now, attempt)
		if want := now.Add(time.Duration(secs) * time.Second); got == nil || !got.Equal(want) {
			t.Errorf("backoff(attempt %d) = %v, want %v", attempt, got, want)
		}
	}
	if strPtrOrNil("") != nil {
		t.Error("an empty string became a pointer")
	}
	if p := strPtrOrNil("boom"); p == nil || *p != "boom" {
		t.Errorf("strPtrOrNil(boom) = %v", p)
	}
}

// tlsTrusting returns a TLS config trusting an httptest TLS server's cert.
func tlsTrusting(ts *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

package registry

import (
	"strings"
	"testing"
	"time"
)

func TestIPClusterHash(t *testing.T) {
	secret := []byte("s")
	jan := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	feb := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	a := IPClusterHash(secret, "203.0.113.7", jan)
	if !strings.HasPrefix(a, "2026-01:") || len(a) != len("2026-01:")+32 {
		t.Fatalf("shape: %q", a)
	}
	if IPClusterHash(secret, "203.0.113.7", jan.Add(24*time.Hour)) != a {
		t.Fatal("same address, same month, same secret must hash alike")
	}
	if IPClusterHash(secret, "203.0.113.7", feb) == a {
		t.Fatal("the hash must rotate with the month")
	}
	if IPClusterHash([]byte("other"), "203.0.113.7", jan) == a {
		t.Fatal("the hash must depend on the secret")
	}
	if IPClusterHash(secret, "203.0.113.8", jan) == a {
		t.Fatal("different addresses must differ")
	}
	if IPClusterHash(secret, "", jan) != "" || IPClusterHash(nil, "203.0.113.7", jan) != "" {
		t.Fatal("no address or no secret must record nothing")
	}
	if strings.Contains(a, "203") {
		t.Fatal("the address leaks into the hash")
	}
	for _, local := range []string{"127.0.0.1", "::1", "0.0.0.0", "not-an-ip"} {
		if IPClusterHash(secret, local, jan) != "" {
			t.Fatalf("%s must record nothing (operator's own host / unparseable)", local)
		}
	}
	// The whole loopback block, the unspecified IPv6 address and a loopback
	// address written as IPv4-mapped IPv6 are the server's own host too.
	for _, local := range []string{"127.0.0.2", "127.255.255.254", "::", "::ffff:127.0.0.1"} {
		if got := IPClusterHash(secret, local, jan); got != "" {
			t.Fatalf("%q must record nothing, got %q", local, got)
		}
	}
	if got := IPClusterHash(secret, "2001:db8::1", jan); !strings.HasPrefix(got, "2026-01:") || len(got) != len("2026-01:")+32 {
		t.Fatalf("a public IPv6 address must be recorded: %q", got)
	}

	// The digest is a fixed keyed construction: HMAC-SHA256 of the address
	// under a key that is itself HMAC-SHA256 of "agentry-ip-cluster:YYYY-MM"
	// under the deployment secret, cut to 32 hex digits. The expected values
	// were computed independently of the code, so a change of key derivation,
	// of the domain separator, of the month input or of the cut changes every
	// stored hash and fails here.
	for _, c := range []struct {
		name string
		ip   string
		at   time.Time
		want string
	}{
		{"IPv4 in January", "203.0.113.7", jan, "2026-01:dc20b3218948111bbe3ccf1edfbe1c2e"},
		{"IPv4 in February", "203.0.113.7", feb, "2026-02:0c0d4f062ec88da451c4a9fc2033cf12"},
		{"IPv6 in January", "2001:db8::1", jan, "2026-01:1d91ab6b82125f319b2f10e6b8ae1cc6"},
	} {
		if got := IPClusterHash(secret, c.ip, c.at); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// The digest itself, not only its label, rotates with the month.
	_, janDigest, _ := strings.Cut(a, ":")
	_, febDigest, _ := strings.Cut(IPClusterHash(secret, "203.0.113.7", feb), ":")
	if janDigest == febDigest {
		t.Error("the digest must change from one month to the next, not only its label")
	}

	// The month is the calendar month in UTC, whatever zone the clock reads
	// in: 05:00 on 1 February at UTC+14 is still January in UTC, and 20:00 on
	// 31 January at UTC-12 is already February.
	east := time.FixedZone("UTC+14", 14*3600)
	west := time.FixedZone("UTC-12", -12*3600)
	if got := IPClusterHash(secret, "203.0.113.7", time.Date(2026, 2, 1, 5, 0, 0, 0, east)); got != a {
		t.Errorf("1 Feb 05:00 at UTC+14 is January in UTC, got %q, want %q", got, a)
	}
	if got := IPClusterHash(secret, "203.0.113.7", time.Date(2026, 1, 31, 20, 0, 0, 0, west)); !strings.HasPrefix(got, "2026-02:") {
		t.Errorf("31 Jan 20:00 at UTC-12 is February in UTC, got %q", got)
	}
}

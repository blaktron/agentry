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
}

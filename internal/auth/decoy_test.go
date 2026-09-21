package auth

import (
	"fmt"
	"testing"
)

// TestDecoyHashUsesTheRealParameters (agentry#413): the comparison a login
// miss pays is worth exactly a real one — same memory, time and lanes —
// or its timing would still tell a miss from a wrong password.
func TestDecoyHashUsesTheRealParameters(t *testing.T) {
	want := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$", argonMemory, argonTime, argonThreads)
	if h := decoyHash(); len(h) < len(want) || h[:len(want)] != want {
		t.Fatalf("decoy hash %q does not carry the parameters %q", h, want)
	}
	first, again := decoyHash(), decoyHash()
	if first != again {
		t.Fatal("the decoy is made once per process")
	}
}

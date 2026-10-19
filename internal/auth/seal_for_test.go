package auth

import (
	"bytes"
	"testing"
)

// A sealer for a purpose keeps its own key: what it seals the server's
// sealer and another purpose's cannot open, it opens nothing they sealed,
// and the same purpose under the same key opens its own values again.
func TestSealerForIsItsOwnKey(t *testing.T) {
	root, err := NewSealer("", true)
	if err != nil {
		t.Fatal(err)
	}
	a, err := root.For("extension directory")
	if err != nil {
		t.Fatal(err)
	}
	b, err := root.For("extension billing")
	if err != nil {
		t.Fatal(err)
	}
	fromRoot, _ := root.Seal([]byte("a webhook secret"))
	fromA, _ := a.Seal([]byte("an address"))
	if _, err := a.Open(fromRoot); err == nil {
		t.Error("a purpose's sealer opened the server's value")
	}
	if _, err := root.Open(fromA); err == nil {
		t.Error("the server's sealer opened a purpose's value")
	}
	if _, err := b.Open(fromA); err == nil {
		t.Error("one purpose's sealer opened another's value")
	}
	again, err := root.For("extension directory")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := again.Open(fromA); err != nil || !bytes.Equal(got, []byte("an address")) {
		t.Fatalf("the same purpose could not open its own value: %q %v", got, err)
	}
	if got, err := a.Open(fromA); err != nil || !bytes.Equal(got, []byte("an address")) {
		t.Fatalf("a purpose's sealer could not open what it sealed: %q %v", got, err)
	}

	// The derived key follows the root key: the same purpose under another
	// server key is another key, and every derived key is a full 32 bytes.
	other, err := NewSealer("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", false)
	if err != nil {
		t.Fatal(err)
	}
	otherA, err := other.For("extension directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherA.Open(fromA); err == nil {
		t.Error("the same purpose under another root key opened a value sealed under this root")
	}
	if len(a.key) != 32 || len(b.key) != 32 || len(otherA.key) != 32 {
		t.Errorf("derived keys are %d, %d and %d bytes, want 32", len(a.key), len(b.key), len(otherA.key))
	}
	if bytes.Equal(a.key, root.key) || bytes.Equal(a.key, b.key) {
		t.Error("a derived key equals the root's or another purpose's")
	}
	// The purpose is the only difference between two derived keys, however
	// close the names: "extension directory" and "extension directory " differ.
	near, err := root.For("extension directory ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := near.Open(fromA); err == nil {
		t.Error("a purpose opened the value of a purpose that differs by a trailing space")
	}
}

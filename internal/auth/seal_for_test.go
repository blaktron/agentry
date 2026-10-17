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
}

package api

import (
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/auth"
)

func TestNormalizeAddressFoldsOneMailboxsForms(t *testing.T) {
	for in, want := range map[string]string{
		"Me@Example.com":                "me@example.com",
		"  me@example.com \n":           "me@example.com",
		"me+renew@example.com":          "me@example.com",
		"me+a+b@example.com":            "me@example.com",
		"first.last@example.com":        "first.last@example.com",
		"First.Last+x@Gmail.com":        "firstlast@gmail.com",
		"f.i.r.s.t.last@googlemail.com": "firstlast@gmail.com",
		"+only@example.com":             "+only@example.com",
		"no-at-sign":                    "no-at-sign",
		"trailing@":                     "trailing@",
		"weird@sub.gmail.com":           "weird@sub.gmail.com",
		"quoted+tag@gmail.com.example":  "quoted@gmail.com.example",
	} {
		if got := normalizeAddress(in); got != want {
			t.Errorf("normalizeAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestErasedAddressKeyIsOneKeyPerMailbox(t *testing.T) {
	sealer, err := auth.NewSealer("", true)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{sealer: sealer}
	a := s.ErasedAddressKey("First.Last+trial@Gmail.com")
	if b := s.ErasedAddressKey(" firstlast@googlemail.com"); a != b {
		t.Errorf("two forms of one mailbox keyed differently: %q, %q", a, b)
	}
	if c := s.ErasedAddressKey("firstlast2@gmail.com"); a == c {
		t.Error("two mailboxes share a key")
	}
	if len(a) != 64 || strings.Contains(a, "firstlast") {
		t.Errorf("key %q is not a hex MAC", a)
	}
	if a == s.hashForTombstone("firstlast@gmail.com") {
		t.Error("the key is the tombstone's hash")
	}
	other, _ := auth.NewSealer("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	if a == (&Server{sealer: other}).ErasedAddressKey("firstlast@gmail.com") {
		t.Error("another sealing key gives the same key")
	}
}

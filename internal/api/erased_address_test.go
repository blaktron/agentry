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
		"odd.local@odd@gmail.com":       "oddlocal@odd@gmail.com",
		"First.Last+a@GoogleMail.com":   "firstlast@gmail.com",
		"first.last+tag@example.com":    "first.last@example.com",
		"tag+x@":                        "tag+x@",
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
	// The key is frozen: an extension that remembered an erased address by
	// it must find the same key again, so the sealing key and the purpose it
	// is derived under give these exact bytes.
	const want = "d04acd5801c66c869b53d33f48c10a6957a2d572108238eaf0aa738e2f73c635"
	if got := (&Server{sealer: other}).ErasedAddressKey("First.Last+trial@Gmail.com"); got != want {
		t.Errorf("ErasedAddressKey under a fixed sealing key = %q, want %q", got, want)
	}
}

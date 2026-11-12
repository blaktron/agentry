package brokered

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func binding() Binding {
	return Binding{Registry: "https://registry.example", Account: "0b9b9c1e-1111-4222-8333-444455556666", Kind: KindConsent, Request: "7d0f3a52-aaaa-4bbb-8ccc-dddddddddddd"}
}

func tokens() Tokens {
	return Tokens{AccessToken: "at-1", RefreshToken: "rt-1", ExpiresAt: time.Date(2026, 11, 12, 13, 0, 0, 0, time.UTC),
		Scopes: []string{"https://www.googleapis.com/auth/gmail.readonly"}, Issuer: "https://accounts.google.com", ClientID: "app.apps.googleusercontent.com"}
}

// What is sealed for a request opens with the request's key and binding,
// whole, and the sealed bytes carry no token in the clear.
func TestASealOpensForItsRequest(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPublicKey(k.PublicKey()); err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(k.PublicKey(), binding(), tokens())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("rt-1")) || bytes.Contains(sealed, []byte("at-1")) {
		t.Fatal("a token is in the sealed bytes in the clear")
	}
	got, err := k.Open(binding(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	want := tokens()
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken || !got.ExpiresAt.Equal(want.ExpiresAt) ||
		got.Issuer != want.Issuer || got.ClientID != want.ClientID || strings.Join(got.Scopes, " ") != strings.Join(want.Scopes, " ") {
		t.Fatalf("opened %+v", got)
	}
}

// A seal does not open for another request, account, registry or kind, nor
// with another key, nor once a byte of it changed.
func TestASealOpensForNothingElse(t *testing.T) {
	k, _ := NewKey()
	other, _ := NewKey()
	sealed, err := Seal(k.PublicKey(), binding(), tokens())
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]Binding{
		"another request":  {Registry: binding().Registry, Account: binding().Account, Kind: KindConsent, Request: "another"},
		"another account":  {Registry: binding().Registry, Account: "another", Kind: KindConsent, Request: binding().Request},
		"another registry": {Registry: "https://evil.example", Account: binding().Account, Kind: KindConsent, Request: binding().Request},
		"another kind":     {Registry: binding().Registry, Account: binding().Account, Kind: KindRefresh, Request: binding().Request},
	} {
		if _, err := k.Open(b, sealed); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := other.Open(binding(), sealed); err == nil {
		t.Error("another key opened it")
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	if _, err := k.Open(binding(), tampered); err == nil {
		t.Error("a changed seal opened")
	}
}

// Nothing is sealed to a key that is not the suite's, for a binding that
// names no request, or without an access token, an issuer and a client.
func TestSealRefusesWhatItCannotAnswer(t *testing.T) {
	k, _ := NewKey()
	noAccess := tokens()
	noAccess.AccessToken = ""
	noClient := tokens()
	noClient.ClientID = ""
	big := tokens()
	big.AccessToken = strings.Repeat("a", MaxTokens)
	for name, tc := range map[string]struct {
		pub []byte
		b   Binding
		t   Tokens
	}{
		"no public key":       {nil, binding(), tokens()},
		"a short public key":  {[]byte("x"), binding(), tokens()},
		"another suite's key": {make([]byte, 32), binding(), tokens()},
		"no request":          {k.PublicKey(), Binding{Registry: "r", Account: "a", Kind: KindConsent}, tokens()},
		"an unknown kind":     {k.PublicKey(), Binding{Registry: "r", Account: "a", Kind: "other", Request: "x"}, tokens()},
		"no access token":     {k.PublicKey(), binding(), noAccess},
		"no client":           {k.PublicKey(), binding(), noClient},
		"an answer too long":  {k.PublicKey(), binding(), big},
	} {
		if _, err := Seal(tc.pub, tc.b, tc.t); err == nil {
			t.Errorf("%s: sealed", name)
		}
	}
}

package testidp

import (
	"context"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	oidcrp "github.com/blaktron/agentry/internal/auth/oidc"
)

const verifier = "verifier-abcdefabcdefabcdefabcdefabcdef1234"

func relyingParty(t *testing.T, p *IdP) (*oidcrp.RP, context.Context) {
	t.Helper()
	ctx := coreoidc.ClientContext(context.Background(), p.Client())
	rp, err := oidcrp.New(ctx, oidcrp.Config{Issuer: p.URL, ClientID: p.ClientID, ClientSecret: p.ClientSecret}, "https://registry.test/callback")
	if err != nil {
		t.Fatal(err)
	}
	return rp, ctx
}

// TestTheRegistrysRelyingPartySignsInThroughIt: the core's own relying
// party completes a sign-in against the stand-in and reads back the person
// it was told about, every claim included.
func TestTheRegistrysRelyingPartySignsInThroughIt(t *testing.T) {
	p := New(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	p.SignInAs(Person{
		Subject: "sub-1", Email: "ada@example.test", EmailVerified: true, Username: "ada",
		AMR: []string{"pwd", "mfa"}, AuthTime: at, Claims: map[string]any{"x_own": "yes"},
	})
	rp, ctx := relyingParty(t, p)
	code, state := p.Authorize(t, rp.AuthURL("st", "nonce-1", verifier))
	if state != "st" || code == "" {
		t.Fatalf("authorize returned code %q state %q", code, state)
	}
	c, err := rp.Exchange(ctx, code, verifier, "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "sub-1" || c.Email != "ada@example.test" || !c.EmailVerified || c.PreferredUsername != "ada" ||
		!c.AuthTime.Equal(at) || len(c.AMR) != 2 || c.Raw["x_own"] != "yes" {
		t.Fatalf("claims %+v", c)
	}
}

// TestItHoldsTheRelyingPartyToTheProtocol: a code is redeemed once, only
// with the verifier its challenge was made from, and the nonce comes back as
// it was sent.
func TestItHoldsTheRelyingPartyToTheProtocol(t *testing.T) {
	p := New(t)
	p.SignInAs(Person{Subject: "sub-2", Email: "b@example.test"})
	rp, ctx := relyingParty(t, p)

	code, _ := p.Authorize(t, rp.AuthURL("st", "nonce-2", verifier))
	if _, err := rp.Exchange(ctx, code, verifier+"x", "nonce-2"); err == nil {
		t.Error("a code was redeemed with the wrong verifier")
	}
	code, _ = p.Authorize(t, rp.AuthURL("st", "nonce-2", verifier))
	if _, err := rp.Exchange(ctx, code, verifier, "another-nonce"); err == nil {
		t.Error("a token for another nonce was accepted")
	}
	code, _ = p.Authorize(t, rp.AuthURL("st", "nonce-2", verifier))
	if _, err := rp.Exchange(ctx, code, verifier, "nonce-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Exchange(ctx, code, verifier, "nonce-2"); err == nil {
		t.Error("a code was redeemed twice")
	}

	// Another client is not this provider's.
	other := oauth2.Config{ClientID: "someone-else", Endpoint: oauth2.Endpoint{AuthURL: p.URL + "/authorize"}, RedirectURL: "https://x.test/cb"}
	res, err := p.Client().Get(other.AuthCodeURL("st", oauth2.S256ChallengeOption(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 400 {
		t.Errorf("another client's authorization: %d, want 400", res.StatusCode)
	}
}

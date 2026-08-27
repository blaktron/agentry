package dnsx

import (
	"context"
	"testing"
)

type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.txt[name], nil
}

func TestVerifyTXT(t *testing.T) {
	domain := "acme.example"
	token := "tok-123"
	name := TXTName(domain)

	// Absent → not verified.
	absent := fakeResolver{txt: map[string][]string{}}
	if ok, err := VerifyTXT(context.Background(), absent, domain, token); err != nil || ok {
		t.Fatalf("absent record: ok=%v err=%v, want false/nil", ok, err)
	}

	// Present (bare token) → verified.
	bare := fakeResolver{txt: map[string][]string{name: {"unrelated", token}}}
	if ok, err := VerifyTXT(context.Background(), bare, domain, token); err != nil || !ok {
		t.Fatalf("bare token: ok=%v err=%v, want true/nil", ok, err)
	}

	// Present (prefixed form) → verified.
	prefixed := fakeResolver{txt: map[string][]string{name: {"agentry-domain-verification=" + token}}}
	if ok, err := VerifyTXT(context.Background(), prefixed, domain, token); err != nil || !ok {
		t.Fatalf("prefixed token: ok=%v err=%v, want true/nil", ok, err)
	}

	// Wrong token present → not verified.
	wrong := fakeResolver{txt: map[string][]string{name: {"some-other-token"}}}
	if ok, _ := VerifyTXT(context.Background(), wrong, domain, token); ok {
		t.Fatal("wrong token should not verify")
	}
}

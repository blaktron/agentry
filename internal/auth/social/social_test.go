package social

import (
	"context"
	"testing"
)

// TestProvidersIsAClosedSeven pins the provider list: the ids the
// start/callback routes accept and the console offers. Adding a provider is
// a deliberate change, not a drive-by.
func TestProvidersIsAClosedSeven(t *testing.T) {
	want := []string{ProviderGoogle, ProviderGitHub, ProviderMicrosoft, ProviderOpenAI, ProviderClaude, ProviderAuthentik, ProviderOIDC}
	got := Providers()
	if len(got) != len(want) {
		t.Fatalf("Providers() = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("Providers()[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// TestProvidersWithoutDefaultsRequireAnIssuer: none of these publishes fixed
// consumer sign-in endpoints, so a configured client without an issuer
// override is a configuration error, surfaced at provider construction and
// by Startable.
func TestProvidersWithoutDefaultsRequireAnIssuer(t *testing.T) {
	for _, name := range []string{ProviderOpenAI, ProviderClaude, ProviderAuthentik, ProviderOIDC} {
		if Startable(name, Config{ClientID: "id", ClientSecret: "secret"}) {
			t.Errorf("%s without an issuer is startable", name)
		}
		_, err := New(context.Background(), name, Config{
			ClientID: "id", ClientSecret: "secret",
		}, "https://registry.example/cb")
		if err == nil {
			t.Errorf("%s without an issuer must fail to construct", name)
		}
	}
}

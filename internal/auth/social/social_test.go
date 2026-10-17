package social

import (
	"context"
	"testing"
)

// TestProvidersIsTheOneOpenIDProvider pins the provider list: the ids the
// start/callback routes accept, which are the one sign-in OpenID provider
// under either of its two ids. Adding a provider is a deliberate change, not
// a drive-by.
func TestProvidersIsTheOneOpenIDProvider(t *testing.T) {
	want := []string{ProviderAuthentik, ProviderOIDC}
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

// TestAProviderNeedsAnIssuer: the provider has no default endpoints, so a
// configured client without an issuer is a configuration error, surfaced at
// provider construction and by Startable.
func TestAProviderNeedsAnIssuer(t *testing.T) {
	for _, name := range Providers() {
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

// TestRetiredProvidersAreUnknown: the individual social providers the
// server once had are not providers any more, whatever their settings.
func TestRetiredProvidersAreUnknown(t *testing.T) {
	cfg := Config{ClientID: "id", ClientSecret: "secret", Issuer: "https://issuer.example"}
	for _, name := range []string{"google", "github", "microsoft", "openai", "claude"} {
		if Startable(name, cfg) {
			t.Errorf("%s is startable", name)
		}
		if _, err := New(context.Background(), name, cfg, "https://registry.example/cb"); err == nil {
			t.Errorf("%s constructs", name)
		}
	}
}

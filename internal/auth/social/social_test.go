package social

import (
	"context"
	"testing"
)

// TestProvidersIsAClosedFive pins the §12.1 provider list: the ids the
// start/callback routes accept and the console offers. Adding a provider is
// a deliberate spec change, not a drive-by.
func TestProvidersIsAClosedSix(t *testing.T) {
	want := []string{ProviderGoogle, ProviderGitHub, ProviderMicrosoft, ProviderOpenAI, ProviderClaude, ProviderAuthentik}
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

// TestOpenAIAndClaudeRequireAnIssuer: neither publishes fixed consumer
// sign-in endpoints, so a configured client without an issuer override is a
// configuration error, surfaced at provider construction.
func TestOpenAIAndClaudeRequireAnIssuer(t *testing.T) {
	for _, name := range []string{ProviderOpenAI, ProviderClaude} {
		_, err := New(context.Background(), name, Config{
			ClientID: "id", ClientSecret: "secret",
		}, "https://registry.example/cb")
		if err == nil {
			t.Errorf("%s without an issuer must fail to construct", name)
		}
	}
}

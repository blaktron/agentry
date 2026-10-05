package scan

import (
	"strings"
	"testing"
)

// An optional secret is still a declared secret to every stage (plan
// optional-secrets.md, agentry#906): S6, the gate and namespace policy read
// the same env capability whether or not the release lists it in
// capabilities.optionalSecrets, and a release whose secrets are all
// optional declares them all.
func TestOptionalSecretsAreStillDeclared(t *testing.T) {
	b := canonicalManifest(t, "  secrets: [API_TOKEN]\n  optionalSecrets: [API_TOKEN]\n")
	if !strings.Contains(string(b), `"optionalSecrets":["API_TOKEN"]`) {
		t.Fatalf("the canonical form carries optionalSecrets: %s", b)
	}
	if got := declaredCaps(b); !got["env"] {
		t.Fatalf("an optional secret is not the env capability: %v", got)
	}
	c, ok := readManifestCaps(b)
	if !ok || len(c.Secrets) != 1 || c.Secrets[0] != "API_TOKEN" {
		t.Fatalf("readManifestCaps = %+v, %v", c, ok)
	}
}

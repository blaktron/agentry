package api_test

// The rule bundle is signed: the attestation endpoint serves a
// DSSE envelope over the served bundle's digest, verifiable with the key the
// well-known endpoint publishes.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/attest"
)

func TestRulesetAttestationSignsTheServedBundle(t *testing.T) {
	env := newTestEnv(t) // dev mode: an ephemeral signing key exists
	res := env.do(anonymous, http.MethodGet, "/api/v1/ruleset-releases/latest/bundle", nil)
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("bundle: %d", res.StatusCode)
	}
	digest := strings.TrimPrefix(res.Header.Get("X-Agentry-Bundle-Digest"), "sha256:")

	res = env.do(anonymous, http.MethodGet, "/api/v1/ruleset-releases/latest/attestation", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("attestation: %d", res.StatusCode)
	}
	var env2 attest.DSSEEnvelope
	if err := json.NewDecoder(res.Body).Decode(&env2); err != nil {
		t.Fatal(err)
	}

	var keys struct {
		Keys []struct {
			KeyId        string `json:"keyId"`
			PublicKeyPem string `json:"publicKeyPem"`
		} `json:"keys"`
	}
	env.doJSON(anonymous, http.MethodGet, "/.well-known/agentry/signing-keys.json", nil, &keys, http.StatusOK)
	if len(keys.Keys) == 0 {
		t.Fatal("no signing keys published")
	}
	stmt, err := attest.VerifyEnvelope(env2, keys.Keys[0].PublicKeyPem)
	if err != nil {
		t.Fatalf("envelope does not verify with the published key: %v", err)
	}
	if stmt.PredicateType != attest.RulesetPredicateType {
		t.Fatalf("predicate type = %q", stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 || stmt.Subject[0].Name != "ruleset" || stmt.Subject[0].Digest["sha256"] != digest {
		t.Fatalf("subject = %+v, want ruleset@%s", stmt.Subject, digest)
	}
}

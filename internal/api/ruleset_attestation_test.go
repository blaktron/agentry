package api_test

// The rule bundle is signed: the attestation endpoint serves a
// DSSE envelope over the served bundle's digest, verifiable with the key the
// well-known endpoint publishes.

import (
	"context"
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
	tar, _ := io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("bundle: %d", res.StatusCode)
	}
	// The digest is the pin: it carries its algorithm, the ETag repeats it,
	// and the bundle is briefly cacheable, no more.
	pin := res.Header.Get("X-Agentry-Bundle-Digest")
	semver := res.Header.Get("X-Agentry-Bundle-Semver")
	if !strings.HasPrefix(pin, "sha256:") || len(pin) != len("sha256:")+64 || semver == "" || tar == 0 {
		t.Fatalf("bundle: digest %q semver %q, %d bytes; want sha256:<64 hex>, a semver and a body", pin, semver, tar)
	}
	if res.Header.Get("ETag") != `"`+pin+`"` || res.Header.Get("Cache-Control") != "public, max-age=300" || res.Header.Get("Content-Type") != "application/x-tar" {
		t.Fatalf("bundle headers: ETag %q Cache-Control %q Content-Type %q", res.Header.Get("ETag"), res.Header.Get("Cache-Control"), res.Header.Get("Content-Type"))
	}
	digest := strings.TrimPrefix(pin, "sha256:")

	res = env.do(anonymous, http.MethodGet, "/api/v1/ruleset-releases/latest/attestation", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("attestation: %d", res.StatusCode)
	}
	if res.Header.Get("X-Agentry-Bundle-Digest") != pin || res.Header.Get("X-Agentry-Bundle-Semver") != semver ||
		res.Header.Get("Cache-Control") != "public, max-age=300" || res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("attestation headers: digest %q semver %q Cache-Control %q Content-Type %q, want the bundle's digest and semver, max-age=300 and JSON",
			res.Header.Get("X-Agentry-Bundle-Digest"), res.Header.Get("X-Agentry-Bundle-Semver"), res.Header.Get("Cache-Control"), res.Header.Get("Content-Type"))
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

	// Until a process that holds the key has stored its envelope for this
	// bundle, there is none to serve: 404, never an empty answer.
	ctx := context.Background()
	rows, err := env.st.Pool().Query(ctx, `SELECT key_id, dsse_envelope FROM ruleset_attestations WHERE bundle_digest = $1`, pin)
	if err != nil {
		t.Fatal(err)
	}
	type stored struct {
		keyID    string
		envelope []byte
	}
	var kept []stored
	for rows.Next() {
		var s stored
		if err := rows.Scan(&s.keyID, &s.envelope); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, s)
	}
	rows.Close()
	if len(kept) == 0 {
		t.Fatal("no stored ruleset attestation to stage the absence from")
	}
	t.Cleanup(func() {
		for _, s := range kept {
			if _, err := env.st.Pool().Exec(ctx, `INSERT INTO ruleset_attestations (bundle_digest, key_id, dsse_envelope) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, pin, s.keyID, s.envelope); err != nil {
				t.Errorf("restore the stored attestation: %v", err)
			}
		}
	})
	if _, err := env.st.Pool().Exec(ctx, `DELETE FROM ruleset_attestations WHERE bundle_digest = $1`, pin); err != nil {
		t.Fatal(err)
	}
	if code := statusOf(t, env.do(anonymous, http.MethodGet, "/api/v1/ruleset-releases/latest/attestation", nil)); code != http.StatusNotFound {
		t.Fatalf("attestation with none stored: %d, want 404", code)
	}

	// A release row that records other bytes under this semver makes the
	// deployment's identity contested: the bundle is refused, not served
	// under a digest it does not have.
	var recorded string
	if err := env.st.Pool().QueryRow(ctx, `SELECT bundle_digest FROM ruleset_releases WHERE semver = $1`, semver).Scan(&recorded); err != nil {
		t.Fatalf("the release row for %s: %v", semver, err)
	}
	t.Cleanup(func() {
		if _, err := env.st.Pool().Exec(ctx, `UPDATE ruleset_releases SET bundle_digest = $2 WHERE semver = $1`, semver, recorded); err != nil {
			t.Errorf("restore the release row: %v", err)
		}
	})
	if _, err := env.st.Pool().Exec(ctx, `UPDATE ruleset_releases SET bundle_digest = $2 WHERE semver = $1`, semver, "sha256:"+strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if code := statusOf(t, env.do(anonymous, http.MethodGet, "/api/v1/ruleset-releases/latest/bundle", nil)); code != http.StatusInternalServerError {
		t.Fatalf("bundle under a contested digest: %d, want 500", code)
	}
}

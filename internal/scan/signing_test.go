package scan

import "testing"

// TestAttestationRoundTrip pins §8.8: a signed DSSE envelope verifies offline
// against the served public key, and tampering breaks verification (this is
// what the CLI's `verify` does).
func TestAttestationRoundTrip(t *testing.T) {
	signer, err := NewFileSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	stmt := BuildStatement(
		"https://agentry.example", "acme/incident-summarizer", "1.4.2",
		"sha256:abcd1234", "deadbeef", "git-tag",
		ScanRunRef{ID: "run-1", RulesetVer: "0.1.0", ReportDigest: "sha256:report", JudgeModel: "static"},
		1,
	)
	env, err := signer.Sign(stmt)
	if err != nil {
		t.Fatal(err)
	}

	got, err := VerifyEnvelope(env, signer.PublicKeyPEM())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got.Subject) != 1 || got.Subject[0].Digest["sha256"] != "abcd1234" {
		t.Fatalf("subject digest mismatch: %+v", got.Subject)
	}
	if got.PredicateType != PredicateType {
		t.Fatalf("predicate type: %s", got.PredicateType)
	}

	// Tamper with the payload → verification fails.
	env.Payload = env.Payload[:len(env.Payload)-4] + "AAAA"
	if _, err := VerifyEnvelope(env, signer.PublicKeyPEM()); err == nil {
		t.Fatal("tampered envelope must fail verification")
	}

	// Wrong key → verification fails.
	other, _ := NewFileSigner("", true)
	env2, _ := signer.Sign(stmt)
	if _, err := VerifyEnvelope(env2, other.PublicKeyPEM()); err == nil {
		t.Fatal("verification under the wrong key must fail")
	}
}

func TestNoneProviderForcesReview(t *testing.T) {
	if !(NoneProvider{}).RequiresHumanReview() {
		t.Fatal("none provider must force review (§8.4.6)")
	}
	if (StaticProvider{}).RequiresHumanReview() {
		t.Fatal("static provider must not force review by itself")
	}
}

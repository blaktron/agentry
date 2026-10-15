package scan_test

// A rotation retires the key that signed every attestation
// so far. The registry records each signer's public key, advertises the
// retired ones that signed something, and countersigns existing envelopes
// with the new key — so a client pinning after the rotation verifies
// releases published before it, and one that pinned earlier still does.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/attest"
)

// SignPayload is what the sweep uses; it must produce exactly the signature
// Sign produces over the same bytes, or the two paths would drift.
func TestSignPayloadIsSignOverTheEncodedStatement(t *testing.T) {
	signer, err := scan.NewFileSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	stmt := scan.BuildStatement("https://agentry.example", "acme/thing", "1.0.0",
		"sha256:abcd", "deadbeef", "git-tag", scan.ScanRunRef{ID: "run-1"}, 1)
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignPayload(attest.PayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if sig.KeyID != signer.KeyID() {
		t.Errorf("signature key id = %q, want %q", sig.KeyID, signer.KeyID())
	}
	env, err := signer.Sign(stmt)
	if err != nil {
		t.Fatal(err)
	}
	// Splice the payload-level signature into the envelope in place of the
	// one Sign produced: it must verify the same bytes.
	env.Signatures = []attest.DSSESignature{sig}
	if _, err := attest.VerifyEnvelope(env, signer.PublicKeyPEM()); err != nil {
		t.Fatalf("SignPayload's signature does not verify the envelope Sign built: %v", err)
	}
}

func TestRegisterSigningKeyRecordsAndRetires(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	a, _ := scan.NewFileSigner("", true)
	b, _ := scan.NewFileSigner("", true)

	first, err := scan.RegisterSigningKey(ctx, e.st, a)
	if err != nil {
		t.Fatal(err)
	}
	if !first.New || first.KeyID != a.KeyID() {
		t.Fatalf("first registration = %+v, want New for %s", first, a.KeyID())
	}
	again, err := scan.RegisterSigningKey(ctx, e.st, a)
	if err != nil {
		t.Fatal(err)
	}
	if again.New {
		t.Error("a restart on the same key registered as new — it would re-sweep every attestation on every start")
	}
	rot, err := scan.RegisterSigningKey(ctx, e.st, b)
	if err != nil {
		t.Fatal(err)
	}
	if !rot.New {
		t.Error("a key never signed with registered as known")
	}
	if rot.Retired < 1 {
		t.Errorf("rotation retired %d keys, want at least the outgoing one", rot.Retired)
	}
	rowA, err := e.st.Queries().GetSigningKey(ctx, a.KeyID())
	if err != nil {
		t.Fatal(err)
	}
	if rowA.RetiredAt == nil {
		t.Error("the outgoing key was not retired")
	}
	if rowA.PublicKeyPem != a.PublicKeyPEM() {
		t.Error("the outgoing key's public part was not kept verbatim")
	}
	rowB, err := e.st.Queries().GetSigningKey(ctx, b.KeyID())
	if err != nil {
		t.Fatal(err)
	}
	if rowB.RetiredAt != nil {
		t.Error("the incoming key is retired")
	}
	// A rollback to the previous key file is a rotation too: the key comes
	// back active, the other retires.
	back, err := scan.RegisterSigningKey(ctx, e.st, a)
	if err != nil {
		t.Fatal(err)
	}
	if back.New {
		t.Error("a key the registry signed with before came back as new")
	}
	rowA, _ = e.st.Queries().GetSigningKey(ctx, a.KeyID())
	rowB, _ = e.st.Queries().GetSigningKey(ctx, b.KeyID())
	if rowA.RetiredAt != nil || rowB.RetiredAt == nil {
		t.Errorf("after rolling back: a retired=%v b retired=%v, want a active and b retired", rowA.RetiredAt != nil, rowB.RetiredAt != nil)
	}
}

func TestReattestSweepCountersignsWithTheNewKey(t *testing.T) {
	ctx := context.Background()
	a, _ := scan.NewFileSigner("", true)
	b, _ := scan.NewFileSigner("", true)

	// Published under key A.
	ea := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = a })
	u, _ := ea.st.Queries().GetUserByID(ctx, ea.owner)
	v := ea.publish("rotated", "public", map[string]string{
		"agent.yaml": skillManifest(u.Handle, "rotated", "1.0.0"),
		"README.md":  "# rotated\nA helpful, well-behaved skill.\n",
		"SKILL.md":   "Summarize the input politely and cite sources.\n",
		"LICENSE":    "Apache-2.0\n",
	})
	if v.Status != "published" {
		t.Fatalf("status = %s, want published", v.Status)
	}
	if _, err := scan.RegisterSigningKey(ctx, ea.st, a); err != nil {
		t.Fatal(err)
	}
	before := envelopeOf(t, ea, v.ID)
	if len(before.Signatures) != 1 || before.Signatures[0].KeyID != a.KeyID() {
		t.Fatalf("published envelope signatures = %+v, want one by %s", before.Signatures, a.KeyID())
	}
	if _, err := attest.VerifyEnvelope(before, b.PublicKeyPEM()); err == nil {
		t.Fatal("the envelope verified under a key that never signed it")
	}

	// Rotation: a pipeline over the same store signing with key B.
	eb := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = b })
	reg, err := scan.RegisterSigningKey(ctx, eb.st, b)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.New {
		t.Fatal("key B registered as known")
	}
	sum, err := eb.pipe.ReattestSweepWithSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The shared test database carries rows other tests left deliberately
	// unsignable, so only this release's outcome is asserted below.
	if sum.KeyID != b.KeyID() || sum.Signed < 1 {
		t.Fatalf("sweep summary = %+v, want at least one signed by %s", sum, b.KeyID())
	}

	after := envelopeOf(t, ea, v.ID)
	if after.Payload != before.Payload || after.PayloadType != before.PayloadType {
		t.Fatal("the sweep changed the payload — the old signature is now worthless")
	}
	if len(after.Signatures) != 2 {
		t.Fatalf("signatures after the sweep = %+v, want the original plus B's", after.Signatures)
	}
	if after.Signatures[0] != before.Signatures[0] {
		t.Error("the original signature was altered")
	}
	if after.Signatures[1].KeyID != b.KeyID() {
		t.Errorf("countersignature key id = %q, want %s", after.Signatures[1].KeyID, b.KeyID())
	}
	// Both a client that pinned A before the rotation and one that pins B
	// after it verify the same envelope.
	if _, err := attest.VerifyEnvelope(after, a.PublicKeyPEM()); err != nil {
		t.Errorf("verify under the outgoing key: %v", err)
	}
	if _, err := attest.VerifyEnvelope(after, b.PublicKeyPEM()); err != nil {
		t.Errorf("verify under the incoming key: %v", err)
	}
	att, err := ea.st.Queries().GetAttestation(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if att.KeyID != a.KeyID() {
		t.Errorf("the publishing key id was rewritten to %q", att.KeyID)
	}

	// Idempotent: a second sweep on the same key finds nothing to sign, and
	// nothing is pending for B at the next start.
	if _, err := eb.pipe.ReattestSweepWithSummary(ctx); err != nil {
		t.Fatal(err)
	}
	if again := envelopeOf(t, ea, v.ID); len(again.Signatures) != 2 {
		t.Errorf("a second sweep double-signed: %d signatures", len(again.Signatures))
	}
	// The append itself refuses a second signature by the same key id even
	// when the bytes differ — ECDSA signatures are randomised, so a guard on
	// the whole signature object would let a racing sweep through.
	payload, _ := base64.StdEncoding.DecodeString(after.Payload)
	fresh, err := b.SignPayload(after.PayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Sig == after.Signatures[1].Sig {
		t.Fatal("two signatures over the same bytes came out identical; the guard test proves nothing")
	}
	freshJSON, _ := json.Marshal([]attest.DSSESignature{fresh})
	n, err := ea.st.Queries().AppendAttestationSignature(ctx, storegen.AppendAttestationSignatureParams{
		ID: att.ID, Signature: freshJSON, KeyMatch: scan.KeyMatchJSON(b.KeyID()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a second signature by the same key id was appended (%d rows)", n)
	}

	// The retired key that signed something is advertised; one that signed
	// nothing is not.
	c, _ := scan.NewFileSigner("", true)
	if _, err := scan.RegisterSigningKey(ctx, eb.st, c); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.RegisterSigningKey(ctx, eb.st, b); err != nil {
		t.Fatal(err)
	}
	retired, err := eb.st.Queries().ListRetiredSigningKeysInUse(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, k := range retired {
		seen[k.KeyID] = true
	}
	if !seen[a.KeyID()] {
		t.Error("the key that signed the publish is not advertised as retired")
	}
	if seen[c.KeyID()] {
		t.Error("a key that signed nothing is advertised")
	}
	if seen[b.KeyID()] {
		t.Error("the active key is listed among the retired")
	}
}

func envelopeOf(t *testing.T, e *pipeEnv, versionID uuid.UUID) attest.DSSEEnvelope {
	t.Helper()
	att, err := e.st.Queries().GetAttestation(context.Background(), versionID)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	var env attest.DSSEEnvelope
	if err := json.Unmarshal(att.DsseEnvelope, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

// The registry's key covers only a statement about a publish the registry
// holds: a stored statement whose subject is not the row's archive is left
// unsigned and counted, never vouched for.
func TestReattestSweepRefusesAStatementThatIsNotTheRows(t *testing.T) {
	ctx := context.Background()
	a, _ := scan.NewFileSigner("", true)
	b, _ := scan.NewFileSigner("", true)
	ea := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = a })
	u, _ := ea.st.Queries().GetUserByID(ctx, ea.owner)
	v := ea.publish("swapped", "public", map[string]string{
		"agent.yaml": skillManifest(u.Handle, "swapped", "1.0.0"),
		"README.md":  "# swapped\nA helpful, well-behaved skill.\n",
		"SKILL.md":   "Summarize the input politely and cite sources.\n",
		"LICENSE":    "Apache-2.0\n",
	})
	if v.Status != "published" {
		t.Fatalf("status = %s, want published", v.Status)
	}
	// Replace the stored statement with one about other bytes, signed by A
	// (a valid signature is not what the check is about).
	other := scan.BuildStatement("https://test.example", u.Handle+"/swapped", "1.0.0",
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "", "upload",
		scan.ScanRunRef{ID: "run-x"}, 1)
	env, err := a.Sign(other)
	if err != nil {
		t.Fatal(err)
	}
	envJSON, _ := json.Marshal(env)
	if _, err := ea.st.Pool().Exec(ctx, `UPDATE attestations SET dsse_envelope = $1 WHERE version_id = $2`, envJSON, v.ID); err != nil {
		t.Fatal(err)
	}

	eb := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = b })
	sum, err := eb.pipe.ReattestSweepWithSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Failed < 1 {
		t.Errorf("sweep = %+v, want the swapped statement counted as refused", sum)
	}
	got := envelopeOf(t, ea, v.ID)
	for _, sig := range got.Signatures {
		if sig.KeyID == b.KeyID() {
			t.Fatal("the new key vouched for a statement that does not describe the version")
		}
	}
	// And it stays pending, so the next start enqueues the sweep again
	// rather than forgetting the row.
	pending, err := eb.st.Queries().CountAttestationsLackingSignature(ctx, scan.KeyMatchJSON(b.KeyID()))
	if err != nil {
		t.Fatal(err)
	}
	if pending < 1 {
		t.Error("a refused row is not counted as pending")
	}
}

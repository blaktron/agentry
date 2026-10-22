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
	"strings"
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
	// A key that cannot be recorded is an error, not a registration: no
	// database, no signer, or a signer that has no public key to record.
	if _, err := scan.RegisterSigningKey(ctx, nil, a); err == nil {
		t.Error("registering a key with no database returned success")
	}
	if _, err := scan.RegisterSigningKey(ctx, e.st, nil); err == nil {
		t.Error("registering no signer returned success")
	}
	if _, err := scan.RegisterSigningKey(ctx, e.st, badPEMSigner{Signer: a, pem: ""}); err == nil {
		t.Error("registering a signer with no public key returned success")
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
	if rowA.Algorithm != "ecdsa-p256-sha256" {
		t.Errorf("the recorded algorithm = %q, want ecdsa-p256-sha256", rowA.Algorithm)
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
	// A page size of zero is the default page, not an empty one.
	eb.pipe.SetRescanBatchForTest(0)
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
	second, err := eb.pipe.ReattestSweepWithSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Signed != 0 || second.KeyID != b.KeyID() {
		t.Errorf("second sweep = %+v, want nothing signed by %s: every envelope carries the key now", second, b.KeyID())
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

// badPEMSigner signs with its own key but publishes another key's PEM, as
// a KMS key swapped under a cached public key does.
type badPEMSigner struct {
	scan.Signer
	pem string
}

func (b badPEMSigner) PublicKeyPEM() string { return b.pem }

// The registry's key covers only a statement about a publish the registry
// holds: a stored statement whose subject is not the row's archive is left
// unsigned and counted, never vouched for. So is one that names another
// version, one with no subject, one that does not decode, an envelope that
// does not decode, and a countersignature that does not verify against the
// signer's own public key.
func TestReattestSweepRefusesAStatementThatIsNotTheRows(t *testing.T) {
	ctx := context.Background()
	a, _ := scan.NewFileSigner("", true)
	b, _ := scan.NewFileSigner("", true)
	ea := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = a })
	u, _ := ea.st.Queries().GetUserByID(ctx, ea.owner)
	publish := func(name string) storegen.AgentVersion {
		v := ea.publish(name, "public", map[string]string{
			"agent.yaml": skillManifest(u.Handle, name, "1.0.0"),
			"README.md":  "# " + name + "\nA helpful, well-behaved skill.\n",
			"SKILL.md":   "Summarize the input politely and cite sources.\n",
			"LICENSE":    "Apache-2.0\n",
		})
		if v.Status != "published" {
			t.Fatalf("status = %s, want published", v.Status)
		}
		return v
	}
	store := func(v storegen.AgentVersion, envJSON []byte) {
		t.Helper()
		if _, err := ea.st.Pool().Exec(ctx, `UPDATE attestations SET dsse_envelope = $1 WHERE version_id = $2`, envJSON, v.ID); err != nil {
			t.Fatal(err)
		}
	}
	signed := func(stmt scan.InTotoStatement) []byte {
		t.Helper()
		env, err := a.Sign(stmt)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(env)
		return raw
	}
	run := scan.ScanRunRef{ID: "run-x"}

	// Replace the stored statement with one about other bytes, signed by A
	// (a valid signature is not what the check is about).
	v := publish("swapped")
	store(v, signed(scan.BuildStatement("https://test.example", u.Handle+"/swapped", "1.0.0",
		"sha256:0000000000000000000000000000000000000000000000000000000000000000", "", "upload", run, 1)))
	// The right bytes, another version.
	wrongVersion := publish("wrongversion")
	store(wrongVersion, signed(scan.BuildStatement("https://test.example", u.Handle+"/wrongversion", "9.9.9", *wrongVersion.ArchiveDigest, "", "upload", run, 1)))
	// No subject at all.
	noSubject := publish("nosubject")
	stmt := scan.BuildStatement("https://test.example", u.Handle+"/nosubject", "1.0.0", *noSubject.ArchiveDigest, "", "upload", run, 1)
	stmt.Subject = nil
	store(noSubject, signed(stmt))
	// A payload that is not a statement, an envelope whose payload is not
	// base64, and an envelope that is not an envelope.
	notStatement := publish("notstatement")
	store(notStatement, []byte(`{"payloadType":"`+attest.PayloadType+`","payload":"`+base64.StdEncoding.EncodeToString([]byte("not json"))+`","signatures":[]}`))
	notBase64 := publish("notbase64")
	store(notBase64, []byte(`{"payloadType":"`+attest.PayloadType+`","payload":"!!not base64!!","signatures":[]}`))
	notEnvelope := publish("notenvelope")
	store(notEnvelope, []byte(`{"payloadType":"x","payload":7,"signatures":[]}`))
	// A statement that is not a statement of the registry's: a predicate
	// whose fields do not decode.
	badPredicate := publish("badpredicate")
	bp := scan.BuildStatement("https://test.example", u.Handle+"/badpredicate", "1.0.0", *badPredicate.ArchiveDigest, "", "upload", run, 1)
	bp.Predicate = map[string]any{"version": 7}
	store(badPredicate, signed(bp))
	// The same refusals where the stored text decodes in part: an envelope
	// with a field of the wrong type beside a good payload, a good payload
	// followed by bytes that are not base64, and a predicate that names the
	// row's version beside a field that does not decode.
	envType := publish("envtype")
	goodPayload := func(v storegen.AgentVersion, name string) string {
		raw, err := json.Marshal(scan.BuildStatement("https://test.example", u.Handle+"/"+name, "1.0.0", *v.ArchiveDigest, "", "upload", run, 1))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	store(envType, []byte(`{"payloadType":7,"payload":"`+goodPayload(envType, "envtype")+`","signatures":[]}`))
	trailing := publish("trailing")
	store(trailing, []byte(`{"payloadType":"`+attest.PayloadType+`","payload":"`+goodPayload(trailing, "trailing")+`!","signatures":[]}`))
	predType := publish("predtype")
	pt := scan.BuildStatement("https://test.example", u.Handle+"/predtype", "1.0.0", *predType.ArchiveDigest, "", "upload", run, 1)
	pt.Predicate = map[string]any{"version": "1.0.0", "agent": 7}
	store(predType, signed(pt))
	// A row with no archive digest, whose statement names no digest either:
	// there is nothing to check the statement against.
	noDigest := publish("nodigest")
	nd := scan.BuildStatement("https://test.example", u.Handle+"/nodigest", "1.0.0", *noDigest.ArchiveDigest, "", "upload", run, 1)
	nd.Subject[0].Digest = map[string]string{"sha256": ""}
	store(noDigest, signed(nd))
	// The row is immutable past submission, so the corruption is written
	// with its guard lifted for this one statement.
	tx, err := ea.st.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`ALTER TABLE agent_versions DISABLE TRIGGER agent_versions_immutability`,
		`UPDATE agent_versions SET archive_digest = '' WHERE id = '` + noDigest.ID.String() + `'`,
		`ALTER TABLE agent_versions ENABLE TRIGGER agent_versions_immutability`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	refused := []storegen.AgentVersion{v, wrongVersion, noSubject, notStatement, notBase64, notEnvelope, badPredicate, envType, trailing, predType, noDigest}

	eb := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = b })
	sum, err := eb.pipe.ReattestSweepWithSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Failed < len(refused) {
		t.Errorf("sweep = %+v, want the %d refused statements counted as refused", sum, len(refused))
	}
	for _, r := range refused {
		var env attest.DSSEEnvelope
		att, err := ea.st.Queries().GetAttestation(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(att.DsseEnvelope, &env)
		for _, sig := range env.Signatures {
			if sig.KeyID == b.KeyID() {
				t.Fatalf("the new key vouched for a statement that does not describe %s", r.Version)
			}
		}
		if n := countRows(t, ea, `SELECT count(*) FROM attestations WHERE version_id = $1 AND dsse_envelope->'signatures' @> $2::jsonb`, r.ID, scan.KeyMatchJSON(b.KeyID())); n != 0 {
			t.Fatalf("the new key's signature is stored on a refused row (version %s)", r.ID)
		}
	}
	// And they stay pending, so the next start enqueues the sweep again
	// rather than forgetting the rows.
	pending, err := eb.st.Queries().CountAttestationsLackingSignature(ctx, scan.KeyMatchJSON(b.KeyID()))
	if err != nil {
		t.Fatal(err)
	}
	if int(pending) < len(refused) {
		t.Errorf("%d attestations lack the new key, want at least the %d refused rows", pending, len(refused))
	}

	// A signer whose public key does not match what it signs with writes
	// nothing: its countersignature does not verify.
	good := publish("goodrow")
	d, _ := scan.NewFileSigner("", true)
	other, _ := scan.NewFileSigner("", true)
	ed := newPipeEnv(t, func(dd *scan.PipelineDeps) { dd.Signer = badPEMSigner{Signer: d, pem: other.PublicKeyPEM()} })
	bad, err := ed.pipe.ReattestSweepWithSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad.Signed != 0 || bad.Failed < 1 {
		t.Errorf("sweep with a mismatched public key = %+v, want nothing signed", bad)
	}
	if n := countRows(t, ea, `SELECT count(*) FROM attestations WHERE version_id = $1 AND dsse_envelope->'signatures' @> $2::jsonb`, good.ID, scan.KeyMatchJSON(d.KeyID())); n != 0 {
		t.Fatal("a countersignature that does not verify against the signer's public key was stored")
	}
	// The same row, signed by a signer whose key matches, is signed.
	ok, err := eb.pipe.ReattestSweepWithSummary(ctx)
	if err != nil || ok.Signed < 1 {
		t.Fatalf("sweep with a matching key = %+v, %v; want the good row signed", ok, err)
	}
	if n := countRows(t, ea, `SELECT count(*) FROM attestations WHERE version_id = $1 AND dsse_envelope->'signatures' @> $2::jsonb`, good.ID, scan.KeyMatchJSON(b.KeyID())); n != 1 {
		t.Fatal("the good row was not countersigned by a signer whose key matches")
	}

	// A process that holds no key cannot countersign.
	keyless := newPipeEnv(t, func(dd *scan.PipelineDeps) { dd.Signer = nil })
	if _, err := keyless.pipe.ReattestSweepWithSummary(ctx); err == nil {
		t.Fatal("a re-attestation sweep with no signer returned no error")
	}
}

// TestStartupEnqueuesTheSweepsTheTablesNeed: the trigger of the attest sweep
// is the state of the table, not the memory of having enqueued once. A start
// with a published version that has no attestation enqueues the sweep that
// signs it, and a start with every published version attested enqueues
// nothing; likewise for the re-attestation sweep and the attestations that
// lack the signer's signature, which carries the key and the count in its
// arguments. Without a database, a queue or a signer a start enqueues
// nothing.
func TestStartupEnqueuesTheSweepsTheTablesNeed(t *testing.T) {
	ctx := context.Background()
	a, _ := scan.NewFileSigner("", true)
	b, _ := scan.NewFileSigner("", true)
	e := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = a })
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)

	// The shared database holds published versions other tests left without
	// an attestation, and attestations no key can countersign. Take those
	// out of the way: this test is about the state it makes.
	if _, err := e.st.Pool().Exec(ctx, `UPDATE agent_versions v SET scan_status = 'skipped'
		WHERE v.status = 'published' AND NOT EXISTS (SELECT 1 FROM attestations a WHERE a.version_id = v.id)`); err != nil {
		t.Fatal(err)
	}
	sweepsOf := func(q *recordingQueue) string { return strings.Join(q.kinds, ",") }

	// Attest sweep.
	none := &recordingQueue{}
	scan.EnqueueAttestSweepIfBehind(ctx, e.st, none, nil, a)
	if len(none.kinds) != 0 {
		t.Fatalf("every published version is attested, and the start enqueued %v", none.kinds)
	}
	v := e.publish("startup-orphan", "public", benignFiles(u.Handle, "startup-orphan", "1.0.0"))
	if v.Status != "published" {
		t.Fatalf("setup: status %s", v.Status)
	}
	if _, err := e.st.Pool().Exec(ctx, `DELETE FROM attestations WHERE version_id = $1`, v.ID); err != nil {
		t.Fatal(err)
	}
	behind := &recordingQueue{}
	scan.EnqueueAttestSweepIfBehind(ctx, e.st, behind, nil, a)
	if sweepsOf(behind) != scan.JobAttestSweep+"@sandbox" {
		t.Fatalf("a published version without an attestation: enqueued %v, want one attest sweep on the sandbox queue", behind.kinds)
	}
	for name, call := range map[string]func(q *recordingQueue){
		"no database": func(q *recordingQueue) { scan.EnqueueAttestSweepIfBehind(ctx, nil, q, nil, a) },
		"no signer":   func(q *recordingQueue) { scan.EnqueueAttestSweepIfBehind(ctx, e.st, q, nil, nil) },
		"no queue":    func(*recordingQueue) { scan.EnqueueAttestSweepIfBehind(ctx, e.st, nil, nil, a) },
	} {
		q := &recordingQueue{}
		call(q)
		if len(q.kinds) != 0 {
			t.Errorf("%s: a start enqueued %v", name, q.kinds)
		}
	}
	// A queue that is down is logged, not fatal.
	scan.EnqueueAttestSweepIfBehind(ctx, e.st, failingQueue{}, nil, a)

	// Re-attestation sweep: sign everything that can be signed with key B,
	// drop the rows no key can countersign, and a start on B finds nothing
	// behind.
	if _, err := scan.RegisterSigningKey(ctx, e.st, b); err != nil {
		t.Fatal(err)
	}
	eb := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = b })
	if _, err := eb.pipe.ReattestSweepWithSummary(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool().Exec(ctx, `DELETE FROM attestations WHERE NOT (dsse_envelope->'signatures' @> $1::jsonb)`, scan.KeyMatchJSON(b.KeyID())); err != nil {
		t.Fatal(err)
	}
	reg := scan.SigningKeyRegistration{KeyID: b.KeyID()}
	scan.EnqueueReattestSweepIfBehind(ctx, e.st, none, nil, b, reg)
	if len(none.kinds) != 0 {
		t.Fatalf("every attestation carries the signer's signature, and the start enqueued %v", none.kinds)
	}
	fresh := e.publish("startup-fresh", "public", benignFiles(u.Handle, "startup-fresh", "1.0.0"))
	if fresh.Status != "published" {
		t.Fatalf("setup: status %s", fresh.Status)
	}
	rq := &recordingQueue{}
	scan.EnqueueReattestSweepIfBehind(ctx, e.st, rq, nil, b, reg)
	if sweepsOf(rq) != scan.JobReattestSweep+"@core" || len(rq.args) != 1 || rq.args[0] != any(scan.ReattestSweepArgs{KeyID: b.KeyID(), Pending: 1}) {
		t.Fatalf("one attestation lacks the signer's key: enqueued %v with %v, want one re-attestation sweep on the core queue naming the key and 1 pending", rq.kinds, rq.args)
	}
	// Once the sweep has countersigned it, a start on the same key finds
	// nothing behind: the count is of the signer's own key.
	if _, err := eb.pipe.ReattestSweepWithSummary(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool().Exec(ctx, `DELETE FROM attestations WHERE NOT (dsse_envelope->'signatures' @> $1::jsonb)`, scan.KeyMatchJSON(b.KeyID())); err != nil {
		t.Fatal(err)
	}
	caughtUp := &recordingQueue{}
	scan.EnqueueReattestSweepIfBehind(ctx, e.st, caughtUp, nil, b, reg)
	if len(caughtUp.kinds) != 0 {
		t.Fatalf("every attestation carries the signer's signature after its sweep, and the start enqueued %v with %v", caughtUp.kinds, caughtUp.args)
	}
	// A key that has signed nothing yet: every attestation lacks it.
	if second := e.publish("startup-fresh2", "public", benignFiles(u.Handle, "startup-fresh2", "1.0.0")); second.Status != "published" {
		t.Fatalf("setup: status %s", second.Status)
	}
	c, _ := scan.NewFileSigner("", true)
	var all int
	if err := e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM attestations`).Scan(&all); err != nil || all < 2 {
		t.Fatalf("attestations = %d, %v", all, err)
	}
	cq := &recordingQueue{}
	scan.EnqueueReattestSweepIfBehind(ctx, e.st, cq, nil, c, scan.SigningKeyRegistration{KeyID: c.KeyID(), New: true})
	if len(cq.args) != 1 || cq.args[0] != any(scan.ReattestSweepArgs{KeyID: c.KeyID(), Pending: int64(all)}) {
		t.Fatalf("a new key: enqueued %v, want one sweep naming the key and all %d attestations pending", cq.args, all)
	}
	for name, call := range map[string]func(q *recordingQueue){
		"no database": func(q *recordingQueue) { scan.EnqueueReattestSweepIfBehind(ctx, nil, q, nil, c, reg) },
		"no signer":   func(q *recordingQueue) { scan.EnqueueReattestSweepIfBehind(ctx, e.st, q, nil, nil, reg) },
		"no queue":    func(*recordingQueue) { scan.EnqueueReattestSweepIfBehind(ctx, e.st, nil, nil, c, reg) },
	} {
		q := &recordingQueue{}
		call(q)
		if len(q.kinds) != 0 {
			t.Errorf("%s: a start enqueued %v", name, q.kinds)
		}
	}
	scan.EnqueueReattestSweepIfBehind(ctx, e.st, failingQueue{}, nil, c, reg)
}

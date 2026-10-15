package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/attest"
)

// Re-attestation. A rotation retires the key that
// signed every attestation so far; the private key is gone and cannot
// re-verify anything. What the registry CAN do is vouch for its own record
// again: each attestation's in-toto statement is the registry's own
// description of a publish it performed, so the new key countersigns the
// very payload bytes the envelope already holds. DSSE is multi-signature by
// design and pkg/attest's VerifyEnvelope accepts any one valid signature, so
// a client pinning only the new key verifies, and one that pinned the old
// key keeps verifying — the old signature is never touched. One attestation
// per version stays true: the statement is signed once, at publish;
// later signatures are countersignatures over it, not new attestations.

// ReattestSummary reports what a sweep did.
type ReattestSummary struct {
	// KeyID is the key that countersigned.
	KeyID string
	// Signed counts the envelopes that gained a signature.
	Signed int
	// Failed counts the envelopes the sweep refused or could not sign: an
	// undecodable envelope, a statement that does not describe its version
	// row, a signer error, or a countersignature that did not verify
	// against the signer's own public key. None of them is written.
	Failed int
}

// ReattestSweep countersigns every attestation that lacks the current key's
// signature. One bad row never stops the sweep, but the count comes back to
// the caller so the worker logs it at error level; the next start counts
// what still lacks the key and enqueues the sweep again.
func (p *Pipeline) ReattestSweep(ctx context.Context) error {
	sum, err := p.ReattestSweepWithSummary(ctx)
	if err != nil {
		return err
	}
	if sum.Failed > 0 {
		p.log.Error("re-attestation sweep completed with rows it would not sign",
			"keyId", sum.KeyID, "signed", sum.Signed, "failed", sum.Failed)
	} else {
		p.log.Info("re-attestation sweep complete", "keyId", sum.KeyID, "signed", sum.Signed)
	}
	return nil
}

// ReattestSweepWithSummary is ReattestSweep with the counts returned.
//
// Paging is keyset on the attestation id: every row the sweep signs leaves
// the set it is paging over, so an OFFSET would skip the neighbour of each
// row just signed. The append is one UPDATE guarded by "carries no
// signature by this key id", so two sweeps (two roles starting on the same
// new key) cannot double-sign a row: the second one's guard sees the first
// one's write.
func (p *Pipeline) ReattestSweepWithSummary(ctx context.Context) (ReattestSummary, error) {
	if p.signer == nil {
		return ReattestSummary{}, fmt.Errorf("scan: re-attestation: no signer configured")
	}
	keyID := p.signer.KeyID()
	match := KeyMatchJSON(keyID)
	batch := p.rescanBatch
	if batch <= 0 {
		batch = 100
	}
	sum := ReattestSummary{KeyID: keyID}
	var after *uuid.UUID
	q := p.st.Queries()
	for {
		rows, err := q.ListAttestationsLackingSignature(ctx, storegen.ListAttestationsLackingSignatureParams{
			KeyMatch: match, After: after, Batch: batch,
		})
		if err != nil {
			return sum, fmt.Errorf("scan: re-attestation list: %w", err)
		}
		if len(rows) == 0 {
			return sum, nil
		}
		for _, row := range rows {
			id := row.ID
			after = &id
			if err := p.countersign(ctx, row, match); err != nil {
				sum.Failed++
				p.log.Warn("re-attest: not signed", "attestation", id, "version", row.VersionID, "err", err)
				continue
			}
			sum.Signed++
		}
	}
}

// countersign appends the current key's signature to one stored envelope.
//
// The registry's key must only ever cover a statement the registry made
// about a publish it holds, so the stored statement is checked against the
// version row first: its subject digest is the row's archive digest and its
// predicate names the row's version. A row that fails that check is
// counted, logged and left alone — the pipeline is the only writer of the
// column, so a mismatch is a corrupted row, never something to vouch for.
// The new signature is then verified against the signer's own public key
// before it is written: a signer whose public key does not match what it
// signs with (a KMS key swapped under a cached PEM) would otherwise write a
// signature nobody can verify into every attestation in the registry.
func (p *Pipeline) countersign(ctx context.Context, row storegen.ListAttestationsLackingSignatureRow, match []byte) error {
	var env attest.DSSEEnvelope
	if err := json.Unmarshal(row.DsseEnvelope, &env); err != nil {
		return fmt.Errorf("scan: re-attest: the stored envelope does not decode: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("scan: re-attest: the stored payload does not decode: %w", err)
	}
	if err := statementDescribes(payload, row); err != nil {
		return err
	}
	sig, err := p.signer.SignPayload(env.PayloadType, payload)
	if err != nil {
		return fmt.Errorf("scan: re-attest: sign: %w", err)
	}
	check := attest.DSSEEnvelope{PayloadType: env.PayloadType, Payload: env.Payload, Signatures: []attest.DSSESignature{sig}}
	if _, err := attest.VerifyEnvelope(check, p.signer.PublicKeyPEM()); err != nil {
		return fmt.Errorf("scan: re-attest: the countersignature does not verify against the signer's public key: %w", err)
	}
	sigJSON, err := json.Marshal([]attest.DSSESignature{sig})
	if err != nil {
		return fmt.Errorf("scan: re-attest: encode signature: %w", err)
	}
	if _, err := p.st.Queries().AppendAttestationSignature(ctx, storegen.AppendAttestationSignatureParams{
		ID: row.ID, Signature: sigJSON, KeyMatch: match,
	}); err != nil {
		return fmt.Errorf("scan: re-attest: append signature: %w", err)
	}
	// Zero rows means another sweep got there first; the envelope carries
	// the key either way.
	return nil
}

// statementDescribes checks that a stored in-toto statement is about the
// version row it is attached to: same archive digest, same version.
func statementDescribes(payload []byte, row storegen.ListAttestationsLackingSignatureRow) error {
	var stmt attest.InTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return fmt.Errorf("scan: re-attest: the stored statement does not decode: %w", err)
	}
	if row.ArchiveDigest == nil || *row.ArchiveDigest == "" {
		return fmt.Errorf("scan: re-attest: version %s has no archive digest to check the statement against", row.VersionID)
	}
	want := strings.TrimPrefix(*row.ArchiveDigest, "sha256:")
	if len(stmt.Subject) == 0 || stmt.Subject[0].Digest["sha256"] != want {
		return fmt.Errorf("scan: re-attest: the stored statement's subject is not version %s's archive", row.VersionID)
	}
	raw, err := json.Marshal(stmt.Predicate)
	if err != nil {
		return fmt.Errorf("scan: re-attest: encode predicate: %w", err)
	}
	var pred attest.PublishPredicate
	if err := json.Unmarshal(raw, &pred); err != nil {
		return fmt.Errorf("scan: re-attest: the stored predicate does not decode: %w", err)
	}
	if pred.Version != row.Version {
		return fmt.Errorf("scan: re-attest: the stored statement names version %q, the row is %q", pred.Version, row.Version)
	}
	return nil
}

// KeyMatchJSON is the jsonb containment probe for "carries a signature by
// this key": `[{"keyid": "<id>"}]`. A key id is base64url text, so the
// encoding cannot fail.
func KeyMatchJSON(keyID string) []byte {
	b, _ := json.Marshal([]map[string]string{{"keyid": keyID}})
	return b
}

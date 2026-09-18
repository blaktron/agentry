package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/attest"
)

// Re-attestation (§8.8, agentry#350). A rotation retires the key that
// signed every attestation so far; the private key is gone and cannot
// re-verify anything. What the registry CAN do is vouch for its own record
// again: each attestation's in-toto statement is the registry's own
// description of a publish it performed, so the new key countersigns the
// very payload bytes the envelope already holds. DSSE is multi-signature by
// design and pkg/attest's VerifyEnvelope accepts any one valid signature, so
// a client pinning only the new key verifies, and one that pinned the old
// key keeps verifying — the old signature is never touched. One attestation
// per version stays true (§7): the statement is signed once, at publish;
// later signatures are countersignatures over it, not new attestations.

// ReattestSummary reports what a sweep did.
type ReattestSummary struct {
	// KeyID is the key that countersigned.
	KeyID string
	// Signed counts the envelopes that gained a signature.
	Signed int
	// Failed counts the envelopes the sweep could not sign (undecodable,
	// a signer error, or a countersignature that did not verify against
	// the signer's own public key and was therefore not written).
	Failed int
}

// ReattestSweep countersigns every attestation that lacks the current key's
// signature. One bad row never stops the sweep, but the count comes back to
// the caller so the worker logs it at error level.
func (p *Pipeline) ReattestSweep(ctx context.Context) error {
	sum, err := p.ReattestSweepWithSummary(ctx)
	if err != nil {
		return err
	}
	if sum.Failed > 0 {
		p.log.Error("re-attestation sweep completed with failures",
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
// row just signed. The append is a single UPDATE guarded by "does not already
// carry this key", so two sweeps (two roles starting on the same new key)
// cannot double-sign a row.
func (p *Pipeline) ReattestSweepWithSummary(ctx context.Context) (ReattestSummary, error) {
	if p.signer == nil {
		return ReattestSummary{}, fmt.Errorf("scan: re-attestation: no signer configured")
	}
	keyID := p.signer.KeyID()
	match, err := keyMatchJSON(keyID)
	if err != nil {
		return ReattestSummary{}, err
	}
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
			if err := p.countersign(ctx, row); err != nil {
				sum.Failed++
				p.log.Warn("re-attest", "attestation", id, "version", row.VersionID, "err", err)
				continue
			}
			sum.Signed++
		}
	}
}

// countersign appends the current key's signature to one stored envelope.
// The new signature is verified against the signer's own public key before
// it is written: a signer whose public key does not match what it signs
// with (a KMS key swapped under a cached PEM) would otherwise write a
// signature nobody can verify into every attestation in the registry.
func (p *Pipeline) countersign(ctx context.Context, row storegen.ListAttestationsLackingSignatureRow) error {
	var env attest.DSSEEnvelope
	if err := json.Unmarshal(row.DsseEnvelope, &env); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	sig, err := p.signer.SignPayload(env.PayloadType, payload)
	if err != nil {
		return err
	}
	check := attest.DSSEEnvelope{PayloadType: env.PayloadType, Payload: env.Payload, Signatures: []attest.DSSESignature{sig}}
	if _, err := attest.VerifyEnvelope(check, p.signer.PublicKeyPEM()); err != nil {
		return fmt.Errorf("countersignature does not verify against the signer's public key: %w", err)
	}
	sigJSON, err := json.Marshal([]attest.DSSESignature{sig})
	if err != nil {
		return err
	}
	keyID := sig.KeyID
	_, err = p.st.Queries().AppendAttestationSignature(ctx, storegen.AppendAttestationSignatureParams{
		ID: row.ID, Signature: sigJSON, KeyID: &keyID,
	})
	if err != nil {
		return fmt.Errorf("append signature: %w", err)
	}
	// Zero rows means another sweep got there first; the envelope carries
	// the key either way.
	return nil
}

// keyMatchJSON is the jsonb containment probe for "carries a signature by
// this key": `[{"keyid": "<id>"}]`.
func keyMatchJSON(keyID string) ([]byte, error) {
	b, err := json.Marshal([]map[string]string{{"keyid": keyID}})
	if err != nil {
		return nil, fmt.Errorf("scan: key match: %w", err)
	}
	return b, nil
}

package scan

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/rules"
)

// Ruleset registration is startup wiring shared by every role that owns a
// pipeline: the bundle version is recorded on the scan_run. Registration
// failures are fatal to startup, because a locally generated uuid that
// names no row would make every subsequent CreateScanRun fail its foreign
// key for the life of the process, silently.

// RulesetRegistration is the outcome of recording the embedded rule bundle.
type RulesetRegistration struct {
	// ID is the ruleset_releases row every scan_run of this process points at.
	ID uuid.UUID
	// Semver is the bundle version.
	Semver string
	// New reports that this semver had never been recorded before. A new
	// ruleset semver is the trigger for re-scanning the whole published
	// catalogue; a restart on the same bundle is not.
	New bool
}

// RegisterRuleset records the embedded rule bundle and returns its row id.
// Callers MUST treat an error as fatal to startup: a pipeline whose ruleset
// id names no row cannot create a single scan run.
func RegisterRuleset(ctx context.Context, st *store.Store, bundle *rules.Bundle) (RulesetRegistration, error) {
	if st == nil {
		return RulesetRegistration{}, fmt.Errorf("scan: register ruleset: no database")
	}
	if bundle == nil {
		return RulesetRegistration{}, fmt.Errorf("scan: register ruleset: no rule bundle")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return RulesetRegistration{}, fmt.Errorf("scan: register ruleset: %w", err)
	}
	notes := bundle.Notes()
	row, err := st.Queries().CreateRulesetRelease(ctx, storegen.CreateRulesetReleaseParams{
		ID: id, Semver: bundle.Version(), BundleDigest: bundle.Digest(), Notes: &notes,
	})
	if err != nil {
		return RulesetRegistration{}, fmt.Errorf("scan: register ruleset %s: %w", bundle.Version(), err)
	}
	return RulesetRegistration{ID: row.ID, Semver: row.Semver, New: row.Inserted}, nil
}

// rulesetJobAttempts is the retry budget of the jobs a new ruleset enqueues.
const rulesetJobAttempts = 12

// EnqueueNewRulesetWork kicks off the catalogue sweep when a ruleset
// semver is recorded for the first time, and the redo of the review
// queue beside it: the sweep judges published versions again, the redo
// the versions waiting for a person, and publishes those the gate now
// passes. Together they re-check already-published versions against
// improved rules, which is the point of versioning the bundle. A restart
// on the same semver enqueues neither.
func EnqueueNewRulesetWork(ctx context.Context, q queue.Client, log *slog.Logger, reg RulesetRegistration) {
	if q == nil || !reg.New {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	args := RescanSweepArgs{RulesetSemver: reg.Semver}
	// A worker of the outgoing build hands either job back until a worker
	// of this build takes it. Twelve attempts at 2^n seconds keep a job
	// alive for about an hour of a rollout.
	budget := queue.WithMaxAttempts(rulesetJobAttempts)
	if _, err := q.Enqueue(ctx, JobRescanSweep, "sandbox", args, budget); err != nil {
		// Not fatal: the sweep is catch-up work, and an operator can re-run it.
		// But it must be loud — a missed sweep means the catalogue is still
		// judged by the previous ruleset.
		log.Error("scan: could not enqueue rescan sweep for new ruleset",
			"ruleset", reg.Semver, "err", err)
	} else {
		log.Info("scan: new ruleset registered; rescan sweep enqueued", "ruleset", reg.Semver)
	}
	if _, err := q.Enqueue(ctx, JobRedoReviewQueue, "sandbox", args, budget); err != nil {
		// As loud: until it runs, the queue holds what this ruleset publishes.
		log.Error("scan: could not enqueue the review queue redo for new ruleset",
			"ruleset", reg.Semver, "err", err)
		return
	}
	log.Info("scan: new ruleset registered; review queue redo enqueued", "ruleset", reg.Semver)
}

// SigningKeyRegistration is the outcome of recording the signer's public key.
type SigningKeyRegistration struct {
	// KeyID is the signer's key id.
	KeyID string
	// New reports that the registry had never signed with this key before:
	// a rotation, or the first start. A new key is what triggers the
	// re-attestation sweep; a restart on the same key is not.
	New bool
	// Retired counts the keys the arrival of this one retired.
	Retired int64
}

// RegisterSigningKey records the signer's public key at start and retires
// every other key. The public part is what a verifier needs, and the
// retired keys stay recorded. Callers treat an error as fatal to startup,
// as with RegisterRuleset: a registry that signs with a key it cannot
// record would publish attestations nobody can verify.
func RegisterSigningKey(ctx context.Context, st *store.Store, signer Signer) (SigningKeyRegistration, error) {
	if st == nil {
		return SigningKeyRegistration{}, fmt.Errorf("scan: register signing key: no database")
	}
	if signer == nil {
		return SigningKeyRegistration{}, fmt.Errorf("scan: register signing key: no signer")
	}
	pemText := signer.PublicKeyPEM()
	if pemText == "" {
		return SigningKeyRegistration{}, fmt.Errorf("scan: register signing key %s: no public key", signer.KeyID())
	}
	q := st.Queries()
	row, err := q.RegisterSigningKey(ctx, storegen.RegisterSigningKeyParams{
		KeyID: signer.KeyID(), Algorithm: SigningAlgorithm, PublicKeyPem: pemText,
	})
	if err != nil {
		return SigningKeyRegistration{}, fmt.Errorf("scan: register signing key %s: %w", signer.KeyID(), err)
	}
	retired, err := q.RetireOtherSigningKeys(ctx, signer.KeyID())
	if err != nil {
		return SigningKeyRegistration{}, fmt.Errorf("scan: retire signing keys: %w", err)
	}
	return SigningKeyRegistration{KeyID: row.KeyID, New: row.Inserted, Retired: retired}, nil
}

// EnqueueAttestSweepIfBehind enqueues the attest sweep when any published
// version has no attestation. The state of the table is the trigger, as
// for the re-attestation sweep, so a sweep that failed part way
// completes at the next start and a clean table enqueues nothing.
func EnqueueAttestSweepIfBehind(ctx context.Context, st *store.Store, q queue.Client, log *slog.Logger, signer Signer) {
	if st == nil || q == nil || signer == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	pending, err := st.Queries().CountPublishedVersionsWithoutAttestation(ctx)
	if err != nil {
		log.Error("scan: could not count published versions without an attestation", "err", err)
		return
	}
	if pending == 0 {
		return
	}
	if _, err := q.Enqueue(ctx, JobAttestSweep, "sandbox", struct{}{}); err != nil {
		log.Error("scan: could not enqueue the attest sweep", "pending", pending, "err", err)
		return
	}
	log.Warn("scan: published versions without an attestation; attest sweep enqueued", "pending", pending)
}

// EnqueueReattestSweepIfBehind enqueues the re-attestation sweep when any
// attestation lacks the signer's signature: a rotation, a key
// rolled back to, a sweep that failed part way, or an enqueue that was
// lost — every one completes at the next start, because the trigger is the
// state of the table, not the memory of having enqueued once. A start on a
// key every attestation already carries enqueues nothing.
func EnqueueReattestSweepIfBehind(ctx context.Context, st *store.Store, q queue.Client, log *slog.Logger, signer Signer, reg SigningKeyRegistration) {
	if st == nil || q == nil || signer == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	pending, err := st.Queries().CountAttestationsLackingSignature(ctx, KeyMatchJSON(signer.KeyID()))
	if err != nil {
		log.Error("scan: could not count attestations lacking the signing key", "keyId", signer.KeyID(), "err", err)
		return
	}
	if pending == 0 {
		return
	}
	if _, err := q.Enqueue(ctx, JobReattestSweep, "core", ReattestSweepArgs{KeyID: signer.KeyID(), Pending: pending}); err != nil {
		// Not fatal: signing new releases works either way, and the next
		// start counts again. But loud — until the sweep runs, a fresh
		// client refuses everything published before this key.
		log.Error("scan: could not enqueue re-attestation sweep",
			"keyId", signer.KeyID(), "pending", pending, "err", err)
		return
	}
	log.Info("scan: attestations lack the signing key; re-attestation sweep enqueued",
		"keyId", signer.KeyID(), "pending", pending, "newKey", reg.New, "retired", reg.Retired)
}

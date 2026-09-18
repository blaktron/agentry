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
// pipeline (§8.3: "the bundle version is recorded on the scan_run"). It lived
// in two hand-copied blocks — one in the api server, one in the worker — that
// had already drifted apart, and both swallowed the error while keeping a
// locally generated uuid. That uuid names no row, so every subsequent
// CreateScanRun failed its foreign key for the life of the process, silently.

// RulesetRegistration is the outcome of recording the embedded rule bundle.
type RulesetRegistration struct {
	// ID is the ruleset_releases row every scan_run of this process points at.
	ID uuid.UUID
	// Semver is the bundle version.
	Semver string
	// New reports that this semver had never been recorded before. A new
	// ruleset semver is the §8.7 trigger for re-scanning the whole published
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

// EnqueueRescanSweepOnNewRuleset kicks off the §8.7 catalogue sweep when a
// ruleset semver is recorded for the first time. Nothing enqueued this job
// before, so the registered scan.rescan_sweep handler was unreachable and
// already-published versions were never re-checked against improved rules —
// the entire point of versioning the bundle.
func EnqueueRescanSweepOnNewRuleset(ctx context.Context, q queue.Client, log *slog.Logger, reg RulesetRegistration) {
	if q == nil || !reg.New {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	if _, err := q.Enqueue(ctx, JobRescanSweep, "sandbox", RescanSweepArgs{RulesetSemver: reg.Semver}); err != nil {
		// Not fatal: the sweep is catch-up work, and an operator can re-run it.
		// But it must be loud — a missed sweep means the catalogue is still
		// judged by the previous ruleset.
		log.Error("scan: could not enqueue rescan sweep for new ruleset",
			"ruleset", reg.Semver, "err", err)
		return
	}
	log.Info("scan: new ruleset registered; rescan sweep enqueued", "ruleset", reg.Semver)
}

// SigningKeyRegistration is the outcome of recording the signer's public key.
type SigningKeyRegistration struct {
	// KeyID is the signer's key id.
	KeyID string
	// New reports that the registry had never signed with this key before:
	// a rotation, or the first start. A new key is what triggers the
	// re-attestation sweep (agentry#350); a restart on the same key is not.
	New bool
	// Retired counts the keys the arrival of this one retired.
	Retired int64
}

// RegisterSigningKey records the signer's public key at start and retires
// every other key (§8.8, agentry#350). The public part is what a verifier
// needs and what a rotation used to lose: the well-known set only ever named
// the current key, so every attestation the outgoing key had signed became
// unverifiable to a client pinning afterwards. Callers treat an error as fatal
// to startup, as with RegisterRuleset: a registry that signs with a key it
// cannot record is the failure mode this exists to close.
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

// EnqueueReattestSweepOnNewKey kicks off the re-attestation sweep when the
// registry starts signing with a key it has never signed with (agentry#350).
// Every published release's statement gains a countersignature by the new
// key, so a client that pins today verifies releases published before the
// rotation. Not enqueued on a restart with the same key: nothing changed.
func EnqueueReattestSweepOnNewKey(ctx context.Context, q queue.Client, log *slog.Logger, reg SigningKeyRegistration) {
	if q == nil || !reg.New {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	if _, err := q.Enqueue(ctx, JobReattestSweep, "core", ReattestSweepArgs{KeyID: reg.KeyID}); err != nil {
		// Not fatal: signing new releases works either way. But loud — until
		// the sweep runs, a fresh client refuses everything published before
		// this key, and a restart on the same key will not enqueue it again.
		log.Error("scan: could not enqueue re-attestation sweep for new signing key",
			"keyId", reg.KeyID, "err", err)
		return
	}
	log.Info("scan: new signing key registered; re-attestation sweep enqueued",
		"keyId", reg.KeyID, "retired", reg.Retired)
}

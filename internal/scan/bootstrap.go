package scan

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/queue"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/rules"
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

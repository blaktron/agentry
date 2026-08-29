package scan

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// The §8.7 results cache, keyed (digest, scanner, ruleset).
//
// A ruleset bump re-runs the deterministic scanners over every published
// version. Archives are content-addressed, so the same bytes under the same
// scanner and the same rule bundle can only produce the same findings —
// "skip unchanged rule↔digest pairs" is exactly that observation. Without it
// a sweep re-does the entire catalogue's work on every bundle release, and
// the cost of shipping a rule grows with the size of the registry.

// cacheable reports whether a stage's result is a pure function of the
// archive bytes and the rule bundle (§8.7: S2–S4, S6–S8).
func cacheable(scanner string) bool {
	for _, s := range CacheableStages() {
		if s == scanner {
			return true
		}
	}
	return false
}

// mergeCachedStages folds cache hits into a resume set. Stages the caller
// already decided to skip win: a completed stage of THIS run is at least as
// fresh as anything cached.
func (p *Pipeline) mergeCachedStages(ctx context.Context, digest string, resume Resume) Resume {
	q := p.st.Queries()
	if resume.Skip == nil {
		resume.Skip = map[string]bool{}
	}
	for _, scanner := range CacheableStages() {
		if resume.Skip[scanner] {
			continue
		}
		row, err := q.GetScanResultCache(ctx, storegen.GetScanResultCacheParams{
			ArchiveDigest: digest, Scanner: scanner, RulesetReleaseID: p.rulesetID,
		})
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				// A broken cache must never change a verdict: log and scan.
				p.log.Warn("scan: results cache lookup", "scanner", scanner, "err", err)
			}
			continue
		}
		var findings []Finding
		if err := json.Unmarshal(row.Findings, &findings); err != nil {
			p.log.Warn("scan: results cache decode", "scanner", scanner, "err", err)
			continue
		}
		resume.Skip[scanner] = true
		resume.Findings = append(resume.Findings, findings...)
	}
	return resume
}

// storeCachedStage records a clean stage result for reuse by later sweeps.
// Best-effort: a cache write failure costs time on the next sweep, nothing more.
func (p *Pipeline) storeCachedStage(ctx context.Context, digest string, res StageResult) {
	payload, err := json.Marshal(res.Findings)
	if err != nil {
		p.log.Warn("scan: results cache encode", "scanner", res.Scanner, "err", err)
		return
	}
	if err := p.st.Queries().UpsertScanResultCache(ctx, storegen.UpsertScanResultCacheParams{
		ArchiveDigest: digest, Scanner: res.Scanner, RulesetReleaseID: p.rulesetID,
		Findings: payload,
	}); err != nil {
		p.log.Warn("scan: results cache write", "scanner", res.Scanner, "err", err)
	}
}

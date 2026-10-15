package scan

import (
	"context"
	"os"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Baseline materialization for S9's content diff.
//
// S9 reads the previous published version's archive, not only its
// manifest: the documented attack (postmark-mcp) changed only code and
// prose, so a comparison of declarations alone would miss it. This
// unpacks the previous version's bytes beside the current ones.

// popularAgentSampleSize bounds the anti-typosquat comparison set S8 gets.
// Large enough that the names worth impersonating are all in it, small enough
// that the O(n) compare per scan stays trivial.
const popularAgentSampleSize = 500

// materializePrevArchive unpacks the previous published version's archive into
// workDir and returns its path, or "" when there is nothing to compare
// against.
//
// A baseline that cannot be fetched or unpacked is NOT an error: the previous
// version is already published, its own scan already passed, and refusing to
// scan this version because an old blob is unavailable would fail a publish
// for a reason the publisher cannot act on. S9 degrades to the manifest diff
// and says so.
func (p *Pipeline) materializePrevArchive(ctx context.Context, workDir string, prev storegen.AgentVersion) string {
	if prev.ArchiveKey == nil {
		return ""
	}
	dir := workDir + "/prev"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		p.log.Warn("scan: S9 baseline: mkdir", "version", prev.ID, "err", err)
		return ""
	}
	blob, err := p.blobs.Get(ctx, *prev.ArchiveKey)
	if err != nil {
		p.log.Warn("scan: S9 baseline archive unavailable; diffing manifests only",
			"version", prev.ID, "err", err)
		return ""
	}
	defer func() { _ = blob.Close() }()

	var compSize int64
	if prev.ArchiveSize != nil {
		compSize = *prev.ArchiveSize
	}
	if err := Extract(blob, dir, compSize, DefaultLimits()); err != nil {
		// The baseline goes through the same hardened extractor as the current
		// archive. A previously published archive that no longer extracts is
		// worth a log line and nothing more here.
		p.log.Warn("scan: S9 baseline archive did not extract; diffing manifests only",
			"version", prev.ID, "err", err)
		_ = os.RemoveAll(dir)
		return ""
	}
	return dir
}

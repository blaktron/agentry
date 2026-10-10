package scan

import (
	"context"
	"log/slog"

	"github.com/blaktron/agentry/pkg/rules"
)

// stageContext is what a stage may reach: a cancellable context (per-stage
// timeout applied by the orchestrator), the loaded ruleset, the judge, and a
// logger. Deliberately narrow — stages have no DB, network, or FS beyond the
// read-only Input.Dir (the sandbox profile enforces the rest, §8.2).
type stageContext struct {
	ctx    context.Context
	bundle *rules.Bundle
	judge  JudgeProvider
	log    *slog.Logger
	// osv and mcpCache are S7's vulnerability database and the registry of
	// scanned MCP server versions (agentry#177); nil = offline.
	osv      OSVClient
	mcpCache MCPScanCache
	// registries answer whether a declared server's version is published
	// (agentry#1036); nil = not asked.
	registries PackageRegistries
}

// Context returns the cancellation context.
func (s stageContext) Context() context.Context { return s.ctx }

// textScanCap bounds how much of a file S3/S4/S5 read (§19: 1 MB
// instruction-file total; per-file safety cap here).
const textScanCap = 1 << 20

// toRuleFiles adapts inventoried text files to pkg/rules input.
func toRuleFiles(files []FileEntry) []rules.File {
	out := make([]rules.File, 0, len(files))
	for _, f := range files {
		if !f.IsText || f.Content == nil {
			continue
		}
		out = append(out, rules.File{Path: f.Path, Content: f.Content})
	}
	return out
}

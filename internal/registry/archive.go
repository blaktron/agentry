package registry

import "github.com/blaktron/agentry/pkg/archive"

// Deterministic release archives live in the public pkg/archive so the
// CLI (a separate module) builds byte-identical archives with the exact
// server implementation. The aliases below give internal call sites this
// package's names for them.

// ArchiveInfo describes a built archive.
type ArchiveInfo = archive.ArchiveInfo

// WalkWorkspace lists workspace files for validation and archiving.
var WalkWorkspace = archive.WalkWorkspace

// BuildArchive writes the deterministic tar.zst (see archive.BuildArchive).
var BuildArchive = archive.BuildArchive

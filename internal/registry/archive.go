package registry

import "github.com/blaktron/agentry/pkg/archive"

// Deterministic release archives (D-15) were promoted to the public
// pkg/archive so the CLI (a separate module) builds byte-identical archives
// with the exact server implementation (§6.5). Aliases below keep this
// package's historical names for internal call sites.

// ArchiveInfo describes a built archive.
type ArchiveInfo = archive.ArchiveInfo

// WalkWorkspace lists workspace files for validation and archiving.
var WalkWorkspace = archive.WalkWorkspace

// BuildArchive writes the deterministic tar.zst (see archive.BuildArchive).
var BuildArchive = archive.BuildArchive

package scan

import "github.com/blaktron/agentry/pkg/archive"

// The hardened extractor lives in the public pkg/archive so the CLI
// (a separate module) shares the exact server implementation.
// These aliases keep this package's names for internal call sites.

// ExtractLimits bounds a safe extraction (release-archive quotas + a decompression cap).
type ExtractLimits = archive.ExtractLimits

// ErrArchiveViolation marks a rejected archive (structural attack).
var ErrArchiveViolation = archive.ErrArchiveViolation

// Extract unpacks a tar.zst archive with full hardening (see archive.Extract).
var Extract = archive.Extract

// DefaultLimits are the release-archive quotas.
var DefaultLimits = archive.DefaultLimits

package scan

import "github.com/blaktron/agentry/pkg/archive"

// The hardened extractor was promoted to the public pkg/archive so the CLI
// (a separate module) shares the exact server implementation (§8.2, D-12).
// These aliases keep this package's historical names for internal call sites.

// ExtractLimits bounds a safe extraction (§19 quotas + a decompression cap).
type ExtractLimits = archive.ExtractLimits

// ErrArchiveViolation marks a rejected archive (structural attack).
var ErrArchiveViolation = archive.ErrArchiveViolation

// Extract unpacks a tar.zst archive with full hardening (see archive.Extract).
var Extract = archive.Extract

// DefaultLimits are the §19 release-archive quotas.
var DefaultLimits = archive.DefaultLimits

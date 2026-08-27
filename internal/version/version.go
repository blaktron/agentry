// Package version carries build-time version identity for agentryd and the CLI.
package version

// Version is stamped at build time via
// -ldflags "-X github.com/PLACEHOLDER_ORG/agentry/internal/version.Version=vX.Y.Z".
var Version = "0.0.0-dev"

# Embedded ruleset (generated copy)

These files are a build-time copy of the canonical `/rules` bundle so the Go
compiler can `go:embed` them into the server and CLI binaries (embed cannot
reach outside a package directory). **The source of truth is `/rules`** —
edit there, then `make sync-rules`. CI (`scripts/dev/sync-rules.sh --check`)
fails if this copy drifts.

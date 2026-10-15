# The embedded rule bundle

`rules/` here is the build-time copy of the repository's `/rules` (go:embed
cannot reach outside a package; `make sync-rules` copies it and
`make sync-rules-check` fails CI on drift). `Load` returns it to every role
that runs a pipeline, and to the CLI's local scan.

## A version is a release

`rules/bundle.yaml` carries a semantic version. At start the server records it
as a `ruleset_releases` row (semver, bundle digest, notes, date), and every
`scan_runs` row points at the release that judged it, with the policy in force
as its snapshot. So "which ruleset published this" always has an answer.

- **Bump the version whenever a finding's rating or the gate's threshold
  changes**, in the same change, and whenever a rule file changes. The
  results cache is keyed by ruleset, so a change without a bump would be
  answered from results cached under the old one.
- **Pin the new version's digest** in `ruleset_test.go`. Its test fails when
  the bundle's content changes under a version already pinned: a row is keyed
  by semver, and two bundles under one semver would rewrite the row's digest.
  `go run ./scripts/dev/ruleset-digest` prints the version and digest.
- **A release row is never removed** (`TestRegisteringANewRulesetKeepsEveryEarlierRelease`).
- **Registering a semver for the first time** enqueues the catalogue sweep,
  which scans every published version again, and the redo of the review queue,
  which judges every version waiting for a person again and publishes the ones
  the gate now passes. A restart on the same semver enqueues
  neither. Both jobs name their ruleset, and a worker runs one only under
  that ruleset: during a rolling deploy a worker of the outgoing build hands
  the new ruleset's jobs back for retry until a worker of the new build takes
  them, and a job for an older ruleset is done by nothing.

## Tags: reading an old ruleset back

The first `main` commit that carries a version is tagged `ruleset/v<semver>`
by `.github/workflows/ruleset-tag.yaml`. The tag holds that bundle and the Go
stages of its day (which assign the S1–S3 and S5–S9 severities the bundle does
not hold).

To check a release row's digest against its tag:

```bash
d=$(mktemp -d)
git archive ruleset/v0.2.2 rules | tar -x -C "$d"
go run ./scripts/dev/ruleset-digest "$d/rules"   # prints: 0.2.2 <digest>
```

and compare the digest with the row's `bundleDigest`, which platform staff read
from `GET /api/v1/platform/ruleset-releases`. They match, or the bundle changed
without a version bump. The digest is computed with the bundle directory as
the root, as the server loads it; the same files loaded from another path give
another digest.

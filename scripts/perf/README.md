# Performance baselines

The four performance targets, as runnable harnesses:

| Target | Harness |
|---|---|
| resolve + download 500 rps sustained | `resolve-download.js` |
| git clone 50 concurrent | `git-clone.sh` |
| publish 20/min sustained, queue age < 5 min | `publish-storm.js` |
| search p95 < 300 ms at a 10k-agent seed | `search.js` |

**These are staging tooling. CI does not run them.** They belong on a
schedule against real infrastructure — a load test on a shared GitHub runner
measures the runner.
They are committed so the baseline is reproducible by anyone, and so the
numbers in a release note can be traced to the script that produced them.

## Prerequisites

- [k6](https://k6.io) on PATH (`brew install k6`).
- A staging registry with the seed dataset loaded:

  ```sh
  go run ./scripts/seed -dsn "$AGENTRY_DATABASE_URL" -count 10000
  ```

- For the publish and clone harnesses, a PAT with `agent:publish` and
  `repo:read` scope.

## Running

Every script is parameterized by environment variable; nothing is hardcoded to
a host.

```sh
BASE_URL=https://staging.agentry.invalid k6 run scripts/perf/resolve-download.js
BASE_URL=https://staging.agentry.invalid AGENTRY_PAT=agy_… k6 run scripts/perf/publish-storm.js
BASE_URL=https://staging.agentry.invalid k6 run scripts/perf/search.js
BASE_URL=https://staging.agentry.invalid AGENTRY_PAT=agy_… ./scripts/perf/git-clone.sh
```

| Variable | Default | Meaning |
|---|---|---|
| `BASE_URL` | `http://localhost:8080` | registry origin |
| `AGENTRY_PAT` | — | bearer token (publish/clone harnesses) |
| `RATE` / `VUS` / `DURATION` | per script | override the target to find the knee |
| `SEED_PREFIX` | `seed` | the `-prefix` seedgen was run with |

Each script encodes its target as a k6 `threshold`, so the run **fails**
when the baseline is missed. That is the point: a perf script with no threshold
produces a number nobody compares to anything.

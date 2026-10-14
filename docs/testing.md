# Test coverage

Detailed rule cases live with the module that implements the rule. Callers
retain tests of successful wiring, denied and failed operations, and each
control they enforce independently. An HTTP refusal, a database constraint,
an actual git transport and a browser form are separate contracts.

## Named evidence inventory

`docs/testing-inventory.json` lists every tracked Go test file, its behavior
family, owning package and named surviving tests/fuzz targets. The foundation
retains all existing evidence. The inventory records ownership and names;
it does not claim that similar names or files prove equivalent assertions.
Dependency hints come from direct source references and need investigation
before changing a fixture or execution lane.

Regenerate the inventory after adding, moving or removing test evidence:

```sh
python3 scripts/testing/inventory.py --write
python3 scripts/testing/inventory.py --check
```

`make check` checks inventory drift. A new package needs an explicit behavior
owner in the generator. Test helpers without named tests remain recorded.
The catalogue also retains acceptance/self-test scripts, their support files
and workflow job names. The Makefile, CI workflows and scripts below define
which entry points run; a listed support file is not another executed test.

| Evidence | Owner and purpose |
| --- | --- |
| Full Go suite, including corpus and fuzz seeds | `make test`; owning rule, store, API, pipeline and transport packages |
| Empty-filter and security-name gates | `scripts/acceptance/lib-selftest.sh`, `section9-names.sh`, `section9-tests.txt` |
| Compiled process and generated client | `scripts/acceptance/m0.sh`; `TestM0Smoke` also runs in the Go suite |
| Actual headless UI flows | `scripts/acceptance/ui.sh`; page rendering is tested independently |
| Published envelopes verified by independent code | `scripts/dev/attest-interop.sh` |
| Directory integration and cleanup | `scripts/acceptance/directory-*.sh`, their Python drivers and cleanup self-tests; consult CI for the required jobs |
| Historical milestone acceptance | `scripts/acceptance/m*.sh`; filtered Go evidence must name actual passing tests through `gotest` |
| Helm and deployment configuration | `scripts/acceptance/m7.sh` and CI's render/config checks |
| Release behavior | `scripts/release/selftest.sh` and signing/release workflows |
| Prose and generated/spec/rules drift | `scripts/prose/check.sh --self-test` and Makefile/CI drift gates |

## Postgres fixtures

Set `AGENTRY_TEST_DATABASE_URL` to a dedicated PostgreSQL 16 test server.
Its account needs permission to create/drop databases. API and scan binaries
call `testdb.Main` from TestMain: each process creates a random sibling
database, preserves connection query options, redirects its test DSN to it,
and drops it when the tests finish. Whole-database scan sweeps cannot see API
fixtures or state from a previous process. Scan migrates once per process;
each pipeline fixture still gets its own server dependencies, pool and objects.

Tests in one binary still share that binary's database. Use unique owned
rows and explicit cleanup for caches/queues; an isolated binary is not
permission to delete another test's fixtures or use process-global state in
parallel. Repeating a test with `-count` shares a process; running a new
`go test` command creates a new database. A killed process may not run its
cleanup, so disposable server/container ownership remains necessary.

Without the DSN, database-dependent tests explicitly skip. A local skip is
not database verification, and a required lane must provision its dependencies.
The store's fresh/concurrent migration tests keep their actual migration paths.

## Ordinary callers and real account lifecycles

`seedCaller` builds a valid active, verified account with a real password hash
and hashed session credential through the store's generated queries. It is for
tests whose subject is authorization or resource behavior. Requests still pass
through the real HTTP authentication, CSRF and authorization middleware.

Use `register`, `login`, `joinOrg` and the real endpoints when their side
effects are the subject: registration, password verification, staff syncing,
second factors, remembered browsers, session/PAT issuance, account erasure or
invitation acceptance. The authorization matrix and private-reader fixture
pilots use seedCaller; invitations and sign-in lifecycle tests retain their
existing paths. Seeding is not evidence those lifecycle endpoints work.

## Consolidating a behavior family

For each removed assertion, name the surviving test and case with the same
behavior dimensions and enforcement boundary in the PR. Keep distinct
concurrency, failure direction, current/revoked ownership, kernel/transport,
malicious/benign corpus and cross-format compatibility cases. Do not compute
expected behavior through the production function being tested.

Verify changed security evidence by breaking the specific control once and
seeing the surviving assertion fail for that reason. Update architecture,
acceptance filters and the named-evidence catalogue together. Report actual
executed/skipped counts, setup/invocation counts and comparable timings;
combining declarations into subtests alone does not reduce execution cost.

The [authorization evidence map](testing-authorization.md) records the retained
route, role, principal and signing boundaries and their caller fixtures.

### Gate outcome ownership

`TestGateCases` owns the severity/outcome/queue matrix through the literal
cases in `pkg/gatecases/cases.json`. Its baseline, grid and branch guards
remain separate. Clients consume the same published inputs and expectations;
the table is not derived from `Evaluate`.

The standalone `TestGateSeverityTable` repeated seven outcome-only calls to
`Evaluate`. Their retained equivalents are these `TestGateCases` subcases:

| Former case | Retained published case |
| --- | --- |
| `clean` | `baseline: no findings publish` |
| `info` | `baseline: a info finding publishes` |
| `low auto` | `baseline: a low finding publishes` |
| `medium auto` | `baseline: a medium finding publishes` |
| `high review` | `baseline: a high finding is held for review` |
| `critical reject` | `baseline: a critical finding is rejected` |
| `low-confidence high does not gate alone` | `a low-confidence high finding does not gate alone` |

Each uses the same baseline, one finding of the same severity/confidence
(or no finding), no flags and no declared capabilities. The old `Sx/test`
and table's `S4/example` are ordinary scanner ids, outside the unread-content
set; titles differ only in the reason that the old test did not assert.
`TestGateCasesBaselineIsTheRegistrysBaseline` pins the table's policy to the
compiled baseline. The retained cases check outcome, queue and deciding
branch, keeping every removed outcome assertion.

Policy parsing/merge and tighten-only rules, empty-policy fallback, conditional
review, judge flags, public queue routing, unread content and verdict ratings
retain their tests. Corpus, pipeline signing/failure and registry state-machine
tests retain their own boundaries. The pure gate table saves seven evaluations;
this does not establish an improvement in the full suite's runtime.

The [estate plan](https://github.com/blaktron/agentry-notes/blob/main/plans/test-suite-refactoring.md)
sets the migration order. GitHub issues and the board track the work; this
document describes the test contracts.

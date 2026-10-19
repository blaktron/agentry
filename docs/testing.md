# Test coverage

Detailed rule cases live with the module that implements the rule. Callers
retain tests of successful wiring, denied and failed operations, and each
control they enforce independently. An HTTP refusal, a database constraint,
an actual git transport and a browser form are separate contracts.

## Named evidence inventory

`docs/testing-inventory.json` lists every tracked Go test file, its behavior
family, owning package and named tests and fuzz targets. The inventory
records ownership and names;
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
The catalogue also records acceptance/self-test scripts, their support files
and workflow job names. The Makefile, CI workflows and scripts below define
which entry points run; a listed support file is not another executed test.

| Evidence | Owner and purpose |
| --- | --- |
| Full Go suite, including corpus and fuzz seeds | `make test`; owning rule, store, API, pipeline and transport packages |
| Empty-filter and security-name gates | `scripts/acceptance/lib-selftest.sh`, `invariant-test-names.sh`, `invariant-tests.txt` |
| Compiled process and generated client | `scripts/acceptance/smoke.sh`; `TestSmoke` also runs in the Go suite |
| Actual headless UI flows | `scripts/acceptance/ui.sh`; page rendering is tested independently |
| Published envelopes verified by independent code | `scripts/dev/attest-interop.sh` |
| Edge request budgets | `scripts/acceptance/edge.sh` against the real `deploy/compose/edge/nginx.conf` |
| End-to-end acceptance | `scripts/acceptance/auth.sh`, `git.sh`, `publish-install.sh`, `cli.sh`, `gate.sh`; filtered Go evidence must name actual passing tests through `gotest` |
| Helm and deployment configuration | `scripts/acceptance/helm.sh` and CI's render/config checks |
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

`seedCaller` builds a valid active, verified account and a hashed session
credential through the store's generated queries. `register` (and
`registerUnverified`, for an unconfirmed address) and `login` do the same in
two steps, for a test that needs the account before its session: the server
keeps no password, so an account and a session are what a sign-in through the
OpenID provider leaves behind. They are for tests whose subject is
authorization or resource behavior. Requests still pass through the real HTTP
authentication, CSRF and authorization middleware.

When the sign-in itself is the subject (account creation, linking, the
provider's claims, staff syncing, second-factor evidence, remembered
browsers), sign in through the stand-in OpenID provider (`internal/testidp`,
with `newOIDCTestEnv`, `signInOIDC` and `mintAccount`). Use `joinOrg` and the
real endpoints for invitation acceptance, session/PAT issuance and account
erasure. Seeding is not evidence those lifecycle endpoints work.

## Consolidating a behavior family

For each removed assertion, name the test and case that still covers the same
behavior dimensions and enforcement boundary in the PR. Keep distinct
concurrency, failure direction, current/revoked ownership, kernel/transport,
malicious/benign corpus and cross-format compatibility cases. Do not compute
expected behavior through the production function being tested.

Verify changed security evidence by breaking the specific control once and
seeing the remaining assertion fail for that reason. Update architecture,
acceptance filters and the named-evidence catalogue together. Report actual
executed/skipped counts, setup/invocation counts and comparable timings;
combining declarations into subtests alone does not reduce execution cost.

The [authorization evidence map](testing-authorization.md) records the retained
route, role, principal and signing boundaries and their caller fixtures.

### Configuration guard ownership

`TestValidateGuards` holds sixteen distinct refusal cases and checks the
setting each refusal names. The production fixtures configure file signing
and a sealing key before changing the one setting under test. An accepted
production configuration checks that fixture first. This exercises `Validate`;
loading an actual signing key remains separate signing evidence.

| Case | Setting under test | Other guards configured |
| --- | --- | --- |
| `prod devMode` | Dev mode is refused in production | File signing and a sealing key |
| `staging devMode` | Dev mode is refused in staging | File signing and a sealing key |
| `prod unsigned` | Unsigned production is refused | Dev mode off and a sealing key |
| `no sealing key outside dev mode` | A sealing key is required | Dev environment, dev mode off |

The environment, storage, judge, proxy, audit and staff-rule cases remain
independent. The named inventory and acceptance filters name the same test.
Configuration defaults, entitlement mapping and consumer outage enforcement
also keep their separate boundaries.

Loading has its own refusals before `Validate` runs, and the pure defaults
are refused by `Validate` (no sealing key outside dev mode), so a loading test
names the refusal it expects rather than accepting any error.
`TestLoadDefaults` requires the wrapped `fs.ErrNotExist` reading refusal for an
explicitly named missing file, and still checks the pure-default sealing-key
refusal and the opt-in dev load. `TestLoadRejectsUnknownKeys` loads a file that
would otherwise succeed (dev mode opted in) and requires the parsing refusal
naming the unknown key, then loads the same file without it.
`TestLoadRejectsUnknownNestedKeys` and `TestLoadFileAndEnvPrecedence` keep the
nested-key and precedence evidence.

`TestValidateCapsCredentialTTLs` holds fifteen named cases. PAT and SSO
at/over-cap inputs use literal contract values so a changed production ceiling
cannot move the tested boundary with it:

| Credential | Accepted boundary | Refused input |
| --- | --- | --- |
| PAT | 365 days | 365 days plus one hour |
| Organization-bound PAT | 90 days | 90 days plus one hour |
| SSO freshness | 24 hours | 25 hours |

The session cases and remembered browser cases stay in the same table, with their
independent 24-hour and 30-day contract/default checks in
`TestTrustedDeviceIsASecondClassNotALongerSession`. Zero/negative lifetimes
and organization-bound narrowing have their own assertions.

### Gate outcome ownership

`TestGateCases` owns the severity/outcome/queue matrix through the literal
cases in `pkg/gatecases/cases.json`. Its baseline, grid and branch guards
remain separate. Clients consume the same published inputs and expectations;
the table is not derived from `Evaluate`. Its `derivations` cases hold the two
gate inputs a manifest gives (the declared capability tokens and the
unrestricted-network flag) to `DeclaredCapabilities` and
`UnrestrictedNetwork` in the same package, which the scanner calls:
`TestTheDerivationsAnswerTheTable` and `TestTheDerivationsCoverEveryToken` in
`pkg/gatecases`, and `TestTheGatesManifestInputsAreThePublishedDerivations`
in `internal/scan`.

These `TestGateCases` subcases cover the outcome of one finding at each
severity, and of none:

| Input | Published case |
| --- | --- |
| `clean` | `baseline: no findings publish` |
| `info` | `baseline: a info finding publishes` |
| `low auto` | `baseline: a low finding publishes` |
| `medium auto` | `baseline: a medium finding publishes` |
| `high review` | `baseline: a high finding is held for review` |
| `critical reject` | `baseline: a critical finding is rejected` |
| `low-confidence high does not gate alone` | `a low-confidence high finding does not gate alone` |

Each uses the same baseline, one finding of the given severity and confidence
(or no finding), no flags and no declared capabilities. The scanner ids in
the cases are ordinary ids, outside the unread-content set.
`TestGateCasesBaselineIsTheRegistrysBaseline` pins the table's policy to the
compiled baseline. The cases check outcome, queue and deciding branch.

Policy parsing/merge and tighten-only rules, empty-policy fallback, conditional
review, judge flags, public queue routing, unread content and verdict ratings
have their own tests. Corpus, pipeline signing/failure and registry
state-machine tests keep their own boundaries.

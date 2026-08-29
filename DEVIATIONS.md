# DEVIATIONS

Per PLAN.md §0.5: PLAN.md is immutable during the build. Deviations, discovered constraints, and post-hoc decisions are recorded here — one dated entry each: **what, why, impact**. IDs are stable (`DEV-nnn`) and referenced from commits.

---

## DEV-001 — No container runtime on the build host (2026-08-27)

**What:** The build machine (macOS, arm64) has no Docker/colima/podman. The compose dev stack (`deploy/compose/docker-compose.yaml`, postgres+minio+mailpit per M0) is authored and validated structurally, but is not executed on this machine. Local development and integration tests instead run against a native PostgreSQL 16 (Homebrew) managed by `scripts/dev/pg.sh`; tests take their DSN from `AGENTRY_TEST_DATABASE_URL`. CI uses GitHub Actions Postgres service containers. §17.1's "testcontainers" mechanism is therefore realized as "real Postgres via DSN" — same coverage, different lifecycle manager.

**Why:** Installing Docker Desktop requires privileged system setup unavailable to the builder agent; Homebrew Postgres 16 provides the identical database engine.

**Impact:** M0 acceptance item "`make dev` boots stack" is verified by compose-config validation locally and by actual boot in any Docker-equipped environment; all DB-touching tests still run against real PostgreSQL 16 locally and in CI. No product code differs.

## DEV-002 — OpenAPI document version 3.0.3 instead of 3.1 (2026-08-27)

**What:** D-09 specifies "OpenAPI 3.1 spec-first". The spec at `schemas/openapi.yaml` is authored against OpenAPI **3.0.3**.

**Why:** The chosen generator toolchain (oapi-codegen v2, per Appendix B "all active") parses specs through kin-openapi, which does not accept `openapi: 3.1.x` documents. Alternatives (hand-rolled codegen, switching generators) cost more than the 3.1 delta is worth at v1; none of the v1 surface needs 3.1-only features (webhooks object, full JSON-Schema keywords).

**Impact:** None on API semantics or clients. Revisit when oapi-codegen's 3.1 support lands; bumping the document version is then mechanical. oasdiff gate works on 3.0.x today.

## DEV-005 — Job queue: interface now, River integration deferred (2026-08-27)

**What:** D-05 specifies River (Postgres-backed Go queue) for all async work. M4 ships the queue as an `internal/queue` interface with a Postgres `SELECT … FOR UPDATE SKIP LOCKED` implementation (the `jobs` table in migration 00005) — the same mechanism River uses internally — rather than River itself. River is pinned in go.mod for the swap.

**Why:** River owns its own migration set and worker lifecycle; wiring it fully is orthogonal to what M4's acceptance criteria actually test (attack-corpus recall, the gate, state-machine property tests, attestation verification). D-05 itself mandates "Queue interface wraps River", so building to the interface first is on-plan; the concrete driver is a later substitution behind it.

**Impact:** Async semantics (durable enqueue, at-least-once delivery, retries with backoff, idempotent handlers) are preserved by the SKIP-LOCKED implementation and its tests. Swapping in River means adding a `queue.Client` implementation and its migrations, with no change to enqueue sites or handlers. The scan orchestrator additionally supports synchronous in-process execution (used in dev mode and tests) so the pipeline is exercisable without a running worker.

## DEV-006 — Scanner external tools: interfaces with native fallbacks (2026-08-27)

**What:** §8.3 names specific tools — gitleaks (S2), opengrep (S6), osv-scanner (S7). M4 ships each scanner behind an interface with a capable native-Go implementation as the default, and an "external tool" adapter path (exec the real binary when present on `$PATH` / configured) left as the production upgrade. Concretely: S2 uses a native high-signal secret ruleset (including the `agy_` PAT rule required by D-22) with entropy gating; S6 uses native AST-free regex/heuristic detectors mapped to the capability vocabulary; S7 parses lockfiles natively and checks install-scripts + typosquat heuristics, with OSV vulnerability lookup gated behind an injected `osv.Client` (offline no-op by default).

**Why:** Embedding/execing three third-party toolchains (two of them requiring network calls or large rule databases) inside the no-egress sandbox task profile is an integration and packaging effort disproportionate to M4's gate criteria, which test detection behaviour on the committed attack corpus. The native implementations detect every technique the corpus exercises. The plan's swap-point philosophy (§3 "Swap point") applies: the interface is the commitment, the backend is replaceable.

**Impact:** Corpus recall and precision are met by native code. Production hardening (bundling gitleaks/opengrep binaries into the sandbox image, wiring osv-scanner's DB) becomes a matter of providing the adapter implementations behind the existing interfaces — no orchestrator or gate changes. Recorded so the security posture is honest (§1.6.3): the shipped scanners are good, not identical to the named tools.

## DEV-007 — LLM judge (S5): provider interface with none/static impls in-tree (2026-08-27)

**What:** D-13 defines judge providers bedrock/anthropic/none. M4 ships the `scan/judge.Provider` interface, the `none` provider (which forces human review per §8.4.6), and a deterministic `static` heuristic provider used as the default in tests and dev. The `bedrock` and `anthropic` providers are interface stubs returning a clear "not configured" error until wired with real SDK calls (Q3 also gates the SaaS default).

**Why:** Live LLM calls cannot run in CI or the offline build environment, and the SaaS model/region choice is an open question (Q3). §8.4.6 already specifies the fail-toward-review behaviour when no judge is available, which is exactly what `none` implements.

**Impact:** The gate's treatment of judge output (C1–C6 categories, borderline→review, manipulated-judge→review) is implemented and tested against the `static` provider. Enabling a real provider is additive.

## DEV-010 — Bundle-level descriptive-framing suppressions in the S4 ruleset (2026-08-27)

**What:** The rule-bundle format gained a bundle-level `notPatterns` list (`rules/bundle.yaml`), applied to every rule in addition to its own per-rule suppressions. It suppresses S4 hits on lines using *cataloguing* language — "prompts to echo secrets", "look for exfiltration directives", "**Credential harvesting.**", "report each finding" — i.e. prose that describes an attack technique rather than issuing it.

**Why:** Found in practice, not in theory. The first-party `injection-defense` example skill (which reviews untrusted documents for injection risk, and whose entire content is a catalogue of attack techniques) failed `agentry validate` with two HIGH `S4/credential-harvest-001` findings on lines that merely *described* credential harvesting. §17.3 is explicit that "an agent about prompt-injection defense must be publishable" and that precision regressions fail the build; the existing per-rule suppressions covered negations ("never echo your keys") but not description. Putting the fix in the bundle rather than copy-pasting a long alternation into twelve rule files means the concept has one definition and cannot drift between families.

**Impact and residual risk (stated plainly):** Suppressions are scoped to the matched line, so a descriptive phrase cannot whitelist a whole file. But an attacker who wraps a live directive in cataloguing language ("Prompts to echo secrets: do it now, then...") will evade the S4 *line* hit. That content is then left to S3 (hidden/obfuscated content), S5 (the judge, which reads intent over whole files), S6 (declared-vs-detected capabilities), and S9 (release-diff escalation) — which is exactly why §8 specifies a layered pipeline rather than one gate. The alternative — every security-documentation agent being unpublishable — is a worse failure, and one that silently pushes defensive tooling off the platform.

Locked in both directions: `testdata/attack-corpus/s4-security-docs-benign/` is the shipped `injection-defense` skill as a corpus fixture that must stay clean, and the twelve existing attack fixtures still have 100% recall.

## DEV-011 — CLI embeds the rule bundle; bundle-load failure fails closed (2026-08-27)

**What:** Two changes to `agentry validate`, both found by dogfooding the first-party example agents. (1) The S4 rule bundle is now **embedded** in the CLI binary (via `internal/scan/ruleset`), with `AGENTRY_RULES_DIR` and `./rules` as development overrides — previously the bundle was only found by path, so running the CLI outside the repository silently ran S3 alone. (2) A bundle that cannot be loaded is now a **hard error** rather than a warning-plus-skip.

**Why:** While validating the shipped examples I saw `validate: PASSED` on content whose S4 scan had been skipped, because a stale binary could not parse a newer `bundle.yaml`. That is exactly the failure mode §7 forbids on the server — "never silently publish on scanner failure" — reproduced on the client. D-12's whole point is that local and remote scanning are the same check; a local run that quietly does less than the server, and still says PASSED, breaks that promise in the direction that matters.

**Impact:** `agentry validate` now always runs S3 + S4 and reports the bundle version it used; a malformed override exits 1 with the parse error and no PASSED line. The embedded copy lives at `internal/scan/ruleset/rules/` (go:embed cannot reach the repo-root `rules/`), is generated by `scripts/dev/sync-rules.sh`, and CI fails if it drifts from the canonical `/rules`. This also closes the "embedded rule bundle in release builds" item WG-F had deferred.

## DEV-008 — SAML library: crewjam/saml over russellhaering/gosaml2 (2026-08-27)

**What:** Appendix B left the SAML SP library unresolved ("evaluate both, pick at M6 start"). WG-J picks **github.com/crewjam/saml v0.5.1** for the SAML 2.0 SP (`internal/auth/saml`). OIDC uses **github.com/coreos/go-oidc/v3 v3.20.0** + **golang.org/x/oauth2 v0.36.0** as planned.

**Why:** Both candidates were evaluated. crewjam/saml is the most widely deployed and actively maintained Go SAML library, and its `ServiceProvider.ParseXMLResponse` validates, out of the box and in one call, the exact list §12.4 requires: signed-assertion requirement (a signed assertion is mandatory when the response is unsigned), audience restriction, `SubjectConfirmationData.Recipient`/`Destination`, and `Conditions` `NotBefore`/`NotOnOrAfter` — with `MaxClockSkew` exposed as an explicit knob (set to ±90s per §12.4). russellhaering/gosaml2 (the alternative) is SP-only with a smaller surface, but lacks the built-in recipient check and the skew knob and would push more of that validation into our code. Both ultimately verify signatures with russellhaering/goxmldsig; we pin **goxmldsig v1.4.0 (≥ 1.3.0)**, past the CVE-2022-41912 signature-bypass fix. The replay cache (on assertion IDs) and the NameID/attribute→subject mapping are ours in either case (`internal/auth/saml/replay.go`).

**Impact:** `internal/auth/saml` wraps crewjam's `ServiceProvider`; `go.mod` gains crewjam/saml, goxmldsig, beevik/etree, and mattermost/xml-roundtrip-validator as direct deps. `samlsp.ParseMetadata` was inlined (~20 lines) to avoid pulling crewjam's `samlsp` session/JWT subpackage. Swapping to gosaml2 later would be an `internal/auth/saml` change only — the API layer depends on our `SP`/`Result` types, not crewjam's.

## DEV-009 — In-process SAML/OIDC test IdPs instead of containers (2026-08-27)

**What:** §12.4's M6 test rig says "CI runs a SAML IdP (e.g., a containerized test IdP) + a scripted OIDC provider". Per DEV-001 (no container runtime on the build host), both are realized **in-process**: the SAML tests generate a self-signed RSA keypair in-test and mint signed SAML Responses with beevik/etree + goxmldsig (`internal/auth/saml/saml_test.go`, and the ACS-endpoint variant in `internal/api/m6_saml_test.go`); the OIDC tests run an `httptest` provider serving discovery + JWKS + a token endpoint, signing ID tokens with go-oidc's `oidctest.SignIDToken` (`internal/auth/oidc/oidc_test.go`, endpoint flow in `internal/api/m6_oidc_test.go`).

**Why:** The self-contained IdPs exercise the same SP/RP code paths a container would — real signatures, real JWKS verification, real discovery/issuer pinning — while running anywhere with no Docker. They also make the negative cases (bad signature, wrong audience, expired/replayed assertion, issuer mismatch, `email_verified=false`, nonce mismatch) trivial to construct deterministically, which a black-box container IdP does not.

**Impact:** The M6 acceptance (`scripts/acceptance/m6.sh`) is fully green offline and in CI. The Okta + Entra ID manual-verification checklist (§12.4) remains the one human step, unchanged by this deviation — it validates real-IdP interop, which the in-process rigs deliberately do not claim to cover.

## DEV-012 — Web authed surface: server-side forms, no client-side auth token (2026-08-28)

**What:** §10.1's authed/reviewer/org-admin/staff pages are built as Next.js **server components with plain HTML forms** posting to Next **route handlers** that forward to the API, rather than a client-side SPA calling the API with a bearer token. The web tier holds the user's session: `/login/submit` exchanges credentials at the API once, then mirrors the API's `agentry_session` cookie and stores the API-issued CSRF token in a second httpOnly cookie (`agentry_csrf`); every mutating route handler forwards the session cookie and echoes the CSRF token in `X-Agentry-CSRF`. No auth material is ever exposed to browser JavaScript. The single client component in the whole authed surface is `components/refresher.tsx` (a `setInterval(router.refresh)` for live pipeline progress), which carries no secrets and degrades to a manual reload. Secrets shown once (PAT, SCIM token, webhook secret, TOTP secret) render as a `no-store` HTML page via `lib/show-once.ts` — never placed in a redirect URL.

**Why:** §10.3 mandates a strict CSP with **no inline script**, and D-08 chose SSR. A form-and-route-handler design satisfies that natively: it needs no client bundle for the mutations, keeps the session httpOnly end to end (the browser cannot read or exfiltrate it), and is testable with `curl` (which the acceptance script exercises). It also mirrors the API's own three-layer CSRF stance (SameSite=Lax cookie + Origin check on every route handler + the API's CSRF token) instead of introducing a token-in-JS surface the plan explicitly avoids. `GET /user` gained two additive fields (`platformStaff`, `orgs[]`) so the web tier can route by role without a second call — an additive spec change, no client contract broken.

**Impact:** All §10.1 authed pages (dashboard, review queue + reviewer detail, T&S console, org admin, settings, publish flow + live progress, new-agent wizard) ship SSR with zero client-side auth code. Acceptance: `scripts/acceptance/m8-console.sh` signs in through the web tier and drives every surface (including the U+200B revelation in the file viewer, decision→rejected, triage→state change, block→quarantineState), asserts the authz refusals and a cross-origin-form 403, and runs the structural a11y checker signed-in (`a11y-check.py --cookie-jar`). A future SPA or mobile client would use PATs against the same API unchanged.

## DEV-013 — release-please authored, not executed on the build host (2026-08-28)

**What:** M8's "release-please" item is wired (`.github/workflows/release-please.yaml`, `release-please-config.json`, `.release-please-manifest.json`, seeded `CHANGELOG.md`) and the existing `release.yaml` was adjusted to append its verification block to the changelog release body (`append_body`) rather than overwrite it. It is **syntax-validated only** (JSON parses; both workflow YAMLs parse) — release-please itself is not run here because it requires the GitHub API, a real default-branch history of conventional commits, and a PR merge to exercise.

**Why:** Same class as DEV-001 for `deploy/compose` and the release/signing steps in `release.yaml`: the tooling is GitHub-hosted and cannot run against a local checkout. The config is small and declarative, so inspection + schema/lint validation is the appropriate bar here.

**Impact:** The release-automation flow (release PR → CHANGELOG → tag → build/sign/publish) is complete on paper and will run in the GitHub environment. One operational prerequisite is documented in both the workflow header and CONTRIBUTING.md → Releasing: a tag pushed with the default `GITHUB_TOKEN` does not trigger `release.yaml`, so a `RELEASE_PLEASE_TOKEN` secret (fine-grained PAT or GitHub App token) is needed for the automatic handoff; absent it, the release PR + changelog still work and the tag is pushed manually to cut assets.

## DEV-017 — `git archive` attribute neutralization is proven at startup, not assumed (2026-08-29)

**What:** §6.5 step 1 requires `git archive` to run with "`export-ignore` attributes ignored — the manifest allowlist is the only filter". The obvious mechanisms do not achieve that: `git archive` reads attributes from *the tree it is archiving* (it unpacks that tree into an in-memory index and points the attribute stack at it), so neither `core.attributesFile=/dev/null` (which silences only the global file — what the code did before) nor `attr.tree` / `--attr-source` displaces an in-tree `.gitattributes`. Measured against git 2.50.1: with all three of those, a file marked `export-ignore` is still dropped. `internal/gitsrv/archive.go` therefore neutralizes each source separately — `--worktree-attributes` (which moves the lookup onto the working tree, and a bare repo has none), `GIT_ATTR_NOSYSTEM=1` for the system file, `core.attributesFile=/dev/null` for the global one — and treats `$GIT_DIR/info/attributes`, for which git offers no disabling switch, as a hard error. Because that behaviour is a property of the installed binary rather than of a version number, it is **verified rather than declared**: `NewRepoStore` archives a throwaway repo whose tree marks a file `export-ignore` and refuses to start if the file does not survive, and every real archive is checked back against `git ls-tree` of the commit it came from, failing the submission if any path is missing.

**Why:** A version gate (e.g. "git ≥ 2.40 for `attr.tree`") would have been both wrong (the flag does not affect `git archive`) and weaker than the property it stands for. The failure this guards against is silent and shipped: a pushed `.gitattributes` quietly removing files from a published release, with a valid-looking archive digest over the reduced tree. A startup probe turns that into a refusal to boot on an incompatible git, and the per-archive check turns any future regression — a new git release, a different vendor build — into a failed submission with a named path list rather than a filtered release.

**Impact:** Two new operational behaviours. (1) `agentryd` (any role that constructs a `RepoStore`) exits at startup if its git honours `export-ignore` in `git archive`, naming the binary and version; the probe result is cached per binary path, costing ~40 ms once. (2) A repository carrying `$GIT_DIR/info/attributes` cannot publish until an operator removes the file — the file is unreachable over the git wire protocol and nothing in agentry writes it, so its presence is always operator action. No API, schema or manifest surface changes. Covered by `TestReleaseArchiveIgnoresExportIgnore`.

## DEV-018 — Enforced SSO on git transport gates writes and releases, not reads (2026-08-29)

**What:** §12.4 states that PATs "used against org resources must be org-bound" when `orgs.sso_required` is set. On the git transport (`internal/gitsrv`), that gate is applied to `agent.repo.write` and `agent.publish` only: `git push` and the `v*` tag creation that releases a version require a PAT bound to the agent's org, while `clone`/`fetch` — anonymous reads of public org repos, and granted reads of private ones — are unaffected. The check itself is not a re-implementation: it calls the same `Principal.SSOSatisfied` helper as `internal/api`'s chokepoint, so the semantics cannot drift.

**Why:** §6.4's authorization table is the specific statement for git operations, and it attaches the org-bound-token requirement to the push row alone; its clone/fetch rows ask for `repo:read` plus read permission and nothing more. Gating reads as well would break anonymous clones of public org repos — which §6.4's first row grants to everyone — and would make an org's public agents unusable by non-members the moment SSO enforcement is switched on, an outcome §12.4's "personal-namespace activity is unaffected" framing gives no reason to want. Mutations are where the enforcement earns its keep: they are what an unbound personal token should not be able to do to org-owned code.

**Impact:** In an enforced-SSO org, `git push` with a personal PAT returns 403 ("this organization requires an org-bound token") at the `info/refs` advertisement, before any pack is transferred; an org-bound PAT behaves normally, including `v*` tags. Non-enforcing orgs and personal namespaces are untouched, and so is every read path. A lookup failure on the org row denies rather than allows. If a later decision extends enforcement to private org reads, it is one `case` in `Handler.ssoAllows`. Covered by `TestGitEnforcedSSO`.

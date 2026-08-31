# Runner reference

The complete operator reference for running BriefAgents: every command,
flag, file, and enforcement mechanism. The [BriefAgents](briefagents.md)
page explains the package format; this page is the runtime side. The
as-built architecture lives with the code in the
[`agentry-cli`](https://github.com/blaktron/agentry-cli) repository
(`ARCHITECTURE.md`, with the immutable design record in `RUNNER-PLAN.md`
and `RUNNER-PLAN-2.md`).

## Commands

### `agentry setup`

Prepares a machine for BriefAgent runs — re-runnable, idempotent:

1. Configures your **LLM provider** into the operator policy —
   interactively on a terminal, or `--provider` / `--model` /
   `--api-key-env` / `--base-url` with `--yes`. Only the env var *name*
   for your key is stored, never the value. `custom` (or any unlisted
   provider name) derives the egress-proxy allowlist from `--base-url`.
2. Stands up the **docker-mcp-gateway plane**: verifies the docker
   engine, pulls the pinned gateway and harness images, and builds the
   local runner image from the CLI's embedded, stdlib-only build context
   (`--skip-images` configures policy only).

`agentry run` performs the same steps lazily on first use, so setup is a
convenience, not a gate. Note: setup rewrites `policy.yaml` as generated
YAML — hand-written comments there are not preserved.

### `agentry run <ns/name[@range]>`

One BriefAgent, one job, one container tree, then gone.

| Flag | Meaning |
|---|---|
| `--input FILE` | task text (else piped stdin, else an empty task) |
| `--file PATH` | provide a file or directory to the run, read-only under `/inputs` (repeatable; basename-rooted; duplicate basenames refused) |
| `--out DIR` | output folder (default `./agentry-out/<ns>-<name>-<runid>/`) |
| `--output-format text\|json` | stdout carries the result text, or the full envelope |
| `--keep-profile true\|false` | this run's MCP-profile completion choice (default: the profile's own setting, else policy) |
| `--reconfigure-profile` | re-run guided profile setup over an existing profile |
| `--timeout N` / `--max-turns N` | override the policy budgets (exit 15 / 16 on breach) |
| `--adapter NAME` / `--list-adapters` | harness adapter (default `docker-agent`; goose/claude/codex are planned slots) |
| `--local DIR` | run an unpublished BriefAgent tree (unsigned by definition: requires `--allow-unsigned`) |
| `--allow-unsigned` | run a release the registry has no attestation for; a *mismatched* attestation always refuses |
| `--pin sha256:…` | require the resolved archive digest to equal this value |
| `--prepare` | verify, compile, install images, run guided profile setup — then stop |
| `--dry-run` | print the compiled run plan; touches no docker, never prompts |
| `--yes` | accept the capability consent gate non-interactively |
| `--policy FILE` | operator policy override (tests, fleets) |
| `--keep-run-dir` | keep the per-run scratch dir for debugging (secrets are still deleted) |

First run of a release **is** the install: verify (sha256 digest + DSSE
attestation against TOFU-pinned keys — the same gate as
`agentry install`), extract, compile the run plan, cache it all per
digest. Later runs of the same digest reuse everything; a changed
operator policy recompiles the plan.

Runs compose like processes: `agentry run a … | agentry run b …`.

### `agentry profiles`

`list` shows every stored MCP profile (ref, digest, keep/remove setting,
secret *names*, last use — never values). `remove <ns/name[@version]>`
or `remove --all` deletes them.

### `agentry install <ref> --provider claude|codex|openclaw`

Embedded mode: the BriefAgent installs into a host agent application and
runs on **its** MCP servers and built-in tools — no docker gateway
involved. `--provider` picks the target (`claude`→claude-skill,
`codex`→agents-md, `openclaw`→claude-skill today); explicit `--target
claude-skill|mcp|agents-md` remains. The claude-skill target compiles the
capability contract into `allowed-tools` frontmatter; agents-md records
it as a Tools note. Plugin-system distribution per provider is planned.

## MCP profiles

A profile is the persistent, credentialed half of a BriefAgent's gateway
configuration, keyed by **signature** (ns/name@version + archive digest)
under `~/.agentry/runner/profiles/…` (directory `0700`, file `0600`).

- **Guided setup** runs on a terminal the first time a release with
  declared `secrets:` runs (or on `--reconfigure-profile`): the declared
  contract is shown, each key is collected with echo off (empty = resolve
  from the environment at run time), and the keep/remove question is
  asked.
- **Resolution order** at run time: profile → host environment / the
  policy's env file. A secret nothing resolves refuses the run (exit 11,
  naming the variable) — never a silent degrade.
- **Completion**: keep → the profile survives (stamped `lastUsedAt`) and
  the next run of that exact release just uses the authenticated
  resources; remove → deleted when the run completes. Default comes from
  policy `profiles.keepByDefault` (shipped `true`).
- A **different digest is a different trust decision** and gets a fresh
  guided setup. Non-interactive runs never create profiles and behave
  exactly like v1.

## The operator policy (`~/.agentry/runner/policy.yaml`)

Created on first use; `AGENTRY_RUNNER_HOME` moves the whole runner home.

| Key | Meaning |
|---|---|
| `images.gateway` / `images.harnessDockerAgent` / `images.goBuilder` | pinned images (digests recommended) |
| `images.runner` | override the locally built runner image tag (pin this when the CLI and desktop app share a machine) |
| `model.provider` / `model.name` / `model.apiKeyEnv` / `model.baseUrl` | the LLM the default adapter drives; the key env var name is yours |
| `model.proxyAllow` | host:port list — the agent container's **only** egress |
| `allowWildcardEgress` | gates manifest `egress: "*"` (default false → refused, exit 11) |
| `secretSource.mode` (`env` \| `envFile`) + `secretSource.envFile` | fallback secret resolution behind profiles |
| `budgets.timeoutSeconds` / `budgets.maxTurns` | default hard stops |
| `profiles.keepByDefault` | the default MCP-profile completion choice |
| `dataAccessServers.<category>` | operator-cataloged MCP server-entry files attached when a manifest declares that dataAccess category |

The policy participates in the plan hash: editing it invalidates cached
plans, which recompile on next use.

## What a run enforces

| Contract line | Mechanism |
|---|---|
| `egress: none` | tools container networking disabled; no `fetch` tool |
| `egress: [hosts]` | gateway per-server proxies + DNS interception (`--block-network`, always on) pin the tools container to `host:443`; the `fetch` tool re-checks the host per request and per redirect hop |
| `filesystem.*` | mount table on the tools container (`:ro`/`:rw`, per-path binds) + server-side grant checks; the agent container never mounts the workspace |
| `exec: {commands}` | `run_command` argv0 allowlist + a shim `PATH` containing only the declared commands |
| `secrets: [names]` | values only in the profile, the per-run secrets file (0600, deleted at teardown), and the tools container env — never in plans, receipts, or process listings |
| run inputs | `--file` items land in a per-run folder mounted **read-only** at `/inputs` on the tool plane, served by always-granted `list_inputs`/`read_input`; job output and receipts live on the separate `/out` volume |
| the agent container itself | internal-only network; reachable endpoints: the gateway (Bearer token) and the egress proxy (allowlist = `model.proxyAllow`); `/plan` is its only mount |

Every claim above appears, mechanism named, in the run's
`capabilities_enforced` — the receipts stay honest about what is enforced
versus declared.

## The output folder

```
<out>/
  result.json            the machine-readable envelope (status, exit class,
                         digest, attestation state, capabilities_enforced,
                         usage, run-plan hash)
  reports/…              whatever the BriefAgent wrote via write_report
  receipts/
    events.ndjson        the raw harness event stream
    gateway.log          the gateway's own log, tool calls included
    run-plan.json        the exact compiled plan that ran
    meta.json, task.txt  run identity, timing, budgets, the task input
```

Exit codes: `0` ok · `1` CLI · `10` verify failed · `11` refused by
policy / missing secret · `12` not compilable/runnable · `13` gateway or
docker environment · `14` the BriefAgent failed · `15` timeout ·
`16` budget · `17` output schema.

## The desktop app

The [desktop app](https://github.com/blaktron/agentry-desktop) mirrors
the registry (browse, report cards, the MCP servers & tools section) and
drives the same runner packages as the CLI: one-click setup with the
provider table, guided profile configuration as a form, and in-app runs
with task input, file/folder pickers for `/inputs` and the output folder,
a keep-profile toggle, a live log stream, and the result envelope.

## Verifying a runner installation

`make accept-runner` in the `agentry-cli` repo: plan-matrix and
determinism checks (no docker), a live MCP-stdio exercise of the tools
server, and — on a machine with a docker engine and a model API key — the
full end-to-end run with teardown leak checks.

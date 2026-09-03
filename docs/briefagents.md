# BriefAgents

*This page covers the package format. The complete runtime side — every
command, flag, policy key, MCP profiles, and enforcement mechanism — is
the [Runner reference](runner.md).*

A **BriefAgent** is a single-purpose AI agent packaged for Agentry:
one manifest declaring what it is and what it may touch, plus the instruction
content itself. Nothing else. BriefAgents carry **no tool code**. At run
time the Agentry runner serves exactly the tools the manifest declares
through an isolated MCP gateway, and when a BriefAgent is installed into an
existing coding agent, the host's built-in tools stand in under the same
declared contract.

Start from the **[BriefAgent template](https://github.com/blaktron/agentry-template)**
(`github.com/blaktron/agentry-template`), a runnable package with every
option below shown in a commented `agent.yaml`. Or scaffold one with
`agentry init`.

`agentry init --from PATH` imports an existing source instead of
scaffolding: an Agent Skills `SKILL.md` (frontmatter name, description,
license and `metadata.version` are mapped; sibling files are copied and
listed in `publish.include`) or an MCP registry `server.json`, which
becomes a skill that declares the published package under
`capabilities.mcpServers` with its exact pin and the secret-flagged
environment variable names. The capability contract is never guessed from
the source: on a terminal the wizard asks for egress, secrets, exec and
filesystem with hints found in the source as defaults you confirm;
non-interactively pass `--egress` and `--secrets` (`none` allowed;
`--exec`, `--fs-read`, `--fs-write` optional) or the import refuses and
prints the hints.

```bash
agentry setup                                        # one-time: LLM provider + the docker MCP gateway
agentry validate .                                   # the registry's checks, offline
agentry run --local . --dry-run --allow-unsigned     # the compiled enforcement plan
echo "task" | agentry run --local . --allow-unsigned --out ./agentry-out
agentry publish                                      # scanned, signed, immutable
```

## Machine setup (`agentry setup`)

One idempotent command prepares a machine for BriefAgent runs before any
agent is involved: it configures **your preferred LLM provider** for agent
runs into the operator policy (interactively on a terminal; `--provider`,
`--model`, `--api-key-env`, `--base-url` with `--yes` in scripts), then
stands up the docker-mcp-gateway plane right away — pulling the pinned
gateway and harness images and building the local runner image. The key
itself is never stored; only the environment variable *name* that will
hold it.

| provider | default model | key env var | agent-container egress |
|---|---|---|---|
| `anthropic` | claude-sonnet-4-5 | `ANTHROPIC_API_KEY` | api.anthropic.com:443 |
| `openai` | gpt-5.2 | `OPENAI_API_KEY` | api.openai.com:443 |
| `google` | gemini-3-pro | `GEMINI_API_KEY` | generativelanguage.googleapis.com:443 |
| `custom` | asked | asked | derived from `--base-url` |

`agentry run` still self-heals (it performs the same steps lazily on first
use), so setup is a convenience, not a gate. The desktop app drives the
same configuration from its Settings surface.

## MCP profiles — keys and identities, once per release

The first run of a BriefAgent that declares secrets starts a **guided
setup**: the runner shows the declared contract, collects each key or
identity (input hidden, values stored only in the profile, `0600`), and
asks whether to keep the result. The stored **MCP profile** is keyed by
*signature* — `ns/name@version` plus the archive digest — so:

- **keep** (the default): the next run of the same exact release just uses
  the authenticated resources — no re-prompting;
- **remove**: the profile is deleted when the run completes.

The choice is configurable at install time: `--keep-profile=true|false` on
`agentry run` (including `--prepare`), the guided setup's final question,
or the policy default `profiles.keepByDefault`. A **different digest is a
different trust decision** and gets a fresh guided setup. Manage stored
profiles with `agentry profiles list` and `agentry profiles remove
<ns/name[@version]>` (secret values are never printed); re-run the guided
flow with `--reconfigure-profile`. Non-interactive runs behave as before:
secrets resolve from the environment or the policy's env file, and a
missing one refuses the run (exit 11) rather than degrading.

## Package layout

```
my-briefagent/
├── agent.yaml                  # the manifest (required)
├── SKILL.md                    # kind: skill instructions (AGENT.md for prompt-agent)
├── README.md                   # rendered on the BriefAgent's registry page
├── LICENSE                     # required for public publication
└── output.schema.json          # optional: structured-output contract
```

## The manifest, option by option

`agent.yaml` uses manifest schema v1, a **closed** schema: unknown keys
are rejected, so a typo cannot silently disable a control.

### Identity and metadata

| Field | Required | Meaning and rules |
|---|---|---|
| `schemaVersion` | yes | the manifest schema major; only `"1"` exists |
| `name` | yes | lowercase `[a-z0-9-]`, ≤64 chars, starts/ends alphanumeric; unique within the namespace |
| `namespace` | yes | the publishing handle (a user or org), lowercase `[a-z0-9-]`, ≤39 chars |
| `kind` | yes | `skill` \| `prompt-agent` \| `mcp-server` (table below) |
| `version` | yes | strict semver without a leading `v`; equals the git tag when publishing from a tag; must exceed every existing version on its channel |
| `summary` | yes | one plain-text line, ≤140 characters |
| `license` | public publish | SPDX identifier or expression (`MIT OR Apache-2.0`) matching the LICENSE file |
| `authors` | no | `[{name, email?}, …]` |
| `homepage` | no | informational URL |
| `tags` | no | lowercase `[a-z0-9-]` search facets |

### Kinds and entrypoints

| `kind` | What it is | Entrypoint | Runnable by `agentry run`? |
|---|---|---|---|
| `skill` | an instruction package (Claude-skill-shaped) | `entrypoints.skill:`, the repo-relative skill file (default `SKILL.md`); frontmatter is stripped, the body becomes the harness instruction | yes |
| `prompt-agent` | pure instructions, no code entrypoint | none; the runner reads `AGENT.md`, else `PROMPT.md`, at the archive root | yes |
| `mcp-server` | a tool server other BriefAgents can use | `entrypoints.mcp: {command, args[], transport: stdio\|http}`; args naming repo files must appear in `publish.include` | no; it is a tool, not an agent (exit 12) |

### `runtime`: informational hints

| Field | Meaning |
|---|---|
| `runtime.models` | free-form model hint patterns (e.g. `["claude-*"]`). A hint, never a lock: the **operator's** runner policy chooses the model and owns the API key |
| `runtime.interfaces` | which install targets the package supports: `claude-skill`, `mcp`, `agents-md` |

### `capabilities`: the security contract

Closed vocabulary. Omitted or empty means a **pure-text BriefAgent**
(its only run-time tool is `write_report`). The registry scans releases
against these declarations, installs prompt on them (egress/exec need
typed consent; a widened contract re-asks on upgrade), and the runner
turns each line into a concrete control:

**`network.egress`**

| Value | Meaning | Run-time enforcement |
|---|---|---|
| `none` / omitted | no outbound network | tools container runs with networking disabled; no `fetch` tool |
| `[exact.dns.host, …]` | outbound only to these hosts | `fetch` granted, restricted to the listed hostnames (checked per request and per redirect hop); the gateway pins the tools container to `host:443` with per-server proxies and DNS interception |
| `"*"` | unrestricted egress | refused at run time unless the operator's policy sets `allowWildcardEgress: true`; the receipt then discloses it |

**`filesystem.read` / `filesystem.write`**

| Value | Meaning | Run-time enforcement |
|---|---|---|
| `none` / omitted | no access in that direction | the corresponding tools do not exist |
| `workspace` | the whole task workspace | `read` grants `fs_read` + `fs_list`; `write` grants `fs_write`; the workspace is bind-mounted into the **tools** container `ro`/`rw` accordingly |
| `{paths: [repo/relative, …]}` | only these paths | per-path bind mounts plus server-side grant checks; a directory entry covers everything under it |

The agent container itself never mounts the workspace. File access goes
through the gateway's tools, which is what makes the contract enforceable.

**`exec`**

| Value | Meaning | Run-time enforcement |
|---|---|---|
| `none` / omitted | no subprocesses | no `run_command` tool; harness built-in shells are never enabled |
| `{commands: [jq, git, …]}` | only these binaries | `run_command` restricted to the listed commands via an argv allowlist plus a shim `PATH` containing only them |

**`secrets`**: a list of environment variable **names**, never values.
The runner resolves each from the operator's secret source before any
container starts (missing ⇒ refuse, exit 11, naming the variable), and
injects values only into the tools container. The `fetch` tool can send a
declared secret as an auth header without the value entering model
context; values never appear in plans, receipts, or process listings.

**`dataAccess`** holds semantic categories for review and audit: `email`,
`calendar`, `files`, `tickets`, `code`, `messages`, `payments`, `other`.
Operators may catalog extra MCP servers per category in their runner
policy; undeclared categories are never wired in.

**`mcpServers`** declares the MCP servers the BriefAgent requires at run
time — explicitly, version-pinned, from a trusted repository:

```yaml
capabilities:
  mcpServers:
    - npm: "@modelcontextprotocol/server-github"
      version: 2026.1.2            # EXACT version — pinned to this release
      tools: [list_issues]         # optional allowlist within the server
      secrets: [GITHUB_PAT]        # env-var NAMES the server needs
      egress: [api.github.com]     # the server's own outbound needs
    - pypi: mcp-server-fetch
      version: 0.6.2
      egress: ["*"]
```

Each entry names exactly one package — `npm:` or `pypi:` — and an **exact
version**: ranges are rejected at validation, because the pin is part of
this release's content and therefore of its archive digest. Installing the
agent installs the servers (from the operator's configured registries —
npm and PyPI endpoints by default, private mirrors configurable), records
the resolved artifact digests, and configures the gateway to load them
**for that exact release signature only**. A new version of the agent is a
new supply-chain decision: nothing carries over, not the servers, not
their keys. Per-server `secrets` join the guided profile setup; per-server
`egress` is that server's own allowlist (`"*"` is policy-gated, like agent
egress). Removing the agent removes the server configuration and keys by
default; keeping them is an explicit option, and a kept configuration is
reachable by nothing except a reinstall of the same digest. Full runtime
mechanics: the [Runner reference](runner.md).

### `dependencies`

`dependencies.agents: [{ref: ns/name, version: "^1.2"}]` is informational
in v1: recorded and displayed, not auto-installed.

### `publish`

| Field | Meaning |
|---|---|
| `publish.include` | **required**; the release archive allowlist of glob patterns (`path.Match` segments; a whole segment `**` matches any depth). Nothing outside it ships |
| `publish.channel` | `stable` (default) or `beta` |

## What a BriefAgent gets at run time

`agentry run` verifies the release exactly like `agentry install`
(sha256 digest + DSSE attestation against pinned keys; unsigned requires
`--allow-unsigned`), compiles manifest + operator policy into a
deterministic run plan, then executes one container tree. The isolated
agent container sits on an internal-only network; its only reachable
endpoints are the MCP gateway and an allowlisting egress proxy for the
model API. A per-run Docker MCP Gateway fronts the companion tools server.

| Manifest declaration | Tool(s) granted |
|---|---|
| (always) | `write_report`: write files into the run's output folder |
| (always) | `list_inputs`, `read_input`: the run's provided input files, read-only |
| `filesystem.read` | `fs_read`, `fs_list` |
| `filesystem.write` | `fs_write` |
| `network.egress` hosts | `fetch` (with optional declared-secret auth) |
| `exec.commands` | `run_command` |

Every instruction is suffixed with the **runner contract**: tools come
only from the gateway; the workspace is rooted at `/workspace` as seen by
tools; provided input files are under `/inputs`; report files go through
`write_report`; the final message is the run's result.

**Input files.** Files and artifacts from outside the container reach a
run through `agentry run --file PATH` (repeatable; files or directories).
They are copied into a per-run folder mounted **read-only** at `/inputs`
on the tool plane — a channel like stdin, operator-controlled per run, so
it needs no manifest capability. Job output and receipts stay on the
separate `/out` volume.

**Structured output.** Ship an `output.schema.json` at the archive root
(listed in `publish.include`) and the runner embeds the schema in the
instruction and requires the final message to parse as JSON. Exit 17
otherwise, with the raw output preserved in the receipts.

**Task input and composition.** `--input FILE`, else piped stdin, else an
empty task. Runs compose: `agentry run a … | agentry run b …`.

**Budgets and exit codes.** The operator policy sets the default timeout
and tool-call budget; `--timeout` / `--max-turns` override per run.
Exit codes: `0` ok · `10` verify failed · `11` refused by policy /
missing secret · `12` not compilable/runnable · `13` gateway or docker
environment · `14` the BriefAgent failed · `15` timeout · `16` budget ·
`17` output schema.

**The output folder** (`--out`, default
`./agentry-out/<ns>-<name>-<runid>/`) holds `reports/…`, `result.json`
(the machine-readable envelope: enforcement mechanisms applied, digest,
attestation state, usage, run-plan hash), and `receipts/` (event stream,
gateway call log, the exact run plan).

**Operator policy** (`~/.agentry/runner/policy.yaml`, created on first
use) pins the gateway/harness images, names the model endpoint and its
API-key variable, sets the egress-proxy allowlist and budgets, chooses
the secret source, and gates wildcard egress.

## Installing into an existing coding agent

The same package installs into a host coding agent with **that
application's** MCP servers and built-in tools standing in. Nothing is
bundled either way, and these users never go through the docker gateway
path. Each major agent application has its own install entry point:

```bash
agentry install ns/name --provider claude    # Claude Code
agentry install ns/name --provider codex     # Codex
agentry install ns/name --provider openclaw  # OpenClaw
```

`--provider` picks the right target below (distribution through each
provider's plugin system is planned; the web Downloads page lists these
flows); the explicit `--target` forms remain:

| Target | What lands | Contract mapping |
|---|---|---|
| `claude-skill` | `~/.claude/skills/<name>/` with SKILL.md frontmatter | capabilities compile to `allowed-tools`: `Read`/`Grep`/`Glob` ⇐ read, `Write`/`Edit` ⇐ write, `Bash(cmd:*)` ⇐ exec, `WebFetch(domain:host)` ⇐ egress |
| `agents-md` | `./agents/<name>/` + a section in `./AGENTS.md` | the section records the same contract as a Tools note |
| `mcp` | `./agents/<name>/` + a server entry merged into `.mcp.json` | for `kind: mcp-server`; declared secrets become empty env placeholders |

Enforcement in embedded mode is the host's. The
[trust model](trust.md) page explains what each layer does and does not
prove.

## Publishing

Three doors, one pipeline. `agentry publish` submits a workspace from the
command line; the registry's **BriefAgent Builder** (`/build`) authors one
in the browser — anyone can download the packed archive for local use, and
signed-in users can submit it; and the **desktop app**'s Build tab does the
same from a form. Repos hosted on the registry can also publish by pushing
a release tag (the agent's auto-publish-tags setting). Whichever door,
the submission is identical server-side: manifest validation, content
scanning against the declared capabilities, human review where findings
demand it, and DSSE signing. Published releases are immutable and content-addressed. The
language rule applies to BriefAgents as it does to everything here: a
release is *scanned, with N findings, signed*, never "safe". Declare the
least you need and the whole chain stays reviewable.

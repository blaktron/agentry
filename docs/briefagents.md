# BriefAgents

A **BriefAgent** is a single-purpose AI agent packaged for SecureAgentry:
one manifest declaring what it is and what it may touch, the instruction
content itself, and nothing else. BriefAgents carry **no tool code** — at
run time the SecureAgentry runner serves exactly the tools the manifest
declares through an isolated MCP gateway, and when installed into an
existing coding agent the host's built-in tools stand in under the same
declared contract.

Start from the **[BriefAgent template](https://github.com/blaktron/agentry-template)**
(`github.com/blaktron/agentry-template`) — a runnable package with every
option below shown in a commented `agent.yaml`, or scaffold one with
`agentry init`.

```bash
agentry validate .                                   # the registry's checks, offline
agentry run --local . --dry-run --allow-unsigned     # the compiled enforcement plan
echo "task" | agentry run --local . --allow-unsigned --out ./agentry-out
agentry publish                                      # scanned, signed, immutable
```

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

`agent.yaml` uses manifest schema v1 — a **closed** schema: unknown keys
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
| `license` | public publish | SPDX identifier matching the LICENSE file |
| `authors` | no | `[{name, email?}, …]` |
| `homepage` | no | informational URL |
| `tags` | no | lowercase `[a-z0-9-]` search facets |

### Kinds and entrypoints

| `kind` | What it is | Entrypoint | Runnable by `agentry run`? |
|---|---|---|---|
| `skill` | an instruction package (Claude-skill-shaped) | `entrypoints.skill:` — the repo-relative skill file (default `SKILL.md`); frontmatter is stripped, the body becomes the harness instruction | yes |
| `prompt-agent` | pure instructions, no code entrypoint | none — the runner reads `AGENT.md`, else `PROMPT.md`, at the archive root | yes |
| `mcp-server` | a tool server other BriefAgents can use | `entrypoints.mcp: {command, args[], transport: stdio\|http}`; args naming repo files must appear in `publish.include` | no — it is a tool, not an agent (exit 12) |

### `runtime` — informational hints

| Field | Meaning |
|---|---|
| `runtime.models` | free-form model hint patterns (e.g. `["claude-*"]`). A hint, never a lock: the **operator's** runner policy chooses the model and owns the API key |
| `runtime.interfaces` | which install targets the package supports: `claude-skill`, `mcp`, `agents-md` |

### `capabilities` — the security contract

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

The agent container itself never mounts the workspace — file access goes
through the gateway's tools, which is what makes the contract enforceable.

**`exec`**

| Value | Meaning | Run-time enforcement |
|---|---|---|
| `none` / omitted | no subprocesses | no `run_command` tool; harness built-in shells are never enabled |
| `{commands: [jq, git, …]}` | only these binaries | `run_command` restricted to the listed commands via an argv allowlist plus a shim `PATH` containing only them |

**`secrets`** — a list of environment variable **names**, never values.
The runner resolves each from the operator's secret source before any
container starts (missing ⇒ refuse, exit 11, naming the variable), and
injects values only into the tools container. The `fetch` tool can send a
declared secret as an auth header without the value entering model
context; values never appear in plans, receipts, or process listings.

**`dataAccess`** — semantic categories for review and audit: `email`,
`calendar`, `files`, `tickets`, `code`, `messages`, `payments`, `other`.
Operators may catalog extra MCP servers per category in their runner
policy; undeclared categories are never wired in.

### `dependencies`

`dependencies.agents: [{ref: ns/name, version: "^1.2"}]` — informational
in v1: recorded and displayed, not auto-installed.

### `publish`

| Field | Meaning |
|---|---|
| `publish.include` | **required** — the release archive allowlist of glob patterns (`path.Match` segments; a whole segment `**` matches any depth). Nothing outside it ships |
| `publish.channel` | `stable` (default) or `beta` |

## What a BriefAgent gets at run time

`agentry run` verifies the release exactly like `agentry install`
(sha256 digest + DSSE attestation against pinned keys; unsigned requires
`--allow-unsigned`), compiles manifest + operator policy into a
deterministic run plan, then executes one container tree: an isolated
agent container on an internal-only network — its only reachable
endpoints are the MCP gateway and an allowlisting egress proxy for the
model API — plus a per-run Docker MCP Gateway fronting the companion
tools server.

| Manifest declaration | Tool(s) granted |
|---|---|
| — (always) | `write_report` — write files into the run's output folder |
| `filesystem.read` | `fs_read`, `fs_list` |
| `filesystem.write` | `fs_write` |
| `network.egress` hosts | `fetch` (with optional declared-secret auth) |
| `exec.commands` | `run_command` |

Every instruction is suffixed with the **runner contract**: tools come
only from the gateway; the workspace is rooted at `/workspace` as seen by
tools; report files go through `write_report`; the final message is the
run's result.

**Structured output.** Ship an `output.schema.json` at the archive root
(listed in `publish.include`) and the runner embeds the schema in the
instruction and requires the final message to parse as JSON — exit 17
otherwise, raw output preserved in the receipts.

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

The same package installs into a host coding agent with the host's
built-in tools standing in — nothing is bundled either way:

| Target | What lands | Contract mapping |
|---|---|---|
| `claude-skill` | `~/.claude/skills/<name>/` with SKILL.md frontmatter | capabilities compile to `allowed-tools`: `Read`/`Grep`/`Glob` ⇐ read, `Write`/`Edit` ⇐ write, `Bash(cmd:*)` ⇐ exec, `WebFetch(domain:host)` ⇐ egress |
| `agents-md` | `./agents/<name>/` + a section in `./AGENTS.md` | the section records the same contract as a Tools note |
| `mcp` | `./agents/<name>/` + a server entry merged into `.mcp.json` | for `kind: mcp-server`; declared secrets become empty env placeholders |

Enforcement in embedded mode is the host's — the
[trust model](trust.md) page explains what each layer does and does not
prove.

## Publishing

`agentry publish` submits the version to the mandatory pipeline: manifest
validation, content scanning against the declared capabilities, and DSSE
signing. Published releases are immutable and content-addressed. The
language rule applies to BriefAgents as it does to everything here: a
release is *scanned, with N findings, signed* — never "safe". Declare the
least you need and the whole chain stays reviewable.

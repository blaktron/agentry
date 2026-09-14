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
scaffolding. From an Agent Skills `SKILL.md` it maps the frontmatter name,
description, license and `metadata.version`, copies the sibling files and
lists them in `publish.include`. From an MCP registry `server.json` it
writes a BriefAgent that declares the published package under
`capabilities.mcpServers` with its exact pin and the secret-flagged
environment variable names. The capability contract is never guessed from
the source: on a terminal the wizard asks for egress, secrets, exec and
filesystem with hints found in the source as defaults you confirm;
non-interactively pass `--egress` and `--secrets` (`none` allowed;
`--exec`, `--fs-read`, `--fs-write` optional) or the import refuses and
prints the hints.

```bash
agentry setup                                        # one-time: LLM provider + the docker MCP gateway
agentry validate .                                   # the manifest rules and the offline scanners (S1/S3/S4)
agentry run --local . --dry-run --allow-unsigned     # the compiled enforcement plan
echo "task" | agentry run --local . --allow-unsigned --out ./agentry-out
agentry publish                                      # scanned, signed, immutable
```

## Machine setup (`agentry setup`)

One idempotent command prepares a machine for BriefAgent runs before any
agent is involved. It writes **your preferred LLM provider** into the
operator policy (interactively on a terminal; `--provider`, `--model`,
`--api-key-env`, `--base-url` with `--yes` in scripts), then stands up the
docker-mcp-gateway plane right away — pulling the pinned gateway and
harness images and building the local runner image. The key itself is
never stored; only the environment variable *name* that will hold it.

| provider | default model | key env var | agent-container egress |
|---|---|---|---|
| `anthropic` | claude-sonnet-4-5 | `ANTHROPIC_API_KEY` | api.anthropic.com:443 |
| `openai` | gpt-5.2 | `OPENAI_API_KEY` | api.openai.com:443 |
| `google` | gemini-3-pro | `GEMINI_API_KEY` | generativelanguage.googleapis.com:443 |
| `custom` | asked | asked | derived from `--base-url` |

For an **OpenAI-compatible endpoint** (a gateway, a hosted open-weight
model, a vendor's compatible mode) use `--provider openai --base-url
https://…/v1 --model <id>`: the provider name is what the harness sees, and
`openai` with a base URL is its OpenAI-compatible mode. The key reaches the
harness under the **same variable name** you give `--api-key-env`, and the
harness's providers read their conventional names — so name it
`OPENAI_API_KEY` for that path. The agent container's egress allowlist is
derived from the base URL's host.

`agentry run` still self-heals (it performs the same steps lazily on first
use), so setup is a convenience, not a gate. The desktop app drives the
same configuration from its Settings surface.

## MCP profiles — keys and identities, once per release

The first run of a BriefAgent that declares secrets starts a **guided
setup**: the runner shows the declared contract, collects each key or
identity (input hidden, values stored only in the profile, `0600`), and
asks whether to keep the result. The stored **MCP profile** is keyed by
*signature* — `ns/name@version` plus the archive digest — so:

- **keep** (the default): the next run of the same exact release uses the
  authenticated resources — no re-prompting;
- **remove**: the profile is deleted when the run completes.

The choice is configurable at install time: `--keep-profile=true|false` on
`agentry run` (including `--prepare`), the guided setup's final question,
or the policy default `profiles.keepByDefault`. A **different digest is a
different trust decision** and gets a fresh guided setup. Manage stored
profiles with `agentry profiles list` and `agentry profiles remove
<ns/name[@version]>` (secret values are never printed); re-run the guided
flow with `--reconfigure-profile`. A non-interactive run skips the guided
setup: secrets resolve from the environment or the policy's env file, and a
missing one refuses the run (exit 11) rather than degrading.

## Package layout

```
my-briefagent/
├── agent.yaml                  # the manifest (required)
├── AGENT.md                    # the instruction file (entrypoints.instruction)
├── README.md                   # rendered on the registry page; required for public publication
├── LICENSE                     # required for public publication
└── output.schema.json          # optional: structured-output contract
```

## The manifest, option by option

`agent.yaml` uses manifest schema **v2**, a **closed** schema: unknown keys
are rejected, so a typo cannot silently disable a control. Releases
published under schema v1 (the `kind`-classified manifest) stay readable
forever — the registry maps `skill` and `prompt-agent` to
`modes: [autonomous]` — but a v2 manifest is what you write today, and
only a v2 manifest can declare `interactive`.

### Identity and metadata

| Field | Required | Meaning and rules |
|---|---|---|
| `schemaVersion` | yes | the manifest schema major: `"2"` (v1 is read, not written) |
| `name` | yes | lowercase `[a-z0-9-]`, ≤65 chars, starts/ends alphanumeric; unique within the namespace |
| `namespace` | yes | the publishing handle (a user or org), lowercase `[a-z0-9-]`, ≤39 chars |
| `modes` | yes | the run modes the release supports: `[autonomous]`, `[interactive]`, or both (section below) |
| `version` | yes | strict semver without a leading `v`; equals the git tag when publishing from a tag; must exceed every existing version on its channel |
| `summary` | yes | one plain-text line, ≤140 characters |
| `license` | public publish | SPDX identifier or expression (`MIT OR Apache-2.0`); a `LICENSE` file must be present (its text is not compared) |
| `authors` | no | `[{name, email?}, …]` |
| `homepage` | no | informational URL |
| `tags` | no | lowercase `[a-z0-9-]` search facets |

### Modes and the instruction file

A BriefAgent is an instruction package. What varies is how it runs, and a
release declares the set of run modes it supports:

| Mode | What a run is | Status |
|---|---|---|
| `autonomous` | starts from its files — after the up-front questions, if any, and MCP profile authentication — does the job, writes its output and receipts, and ends | this is `agentry run` today |
| `interactive` | starts from the same plan and controls, but the run is a conversation: in the CLI a chat in the terminal (`agentry run --mode interactive`), in the desktop the run panel's chat. The agent can ask for information as the work reveals the need; you can answer and drop files into the read-only inputs folder (`/add PATH`), then `/finish` for the final result. You **cannot** give it more access than the manifest declares — the capability contract, the gateway and the egress allowlist are exactly those of an autonomous run of the same release, and a permission request from inside the sandbox is granted only for a tool the plan already serves, refused otherwise | `agentry run --mode interactive`; a release with one mode runs in it, one with both is asked on a terminal and runs autonomous otherwise |

The instruction is one file:

| Field | Meaning |
|---|---|
| `entrypoints.instruction` | the repo-relative instruction file, `AGENT.md` when omitted. A leading YAML frontmatter block (the Agent Skills `SKILL.md` shape) is stripped; the body becomes the harness instruction, so a `SKILL.md` works unchanged as `entrypoints.instruction: SKILL.md`. The file must exist and be matched by `publish.include` |

There are no other package kinds. An MCP server is something a BriefAgent
*uses* — declared under `capabilities.mcpServers` and installed with the
release — not a package of its own; the former `mcp-server` kind was
withdrawn, and the one such package on the public registry is blocked
with an advisory saying so.

### `intake`: questions asked before a run

Both modes may ask a few things up front. The runner asks them through
the same prompter that collects MCP profile secrets (a terminal prompt in
the CLI, a form in the desktop) and stages the answers read-only for the
agent at `/inputs/intake.json`.

```yaml
intake:
  - id: dataset            # [a-z0-9_]+, unique
    prompt: "Path to the dataset to analyse"
    type: file             # text (default) | secret | choice | file
    required: true
  - id: region
    prompt: "Which region?"
    type: choice
    choices: [emea, apac, amer]
```

| Rule | |
|---|---|
| `id` | `[a-z0-9_]{1,64}`, unique within the manifest |
| `prompt` | required |
| `type` | `text`, `secret` (injected as a run-scoped secret, never written as text or recorded; the upper-cased id must be listed under `capabilities.secrets`, or the run refuses it), `choice` (needs `choices`), `file` (a host path the runner stages into the inputs folder) |
| `choices` | only with `type: choice` |
| at most 20 questions | |

Non-secret answers are part of the run's receipts.

### `interactive`: session hints

```yaml
interactive:
  opening: "Which incident, and what do you need from it?"   # ≤ 500 characters
  idleTimeoutSeconds: 900                                    # policy caps it
```

`opening` is the assistant's first message when a session starts with no
task text. Everything else about a session — budgets, idle timeout, wall
time — is the operator's runner policy, which a manifest can only
tighten. A release that does not list `interactive` may still declare
hints: validation warns, and they never apply.

### `runtime`: informational hints

| Field | Meaning |
|---|---|
| `runtime.models` | free-form model hint patterns (e.g. `["claude-*"]`). A hint, never a lock: the **operator's** runner policy chooses the model and owns the API key |
| `runtime.interfaces` | which install targets the package supports: `claude-skill`, `agents-md`. Independent of mode — an interactive agent still exports as a Claude skill; what it loses in that host is the Agentry session, not its instructions. The first listed interface picks the default `agentry install` target |

### `capabilities`: the security contract

Closed vocabulary. Omitted or empty means a **pure-text BriefAgent**
(its run-time tools are `write_report` and the read-only `list_inputs` /
`read_input`, nothing else). The registry scans releases
against these declarations, an install prompts on them (egress/exec need
typed consent; a widened contract re-asks on upgrade), and the runner
turns each line into a concrete control. The same contract covers support
scripts. The scan reads every shell, Python or JavaScript file in the
package, and reports as high a script under `exec: none`, a network call
to a host outside `network.egress`, a file write under
`filesystem.write: none`, an undeclared subprocess or `eval`, and any
`curl … | sh` remote execution; an environment variable read outside
`secrets` is a medium finding. It matches text without running anything,
and a host only counts inside a network call, so a documentation URL in a
comment is not a finding (see [trust](trust.md), stage S6).

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
time — explicitly, version-pinned, from the operator's configured
package registries:

```yaml
capabilities:
  mcpServers:
    - npm: github-mcp-server-js
      version: 0.1.7               # EXACT version — pinned to this release
      tools: [list_issues, get_issue]   # optional allowlist within the server
      secrets: [GITHUB_TOKEN]      # env-var NAMES the server needs
      env:
        GITHUB_PERMISSION: read-only    # plain configuration, never a secret
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

**`env`** on a server entry is the plain configuration the server reads
from its environment — a mode switch, a directory, a region — as opposed
to a credential. Values are written in the manifest, so they are visible
in the release diff, part of the release's archive digest like the pin,
and shown to reviewers. The rules (a v2 field): at most 16 entries per
server; names on the environment-variable grammar; values single-line
strings of at most 512 characters with no control characters. A name that
is also listed under `secrets` — the server's or the agent's — is refused:
a value is either configuration in the contract or a secret from the
profile, never both. `agent.yaml` is scanned like any other archived
file, so a token in a shape the secret scanner recognises is a finding;
that is a backstop, not a place to keep one. In the example above,
`GITHUB_PERMISSION` comes from the manifest and `GITHUB_TOKEN` from the
operator's profile. The runner compiles `env` into the server's gateway
entry as its plain environment, shows the pairs beside the server's secret
names at install and asks for consent again when a value changes, and the
receipt names the keys. Values are literal: the gateway would expand a
`$` followed by a name character, `{` or a shell parameter character
(`$NAME`, `${NAME}`, `$$`) against the server's environment, secrets
included, and evaluate a value holding both `{{` and `}}` as a template,
so `agentry validate` and submission refuse those shapes (V5, "declare a
literal value"); a trailing `$` or a single brace pair is literal and
passes. The runner refuses the same shapes at plan time, and with them an
empty value and the `@@` marker of its own run placeholders.

**Declared servers are scanned too.** At submission, stage S7 checks each
declared package version against the OSV vulnerability database and reports
every advisory as a finding at the advisory's own severity, CVE ids and
fixed versions included — a high finding routes the version to review, a
critical one rejects it, exactly like a finding in your own files. Pin a
version with a fix rather than asking for an exception; the [trust
model](trust.md) page describes what the check does and does not prove.

### `dependencies`

`dependencies.agents: [{ref: ns/name, version: "^1.2"}]` is informational:
recorded and displayed, not auto-installed.

### `publish`

| Field | Meaning |
|---|---|
| `publish.include` | **required**; the release archive allowlist of glob patterns (`path.Match` segments; a whole segment `**` matches any depth). Nothing outside it ships |
| `publish.channel` | `stable` (default) or `beta` |

## What a BriefAgent gets at run time

`agentry run` verifies the release exactly like `agentry install`
(sha256 digest + DSSE attestation against pinned keys; unsigned requires
`--allow-unsigned`), asks the registry whether any declared MCP server
version carries a known high or critical vulnerability (refusing if so,
unless the operator overrides it), compiles manifest + operator policy into
a deterministic run plan, then executes one container tree. That is an
**autonomous** run; an **interactive** session starts from the same plan
and the same enforcement and adds only a conversation and a read-only
file drop (see [Modes](#modes-and-the-instruction-file)). The isolated
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

The runner suffixes every instruction with the **runner contract**: tools
come only from the gateway; the workspace is rooted at `/workspace` as
seen by tools; provided input files are under `/inputs`; report files go
through `write_report`; the final message is the run's result.

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

**Budgets and exit codes.** The operator policy sets the default timeout,
tool-call budget and cost ceiling; `--timeout` / `--max-turns` /
`--max-cost` override per run (a run is killed once the harness reports
more than the cost ceiling, `0` = unlimited). Exit codes: `0` ok · `1`
other CLI error · `2` usage · `10` verify failed · `11` refused by policy /
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

Enforcement in embedded mode is the host's. The
[trust model](trust.md) page explains what each layer does and does not
prove.

## Publishing

Three doors, one pipeline. `agentry publish` submits a workspace from the
command line; the hosted site's **BriefAgent Builder** (`/build`, on a
registry with the site in front) authors one in the browser — anyone can
download the packed archive for local use, and signed-in users can submit
it; and the **desktop app**'s Build tab does the same from a form. Repos hosted on the registry can also publish by pushing
a release tag (the agent's auto-publish-tags setting). Whichever door,
the submission is identical server-side: manifest validation, content
scanning against the declared capabilities, human review where findings
demand it, and DSSE signing. A publish to a public namespace needs a
second factor on the account (a TOTP app, or an identity provider that
did MFA) when the registry has that on — `/meta` reports it as
`features.publicPublish2FA`. Published releases are immutable and content-addressed. The
language rule applies to BriefAgents as it does to everything here: a
release is *scanned, with N findings, signed*, never "safe". Declare the
least you need and the whole chain stays reviewable.

Every door checks the same quotas (V8): at most 2,000 files and 10 MiB in
the archive, 2 MiB per file (5 MiB per image), and 1 MiB of text files in
total — the prose the scanners read in full, so an instruction set cannot
grow past what a reviewer can read by being split across files.
`agentry validate` reports the same limits offline.

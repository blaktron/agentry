# Runner reference

The complete operator reference for running BriefAgents: every command,
flag, file, and enforcement mechanism. The [BriefAgents](briefagents.md)
page explains the package format; this page is the runtime side. The
as-built architecture is
[ARCHITECTURE.md](https://github.com/blaktron/agentry-notes/blob/main/ARCHITECTURE.md)
§6 in agentry-notes; the original runner design records are archived there
under `archive/agentry-cli/`, and departures from them are logged in
[RUNNER-DEVIATIONS.md](https://github.com/blaktron/agentry-notes/blob/main/agentry-cli/RUNNER-DEVIATIONS.md).

## Commands

Two flags are global to every command below.

`--registry URL` names the registry to talk to. Without it the CLI uses the
configured default, then the default baked into the binary: a build a
registry serves under `/downloads/`, or one from a site's download page,
points at that registry, and a source build falls back to
`http://localhost:8080`. `--json` asks for machine-readable output where a
command supports it: `info`, `search`, `verify`.

### `agentry setup`

Prepares a machine for BriefAgent runs — re-runnable, idempotent:

1. Configures your **LLM provider** into the operator policy —
   interactively on a terminal, or `--provider` / `--model` /
   `--api-key-env` / `--base-url` with `--yes`. Only the env var *name*
   for your key is stored, never the value. `custom` (or any unlisted
   provider name) derives the egress-proxy allowlist from `--base-url`.
   For an OpenAI-compatible endpoint use `--provider openai --base-url …`
   and name the key `OPENAI_API_KEY`: the provider name and the variable
   name are passed to the harness as given (see the
   [provider table](briefagents.md#machine-setup-agentry-setup)).
2. Stands up the **docker-mcp-gateway plane**: verifies the docker
   engine, pulls the pinned gateway and harness images, and builds the
   local runner image from the CLI's embedded, stdlib-only build context
   (`--skip-images` configures policy only).

`agentry run` performs the same steps lazily on first use, so setup is a
convenience, not a gate. Note: setup rewrites `policy.yaml` as generated
YAML — hand-written comments there are not preserved.

### `agentry doctor [ns/name[@range] | --local DIR]`

Reports, without changing anything, whether `agentry run` would get past
its preflight on this machine: the operator policy and model (provider,
model, the `apiKeyEnv` variable present in the environment), the secret
source, the docker engine, the pinned gateway/harness/runner images (and the
node/python runtime images when the agent declares MCP servers of that
ecosystem), and the registry's `/healthz`. With a ref or `--local DIR` it
also checks that BriefAgent: resolution, the verified install (a warning
until the first `run --prepare`), the declared MCP servers' store, the
compiled plan, the MCP profile, the registry's vulnerability verdict on each
declared MCP server, and that **every declared secret resolves** —
the exit-11 refusals a scheduled run would otherwise meet at 03:00. Exit 0
when every check passes (warnings allowed), 1 otherwise; `--json` for
machines. No secret *value* is ever printed. `--adapter NAME` adds the
checks a host-run harness needs: that its executable resolves (on `PATH`
or at `harness.<name>.path`), which release is installed and whether that
is the one the adapter was written against, and whether the endpoint
`harness.<name>.baseUrl` names is one `model.proxyAllow` permits.

### `agentry run <ns/name[@range]>`

One BriefAgent, one job, one container tree, then gone.

| Flag | Meaning |
|---|---|
| `--mode autonomous\|interactive` | the run mode (default: the release's only mode; asked on a terminal when it declares both, autonomous otherwise) |
| `--input FILE` | task text (else piped stdin, else an empty task) |
| `--intake id=value` | answer an intake question non-interactively (repeatable; unanswered questions are asked on a terminal, and a `secret` answer is never recorded) |
| `--file PATH` | provide a file or directory to the run, read-only under `/inputs` (repeatable; basename-rooted; duplicate basenames refused) |
| `--out DIR` | output folder (default `./agentry-out/<ns>-<name>-<runid>/`) |
| `--output-format text\|json` | stdout carries the result text, or the full envelope |
| `--keep-profile true\|false` | this run's MCP-profile completion choice (default: the profile's own setting, else policy) |
| `--reconfigure-profile` | re-run guided profile setup over an existing profile |
| `--timeout N` / `--max-turns N` / `--max-cost USD` | override the policy budgets (exit 15 / 16 on breach; cost is the harness's running total, `0` = unlimited) |
| `--adapter NAME` / `--list-adapters` | harness adapter (default `docker-agent`; `claude` and `codex` drive your own installation of those CLIs, see below; goose is a planned slot) |
| `--local DIR` | run an unpublished BriefAgent tree (unsigned by definition: requires `--allow-unsigned`) |
| `--allow-unsigned` | run a release the registry has no attestation for; a *mismatched* attestation always refuses |
| `--allow-vulnerable-mcp` | run even though the registry reports a known high or critical vulnerability for a declared MCP server version (the receipt records the override) |
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

### Run modes

A release declares the run modes it supports (`modes` in the manifest),
and the runner compiles one plan per mode from the same manifest and
policy. An **autonomous** run is the files in, the output and receipts
out, the sandbox gone. An **interactive** session (`--mode interactive`)
is the same plan, gateway and enforcement driven as a conversation: the
harness serves the Agent Client Protocol over stdio inside the sandbox,
and the CLI opens a chat in the terminal. Type to talk, `/add PATH` to
drop a file or directory into the read-only inputs folder, `/caps` to
print the enforced contract, `/finish` to end the session with the
agent's final result (validated against `output.schema.json` like an
autonomous result), `/quit` to abandon it, `/help`. The release's
`interactive.opening` line starts the conversation when no task text was
given. A permission request from inside the sandbox is always answered
*deny*: nothing a user types can widen what the manifest declared. The
session is bounded by the policy's `sessions` block (idle timeout, wall
time, user turns) on top of the cost and tool-call budgets, and its
receipts add `transcript.md` and the intake answers. A release with one
mode runs in it; one with both is asked on a terminal and runs autonomous
otherwise (`--yes` or `--dry-run` never ask). The desktop app runs the
same session in its run panel.

### Intake questions

A release may declare up to twenty **intake** questions (`intake` in the
manifest). The runner asks them before either kind of run — on a terminal
through the same prompter that collects MCP profile secrets, in the
desktop as a form — or takes them from `--intake id=value`. Answers are
staged read-only for the agent as `/inputs/intake.json`; a `file` answer
is copied into the inputs folder like `--file`; a `secret` answer becomes
a run-scoped secret under its upper-cased id and is never written as
text or recorded. Non-secret answers appear in the receipts.

### `agentry uninstall <ns/name[@version]>`

Removes this machine's runner state for a BriefAgent: the verified
install cache (workspace + compiled plans) and — **by default** — its
MCP profile, stored keys and installed MCP servers included
(RUNNER-PLAN-3: remove on uninstall is the default). `--keep-mcp`
retains the profile directory, which stays locked to the exact release
digest it was created for: a same-digest reinstall reconnects without
re-prompting; nothing else — no other BriefAgent, no other user, no
newer version — can ever reference it. Embedded installs (claude-skill /
mcp / agents-md exports) are separate state and untouched.

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
- **Completion**, when the run ends: keep → the profile survives (stamped
  `lastUsedAt`) and the next run of that exact release reuses the
  authenticated resources; remove → deleted when the run completes.
  Default comes from policy `profiles.keepByDefault` (shipped `true`).
- A **different digest is a different trust decision** and gets a fresh
  guided setup. Non-interactive runs never create profiles and behave
  exactly like v1.

### Declared MCP servers (RUNNER-PLAN-3)

A release that declares `capabilities.mcpServers` installs them as part
of its own install: each entry resolves against the operator's configured
registries (`mcpRegistries`, npm/PyPI by default) at its **exact pinned
version**, the resolved artifact digests are recorded into the release's
profile (`servers/`), the dependency closure is installed inside the
pinned runtime image with egress restricted to the registry hosts, and
the consent gate shows every server, source, version, and digest before
anything is fetched. PyPI servers install **wheel-only**: the builder
downloads the pinned package on its own, checks the file pip chose against
every digest the registry's metadata advertised for that release, refuses
an unlisted or mismatching file, and only then installs it plus wheels for
its dependencies — a source distribution would run the package's own build
code in the builder, so it is refused unless the policy's
`mcpRegistries.pypiAllowSourceDists: true` says otherwise. npm installs
run with `--ignore-scripts`. At run time the per-run gateway loads exactly those
servers — each with its declared tool filter, its own egress allowlist,
and only its own secret values — alongside the agentry tools server. A
server's plain `env` map (manifest v2; see the [BriefAgent
reference](briefagents.md)) is validated and shown by the registry today
and is not yet part of what the gateway passes to a server: compiling it
into the catalog entry, with consent at install and the key names in the
receipt, is agentry-cli#99.

**Known vulnerabilities.** Before a declared server is resolved, the runner
asks the registry what its scan and daily sweep recorded for that exact
package version (`GET /mcp-servers/scan`). A known **high or critical**
advisory refuses the run (exit 11, naming the advisories and the versions
they are fixed in) unless `--allow-vulnerable-mcp` or the policy's
`mcpServers.allowVulnerable` overrides it; lower severities and a version
the registry has never seen only print a line. A registry that cannot be
reached does not stop the run. Whatever happened, the receipt's
`capabilities_enforced.mcpServers.vulnerabilities` says what was checked,
against which registry, and why the run went ahead. `agentry doctor`
reports the same verdict per server, as a failure when a run would refuse.

The isolation rules are the profile rules: server configuration and keys
belong to one signature (ns/name@version + digest). No other BriefAgent
can reach them, no other user can read them (0700, per-run containers are
the only consumers), and a **new version of the same BriefAgent starts
over** — new digest, fresh resolve, fresh consent, fresh keys. A
reinstall of the same signature whose registry resolution no longer
matches the recorded digests refuses (the pin is the trust decision).
`agentry profiles remove` deletes servers and keys with the profile;
uninstalling a BriefAgent does the same, because **remove is the default**.
`agentry uninstall --keep-mcp` retains the signature directory so a
same-digest reinstall reconnects without re-prompting.

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
| `budgets.timeoutSeconds` / `budgets.maxTurns` / `budgets.maxCostUsd` | default hard stops (cost `0` = unlimited) |
| `sessions.idleTimeoutSeconds` / `sessions.maxWallSeconds` / `sessions.maxUserTurns` | interactive-session caps (shipped 900 s idle, 7200 s wall, 200 user turns); a manifest can only tighten the idle timeout |
| `profiles.keepByDefault` | the default MCP-profile completion choice |
| `dataAccessServers.<category>` | operator-cataloged MCP server-entry files attached when a manifest declares that dataAccess category |
| `mcpRegistries.npm` / `mcpRegistries.pypi` | where declared `capabilities.mcpServers` resolve (defaults: registry.npmjs.org, pypi.org; point at private mirrors here) |
| `mcpRegistries.pypiAllowSourceDists` | allow a PyPI MCP server to install from a source distribution (default false: wheels only, see below) |
| `mcpServers.allowVulnerable` | let runs proceed when the registry reports a high or critical advisory for a declared server version (default false: refused, exit 11) |
| `harness.<adapter>.path` | the executable a host-run harness adapter uses instead of looking it up on `PATH` |
| `harness.<adapter>.baseUrl` / `.model` / `.apiKeyEnv` | the model endpoint that adapter is given, in its own vendor's terms — a host-run harness speaks its vendor's API, which is not always the one `model.*` describes. The host must also be in `model.proxyAllow` or the run's proxy denies it (`agentry doctor --adapter <name>` says so before a run finds out). |
| `images.nodeRuntime` / `images.pythonRuntime` | pinned runtime images that install and run declared npm/PyPI MCP servers |

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
| the gateway on an SELinux host | the gateway is the one container that drives the host's docker daemon, so on a daemon with SELinux enabled it runs with label confinement off (`--security-opt label=disable`) — a confined container cannot open that socket at all. Everything else in the run stays confined, and the run's own directories are relabelled so the tool containers can use them; the socket itself is never relabelled, which would hand daemon access to every container on the machine. |
| a **host-run** harness instead (`--adapter claude`) | no agent container: the gateway's catalog is still the whole tool surface, and the proxy variables are still the route to the model, but they are configuration the harness is asked to honour rather than a network it cannot leave. The receipt says so in `capabilities_enforced["harness.isolation"]`, and `receipts/proxy.log` shows every CONNECT it actually made. |

Every claim above appears, mechanism named, in the run's
`capabilities_enforced` — the receipts stay honest about what is enforced
versus declared.

When a BriefAgent declares `exec: {commands: […]}`, its tools server runs in a
per-BriefAgent **exec image** — the runner image with every executable deleted
except the declared commands (and the runner binary that serves the tools),
built once at install time from a one-line generated Dockerfile
(`agentry-runner-exec:<version>-<hash>`). `run_command` is still gated by the
argv0 allowlist and shim `PATH`; the image no longer contains anything
else to run. A declared command the runner image never had is reported absent,
as before.

## Harness adapters

`--adapter` chooses which agent harness runs the BriefAgent. Every adapter
gets the same contract — the gateway's catalog is the only tool surface, the
model key and the gateway token arrive by variable name, telemetry is off,
and the result envelope has one shape — and a conformance suite holds them
to it. What differs is where the harness runs.

| Adapter | What runs | Modes | Isolation |
|---|---|---|---|
| `docker-agent` (default) | the pinned `docker/docker-agent` image | autonomous, interactive (Agent Client Protocol over the container's stdio) | a container on the run's internal network: it has no route out but the proxy |
| `claude` | **your own installation** of Claude Code, as a process of your user | autonomous, interactive (Claude Code's own bidirectional stream-json) | the harness is outside the run's network boundary — see below |
| `codex` | **your own installation** of the OpenAI Codex CLI, as a process of your user | autonomous, interactive (codex's own app-server protocol) | as for `claude` — see below |
| `goose` | planned (RUNNER M-R4d) | — | — |

### `claude`

The runner does not package or pin Claude Code: it runs the `claude` you
already have (`harness.claude.path` overrides the `PATH` lookup), and
`agentry doctor --adapter claude` reports which release that is. Each run
gets a generated MCP config naming the run's gateway and nothing else,
locked in with `--strict-mcp-config`, with the built-in tools switched off
and anything outside the gateway's catalog refused. It runs in Claude Code's
bare mode, so none of your hooks, plugins, skills, memory or `CLAUDE.md`
reaches a BriefAgent run, and `CLAUDE_CONFIG_DIR` points inside the run, so
the run leaves nothing in your own configuration.

Bare mode also reads no login credential of yours, which is deliberate: a
run spends the **operator's** model access, never your subscription. Give it
an endpoint that speaks the Anthropic Messages API — Anthropic's own or a
compatible one — with `harness.claude.baseUrl`, `.model` and `.apiKeyEnv`,
and put its host in `model.proxyAllow`.

### `codex`

The same shape as `claude`, with codex's own mechanisms. The runner runs
the `codex` you have installed (`harness.codex.path` overrides the `PATH`
lookup; `agentry doctor --adapter codex` reports the release) from a
run-scoped `CODEX_HOME`, so none of your own config, rules, skills or
sessions is read and nothing of the run lands in yours. The generated
config declares the run's gateway as the only MCP server and switches
every built-in tool off — the shell, the image viewer, web search, apps,
the browser, computer use, image generation, sub-agents, hooks, memories —
leaving the model the gateway's catalog and codex's three MCP resource
readers, which read from that same gateway. It runs with `--strict-config`
on purpose: a config key a codex release renames is a loud refusal, not a
silently re-enabled tool.

Codex speaks the OpenAI Responses API and, in the release the adapter was
written against, nothing else. The policy's `model.baseUrl`, `.apiKeyEnv`
and `.name` are what it is given, as a provider block in that config; an
OpenAI-compatible endpoint that serves `/responses` works as it stands, and
`harness.codex.baseUrl` / `.model` / `.apiKeyEnv` override those three when
the endpoint differs from the default adapter's. An autonomous run is
`codex exec` with JSONL events; an interactive session is codex's own
app-server protocol over stdio, in which the runner is the approval
authority — each MCP call is put to the runner, which accepts it for a
gateway tool and declines anything else, and every answer is a transcript
line.

The trade-off to understand: a harness running as your own process is not
inside the run's network boundary the way a container is. Its file and
network access are bounded by its configuration and by the proxy variables,
not by Docker. The tools container still enforces every declared capability
for everything that goes through the gateway, and `receipts/proxy.log`
records every CONNECT the harness made, so the enforcement record stays
honest about which half is which.

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
    proxy.log            the LLM egress proxy's decisions: one allow/deny line per CONNECT
    run-plan.json        the exact compiled plan that ran
    meta.json, task.txt  run identity, timing, budgets, the task input
    intake.json          the non-secret intake answers (when the release asks any)
    transcript.md        the conversation, for an interactive session
```

Exit codes: `0` ok · `1` other CLI error · `2` usage · `10` verify failed ·
`11` refused by policy / missing secret · `12` not compilable/runnable ·
`13` gateway or docker environment · `14` the BriefAgent failed ·
`15` timeout · `16` budget · `17` output schema.

## The desktop app

The [desktop app](https://github.com/blaktron/agentry-desktop) mirrors
the registry (browse, report cards, the MCP servers & tools section) and
drives the same runner packages as the CLI: one-click setup with the
provider table (including a prerequisites installer for docker and the
MCP gateway), guided profile configuration and intake questions as forms,
and in-app runs with task input, file/folder pickers for `/inputs` and the
output folder, a keep-profile toggle, a live log stream, and the result
envelope. An interactive release opens as a chat in the same run panel,
over the same session API the CLI uses. It signs in through the browser —
the registry's directory service handles the login, one explicit approval
page hands the app a one-time code on a loopback listener, and the app
exchanges the code for a scoped token from its own process (the token
never appears in the browser); a sign-in that stalls can be cancelled
from Settings. Its Build tab authors and submits BriefAgents through the
same pipeline as `agentry publish`, with a structured editor for
`capabilities.mcpServers`.

## Verifying a runner installation

`make accept-runner` in the `agentry-cli` repo: plan-matrix and
determinism checks (no docker), a live MCP-stdio exercise of the tools
server, and — on a machine with a docker engine and the model key named by
the operator policy's `apiKeyEnv` in the environment (`ANTHROPIC_API_KEY`
when there is no policy yet) — the full end-to-end run with teardown leak
checks (`scripts/acceptance/runner-r2.sh`).

## The other commands

The rest of the CLI, one line each; the [package format](briefagents.md)
page covers authoring and publishing in depth.

| Command | What it does |
|---|---|
| `agentry login [--browser \| --paste]` | signs in to a registry: the browser flow hands the CLI a one-time code on a loopback listener and the CLI exchanges it for a scoped token from its own process; `--paste` reads a token from stdin for machines without a browser. Signing in also pins the registry's signing keys (TOFU) |
| `agentry init [--from PATH]` | scaffolds a workspace, or imports a `SKILL.md` or an MCP registry `server.json` |
| `agentry validate DIR` | the registry's manifest rules and offline scanners (V1–V9, S1/S3/S4) |
| `agentry info ns/name` / `agentry search` | a BriefAgent's page and capability contract; full-text search with the mode, capability, license and verified-org facets (`--json` on both) |
| `agentry verify ns/name@version` | digest and DSSE attestation check against the pinned keys — an exit code for CI |
| `agentry publish` | submits a workspace and follows the pipeline's event stream to the verdict |
| `agentry yank ns/name@version` | yanks a published version |
| `agentry install` / `uninstall` / `profiles` / `doctor` / `setup` | above |

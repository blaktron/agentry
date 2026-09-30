# Runner reference

The complete operator reference for running QuickAgents: every command,
flag, file, and enforcement mechanism. The [QuickAgents](quickagents.md)
page explains the package format; this page is the runtime side, and
[Hosted runs](hosted-runs.md) is the same runner driven on a deployment's
own machine, with caps and credits, instead of yours. The
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
`http://localhost:8080`. `--json` asks for machine-readable output on stdout
where a command supports it; the shapes are listed under
[Machine-readable output](#machine-readable-output).

### `agentry setup`

Prepares a machine for QuickAgent runs — re-runnable, idempotent:

1. Configures your **LLM provider** into the operator policy —
   interactively on a terminal, or `--provider` / `--model` /
   `--api-key-env` / `--base-url` with `--yes`. Only the env var *name*
   for your key is stored, never the value. `custom` (or any unlisted
   provider name) derives the egress-proxy allowlist from `--base-url`.
   For an OpenAI-compatible endpoint use `--provider openai --base-url …`
   and name the key `OPENAI_API_KEY`: the provider name and the variable
   name are passed to the harness as given (see the
   [provider table](quickagents.md#machine-setup-agentry-setup)).
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
also checks that QuickAgent: resolution, the verified install (a warning
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

One QuickAgent, one job, one container tree, then gone.

| Flag | Meaning |
|---|---|
| `--mode autonomous\|interactive` | the run mode (default: the release's only mode; asked on a terminal when it declares both, autonomous otherwise) |
| `--input FILE` | task text (else piped stdin, else an empty task) |
| `--intake id=value` | answer an intake question non-interactively (repeatable; unanswered questions are asked on a terminal, and a `secret` answer is never recorded) |
| `--file PATH` | provide a file or directory to the run, read-only under `/inputs` (repeatable; basename-rooted; duplicate basenames refused) |
| `--knowledge DIR` | attach a knowledge pack read-only at `/knowledge/<name>`, searched with the knowledge tools (repeatable; [below](#knowledge-packs)) |
| `--out DIR` | output folder (default `./agentry-out/<ns>-<name>-<runid>/`) |
| `--output-format text\|json` | stdout carries the result text, or the full envelope |
| `--keep-profile true\|false` | this run's MCP-profile completion choice (default: the profile's own setting, else policy) |
| `--reconfigure-profile` | re-run guided profile setup over an existing profile |
| `--timeout N` / `--max-turns N` / `--max-cost USD` | override the policy budgets (exit 15 / 16 on breach; cost is the harness's running total, `0` = unlimited) |
| `--adapter NAME` / `--list-adapters` | harness adapter (default `docker-agent`; `claude` and `codex` drive your own installation of those CLIs, see below; goose is a planned slot) |
| `--local DIR` | run an unpublished QuickAgent tree (unsigned by definition: requires `--allow-unsigned`) |
| `--allow-unsigned` | run a release the registry has no attestation for; a *mismatched* attestation always refuses |
| `--allow-vulnerable-mcp` | run even though the registry reports a known high or critical vulnerability for a declared MCP server version (the receipt records the override) |
| `--pin sha256:…` | require the resolved archive digest to equal this value |
| `--prepare` | verify, compile, install images, run guided profile setup — then stop |
| `--dry-run` | print the compiled run plan; touches no docker, never prompts |
| `--yes` | accept the capability consent gate non-interactively |
| `--policy FILE` | operator policy override (tests, fleets) |
| `--keep-run-dir` | keep the per-run scratch dir for debugging (secrets are still deleted) |
| `--events FILE` | append the harness event stream to FILE as JSON lines **while the run is live** — the same redacted lines the receipt's `events.ndjson` gets, for a driver that meters a run as it goes |
| `--session-protocol` | drive an interactive session from a program, with no terminal: JSON-line commands on stdin, its events on descriptor 3 ([below](#driving-a-session-from-a-program)) |
| `--session-inputs DIR` | with `--session-protocol`: the directory the driver stages files in; an add must name a regular file directly in it (without it, the session takes no files) |

With `--output-format json` the run also narrates the harness's usage to
**stderr** as it arrives, one line per report:

```
usage: input=6186 output=2153 total=8339 turns=2
```

stdout still carries nothing but the envelope, so a driver reads the lines
without disturbing what it parses. The numbers are the run's running totals,
and the last line is what the envelope ends up carrying; `total` is the
harness's own total where it reports one and input plus output otherwise, so
a meter never has to know which kind of harness ran. Text mode narrates no
usage. This is what lets something driving `agentry run` hold it to a token
budget while it runs, rather than discovering the cost when the run is over
(`--timeout` and `--max-turns` are enforced inside the run either way).

First run of a release **is** the install: verify (sha256 digest + DSSE
attestation against TOFU-pinned keys — the same gate as
`agentry install`), extract, compile the run plan, cache it all per
digest. Later runs of the same digest reuse everything; each run mode keeps
its own plan. A plan is recompiled when anything it was compiled from
changes — the operator policy, the adapter, the declared MCP servers, the
plan schema, the CLI build or the runner image — or when its files fail
their integrity check. The last four say so on stderr.

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
given. A permission request from inside the sandbox is granted only for
a tool the plan's gateway already serves, and refused for anything else
(both recorded in the receipts): nothing a user types can widen what the
manifest declared. The
session is bounded by the policy's `sessions` block (idle timeout, wall
time, user turns) on top of the cost and tool-call budgets, and its
receipts add `transcript.md` and the intake answers. A release with one
mode runs in it; one with both is asked on a terminal and runs autonomous
otherwise (`--yes` or `--dry-run` never ask). The desktop app runs the
same session in its run panel, and a hosted session
([Hosted runs](hosted-runs.md#a-hosted-session)) runs it on a sandbox host
through the session protocol below.

#### Driving a session from a program

Without a terminal, an interactive run is refused: the chat is its input.
`--session-protocol` is the other way in, for a program that drives the
session itself, such as runhost on a sandbox host (DR-51):

```
agentry run ns/name --mode interactive --session-protocol \
  --session-inputs DIR --yes --output-format json --input TASK 3>EVENTS
```

- **Commands** arrive on stdin, one JSON object a line:
  `{"send":{"text":"…"}}` sends a message, `{"add":{"path":"…"}}` adds a
  file, and `{"end":{"finish":true}}` asks the agent for its final result
  and ends (`false` ends without one). End of input is an end without a
  result. The task comes only from `--input`, since stdin is the command
  stream.
- **One turn at a time.** A `send` is refused from a `user_turn` event to
  the event that closes the turn, the task's own turn included when there
  is one.
- **Files.** An `add` must name a regular file directly in
  `--session-inputs DIR`, where the driver stages it; a relative path is
  taken there, and a path that resolves into a subdirectory or out of the
  directory, or a link, is refused. Without the
  flag the session takes no files. The engine checks the file again when it
  copies it under `/inputs`.
- **Events** leave on descriptor 3, one JSON line each: the session's own
  event, redacted exactly as it reaches the receipt's `events.ndjson`,
  without `raw`. Descriptor 3 must be a pipe or a socket open for writing;
  anything else is a usage error before anything runs. It is closed on exec,
  so no process the CLI starts can write to it.
- **Refusals.** A command the protocol will not take is answered on
  descriptor 3 by an `error` event carrying `refused`: `malformed`,
  `unknown_command`, `busy` or `input_refused`. A refusal never ends the
  session and is not a session event, so the receipts do not hold it.
- **stdout and stderr** are what they are for any run: the envelope under
  `--output-format json`, and the usage narration.
- **A slow reader** never stops the session: events are queued, and a
  reader 16 MiB behind, or whose pipe broke, is written nothing more, and
  stderr says so once. The idle close, the budgets and the teardown run
  regardless.
- **What stays refused.** Without the flag, the terminal rule stands.
  `--events` is refused with it, and an autonomous run refuses the flag.
  Windows refuses it. The flag changes nothing that is compiled: the plan
  is the one a terminal session runs.

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

Removes this machine's runner state for a QuickAgent: the verified
install cache (workspace + compiled plans) and — **by default** — its
MCP profile, stored keys and installed MCP servers included
(RUNNER-PLAN-3: remove on uninstall is the default). `--keep-mcp`
retains the profile directory, which stays locked to the exact release
digest it was created for: a same-digest reinstall reconnects without
re-prompting; nothing else — no other QuickAgent, no other user, no
newer version — can ever reference it. Embedded installs (claude-skill /
mcp / agents-md exports) are separate state and untouched.

### `agentry profiles`

`list` shows every stored MCP profile (ref, digest, keep/remove setting,
secret *names*, last use — never values). `remove <ns/name[@version]>`
or `remove --all` deletes them.

### `agentry install <ref>`

The default target is the runner home (explicitly, `--target runner`):
the release verified (digest, attestation, the capability contract
diffed against the installed version, the same consent gate as a first
run) and laid down in `~/.agentry/runner/agents/<ns>/<name>/<version>-<digest12>/`,
where `agentry run` reads it — a run after the install fetches nothing,
and the consent given at install covers the run. Inside it, under
`export/`, lands the coding-agent shape the operator policy implies
(`harness.claude` → a Claude skill; `harness.codex` → AGENTS.md; else an
Anthropic key → a Claude skill, any other provider → AGENTS.md), where a
host adapter can read it. `--dir` is refused for this target. A newer
version replaces the older; `agentry uninstall` removes the directory
and the record; `agentry list --check` asks the registry (the configured
one for these records; the credential goes to it alone) whether a newer
version exists.

### `agentry install <ref> --provider claude|codex|openclaw`

Embedded mode: the QuickAgent installs into a host agent application and
runs on **its** MCP servers and built-in tools — no docker gateway
involved. `--provider` picks the target (`claude`→claude-skill,
`codex`→agents-md, `openclaw`→claude-skill today); explicit `--target
claude-skill|agents-md` remains. The claude-skill target compiles the
capability contract into `allowed-tools` frontmatter; agents-md records
it as a Tools note. Plugin-system distribution per provider is planned.

### `agentry draft "<description>"`

Drafts a QuickAgent from a plain description of what it should do
(`--description-file FILE` reads it from a file; `--hint TEXT`, repeatable,
adds the services or sites it works with, how it runs, or an example of the
output wanted). The built-in **Drafter** does the work: the second package
the CLI embeds, run with the attestation state `builtin` like the Knowledge
Creator, never fetched from a registry. It searches the registry for a
published QuickAgent that already does the task, researches how the task is
done, and writes a draft. It never submits anything.

- **AI Review reads what the Drafter reads, first.** TypeSafe's Jev reads the
  description and the hints before the Drafter starts; one it flags, or
  cannot scan, stops the draft at stage `description` (exit 11) before
  anything is searched or read. While the Drafter works, AI Review reads
  every search result, page and registry answer before the Drafter's model
  does. What it flags, or cannot scan, is withheld: the model gets the
  address and the reason, never the text, and the draft lists it. On this
  machine the scans use **your own Jev key** (`$TYPESAFE_API_KEY`, the
  variable the policy's `judge.apiKeyEnv` names, or with
  `judge.apiKeySource: keyring` the keychain entry `provider:typesafe`), and
  without one the Drafter does not run.
- **The web tools** (`web_search`, `web_read`, `registry_search`) are the
  Drafter's alone; the compiler refuses them to any other package. They run in the
  tools container, which holds the scan and search keys; the agent container
  holds no Jev key, no search key and no registry credential. `web_read`
  makes GET requests only, over http and https on ports 80 and 443, to
  public addresses only, checked at every connection and redirect hop, sends
  no cookie or credential, and returns at most 32 KiB of a page's text.
  `web_search` needs a search provider of your own in the policy's
  `webSearch` block (`brave` with `$BRAVE_API_KEY`, or `youcom` with
  `$YDC_API_KEY`, or the keychain); without one the Drafter reads the
  registry and the pages it already knows. Under a sandboxed runtime the
  Drafter does not run without
  [`docker.resolvers`](#the-hosts-name-servers-dockerresolvers).
- **Where the words go.** The description, the searches and the pages go to
  the search provider, to TypeSafe and to the sites read, so the description
  should hold no secret. The draft runs against the model the policy names,
  for no credits.
- **The result**, in `--out DIR` (default
  `./agentry-out/agentry-drafter-<runid>`): `draft.json` (the manifest as
  JSON, the instructions, the notes, the matching published QuickAgents, the
  sources, the open questions, AI Review's record, and `validation`, the
  report `agentry validate --json` gives on the rendered package) and
  `package/` (`agent.yaml`, the instruction file, `AGENT.md` unless the
  draft names another, a README and a LICENSE placeholder), beside the run's
  `reports/` and `receipts/`.
  A draft that still fails the rules after the steps below is kept with its
  problems for you to fix ([below](#before-a-draft-is-written)); review
  every part before you publish it.
  `--timeout`, `--max-turns` and `--max-cost` bound the run.
- **The Drafter decides rather than asks.** It picks a default for what the
  description leaves open and names it in its notes. It asks at most three
  intake questions (most drafts none or one), lists at most five things to
  prepare, leaves at most two open questions, and keeps its notes to five
  bullets. The instruction it writes has four parts: Role, Inputs, Steps and
  Output.
- **In Agentry.** `agentry draft --hosted --output-format json` is what a
  sandbox host runs for a draft made in Agentry, from the site's or the
  desktop's Describe it: the scans, the search and AI Review's check of the
  finished draft go through the registry with the job's credential in
  `$AGENTRY_JOB_TOKEN`, and no Jev or search key
  is on the host ([the draft kind](hosted-runs.md#a-hosted-draft)).

#### Before a draft is written

The CLI checks every draft in four steps (agentry-cli#417, agentry-cli#418):

1. **Mechanical slips are corrected without the model.** A mode, a tag or
   a choice named twice loses the second one. An optional part left empty,
   or holding a placeholder such as "None", is removed. A list past its
   limit is cut to the limit, and a text past its limit is shortened at a
   word, ending with "…". The limits are the rules' own. The notes name
   each correction under "Corrected after drafting", and nothing is
   invented.
2. **The rules check it**, with `agentry validate`'s own code.
3. **AI Review checks the finished draft.** It reads the rendered package
   (exactly the files `publish.include` takes, the license among them) two
   ways: with the release rubric, asked as the pipeline's stage S5 asks it
   at publish, and with one question on whether the instructions do the
   task you described (`off_task`). On this machine it uses your own Jev
   key. With `--hosted` it uses the registry's
   [`POST /api/v1/model-input/check`](model-input.md#the-check-of-a-finished-draft) with
   the job's credential, which the registry admits at most twice a draft
   and the CLI never retries. The verdicts go into `draft.json` under
   `aiReview.check`, and the notes say what a flag means under "AI
   Review's check".
    - The rubric's C3 (a capability used but not declared) is recorded and
      never sent to the repair turn; at publish it sends the version to
      review, not to refusal.
    - A description over 8 KiB is not checked, and neither is a draft that
      could not be rendered.
    - A pass does not mean the draft does all of the task. The pipeline
      scans the whole version at publish whatever the check said.
4. **One repair turn.** If the rules still refuse the draft, or the check
   flagged something the draft can fix (`off_task`, or a rubric finding
   other than C3), the Drafter runs once more, without its web tools.
    - Its task is the rules' report, what the check flagged, and its own
      manifest and instructions, and nothing else: no notes, no page. With a
      flag it is also given the task the first turn was given, which AI
      Review passed before that turn started.
    - A last message that was not a draft at all (not one JSON object, exit
      17) gets the same turn, given the error and that message back. The turn
      returns the manifest again, and the instruction file too if the report
      names it.
    - The second answer is corrected and checked like the first, so a draft
      asks at most two checks. It is kept whether or not it passes, unless
      it breaks rules the first passed. Its notes say "Repaired once" and
      what sent it to the turn.
    - A repair turn that returns no draft leaves the first, with its
      problems and a note saying why. When the first was not a draft
      either, the draft ends with exit 17.
    - The turn's budget is the draft's, capped at 300 seconds and 8 tool
      calls, and what is left of `--max-cost`. Its receipts are in
      `DIR/repair/`, and the usage lines it narrates count from the first
      turn's total.

## MCP profiles

A profile is the persistent, credentialed half of a QuickAgent's gateway
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
only its own secret values, and its plain `env` map (manifest v2; see the
[QuickAgent reference](quickagents.md)) as the environment the server
starts with — alongside the agentry tools server. A server's declared hosts
are reached through the gateway's per-host TCP relays on its own relay
network; nothing else resolves from the server. That network has one fixed
name for every gateway on the docker host (the pinned docker/mcp-gateway
offers no other), so the runner refuses to share it: a run whose declared
servers need relays does not start (exit 13) while another gateway's relay
sidecars are on it — another run of `agentry`, or the user's own
`docker mcp gateway` — and the relays its gateway started are removed at
teardown by the names the gateway's log gave them. The check is made as
the run starts: a gateway started during the run is not refused. Two
QuickAgents with declared egress therefore run one at a time on a host. A
changed `env` value is a
change to the server: the install-state diff reports it and asks for
consent again, and the receipt's server line names the `env` keys, never
a value. The runner refuses an `env` value the gateway would rewrite (one
holding `$NAME`, `${NAME}` or `{{…}}`), an empty one, or one carrying the
run's `@@…@@` placeholder marker: a declared value is literal or it is not
declared.

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
belong to one signature (ns/name@version + digest). No other QuickAgent
can reach them, no other user can read them (0700, per-run containers are
the only consumers), and a **new version of the same QuickAgent starts
over** — new digest, fresh resolve, fresh consent, fresh keys. A
reinstall of the same signature whose registry resolution no longer
matches the recorded digests refuses (the pin is the trust decision).
`agentry profiles remove` deletes servers and keys with the profile;
uninstalling a QuickAgent does the same, because **remove is the default**.
`agentry uninstall --keep-mcp` retains the signature directory so a
same-digest reinstall reconnects without re-prompting.

## The operator policy (`~/.agentry/runner/policy.yaml`)

Created on first use; `AGENTRY_RUNNER_HOME` moves the whole runner home.
A run's envelope names the policy file it enforced, how that path was
chosen (`default`, `--policy` as `flag`, or `env` for a relocated home) and
its digest, so a run record says which file a run obeyed.

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
| `exec.packages` | the exec catalog: command name → apk package (optionally `=version`) the exec image installs for a QuickAgent that declares that command; a declared command with no entry is refused at plan time (exit 11) |
| `exec.apkMirror` | the Alpine mirror the exec image build installs from (default: the runner image's own repositories) — egress of the image build only, over ordinary docker networking; a run's network posture is unchanged |
| `harness.<adapter>.path` | the executable a host-run harness adapter uses instead of looking it up on `PATH` |
| `harness.<adapter>.baseUrl` / `.model` / `.apiKeyEnv` | the model endpoint that adapter is given, in its own vendor's terms — a host-run harness speaks its vendor's API, which is not always the one `model.*` describes. The host must also be in `model.proxyAllow` or the run's proxy denies it (`agentry doctor --adapter <name>` says so before a run finds out). |
| `images.nodeRuntime` / `images.pythonRuntime` | pinned runtime images that install and run declared npm/PyPI MCP servers |
| `docker.runtime` | the daemon-registered OCI runtime the containers holding the QuickAgent's code are created with (unset: the daemon's default) — below |
| `docker.gatewayRuntime` | the daemon-registered runtime the gateway alone is created with: a second registration of gVisor with `--host-uds=open` (unset: the daemon's default; needs `docker.runtime`) — below |
| `docker.resolvers` | at most three IPv4 name servers of the host's that the built-in Drafter's web tools, and under `docker.runtime` the llm-proxy, the MCP server install proxy and the relays, resolve through (unset: docker's DNS) — below |

The policy participates in the plan hash: editing it invalidates cached
plans, which recompile on next use.

### The OCI runtime (`docker.runtime`)

```yaml
docker:
  runtime: runsc
```

`docker.runtime` names a runtime the docker daemon has registered — gVisor's
`runsc`, or any name `docker run --runtime` takes — and the runner creates the
containers that hold **the QuickAgent's code** with it: the agent container,
an interactive session's agent and the one-shot that gives it the session
store, and the MCP server installer that builds a declared server's dependency
closure. Unset, the shipped default, every container takes the daemon's own
default and the receipt says nothing about a runtime.

Since agentry-cli#221 the runtime also holds the gateway's health probe and,
through the run's docker filter, the tools server and the declared MCP servers
the gateway launches. A sandboxed runtime's own network stack does not reach
docker's embedded DNS at `127.0.0.11`, so the containers under it find the
ones they talk to through `/etc/hosts` entries pinned from the containers'
addresses.

Four classes need more than that, measured on a live run rather than assumed
(DR-23), and since agentry-cli#337 each can move under a sandbox too:

- **The llm-proxy, the MCP server install proxy and the relays** resolve the
  hosts they forward to by name. With `docker.resolvers` (below) they run
  under `docker.runtime`, reading a `resolv.conf` of the run's own. Each is
  created with every network it joins, because a sandboxed container takes
  no network connected after it starts. So the proxies leave through an
  egress network of their own rather than docker's default bridge, which
  docker does not attach beside another network at create. The docker
  filter refuses to connect a started container under the runtime to a
  network. Without resolvers the three stay on the daemon's default. So does
  the proxy of a host-run harness, which publishes ports to the host, and so
  do the relays where the docker filter does not run (Docker Desktop,
  agentry-cli#322).
- **The gateway** reaches the run's docker filter through a bind-mounted host
  Unix socket, which `runsc` opens only when registered with
  `--host-uds=open`. `docker.gatewayRuntime` names such a registration for
  the gateway alone:

  ```json
  "runtimes": {
    "runsc":     { "path": "/usr/bin/runsc" },
    "runsc-uds": { "path": "/usr/bin/runsc", "runtimeArgs": ["--host-uds=open"] }
  }
  ```

  ```yaml
  docker:
    runtime: runsc
    gatewayRuntime: runsc-uds
    resolvers: [192.168.122.1]
  ```

  The flag opens only the sockets bind-mounted into that container, and the
  gateway's one socket is the filter's. `docker.gatewayRuntime` needs
  `docker.runtime`: the gateway is never sandboxed while the QuickAgent's
  code is not. Unset, the gateway stays on the daemon's default.

gVisor's `--reproduce-nat`, the other flag the measurements tried, starts no
container on a host whose docker writes its rules through nftables. The
receipt's runtime line names each class, and each that takes the default and
why; with both settings it says that no class of the run is on the daemon's
default.

### The host's name servers (`docker.resolvers`)

```yaml
docker:
  runtime: runsc
  resolvers: [192.168.122.1]
```

The built-in Drafter's web tools reach past the host by name, on a network
of the run's own. Under a sandboxed runtime their container cannot reach
docker's embedded DNS there. `--dns` only sets that server's upstream on a
user-defined network. gVisor's `--reproduce-nat`, which would copy docker's
DNS rule into the sandbox, does not start a container on a host whose docker
writes its rules through nftables. Both were measured on 2026-09-27
(agentry-cli#386).

So the runner writes the policy's `docker.resolvers` into a `resolv.conf` of
the run's own, and the docker filter binds it read-only at `/etc/resolv.conf`
in the web tools' server and, under the runtime, in each relay. The runner
binds it into the llm-proxy too, and the install proxy gets one of its own
(agentry-cli#337). That server takes no DNS setting, hosts
entry, volume or tmpfs of the gateway's, and nothing under `/etc` but its
tools spec.

Name the host's upstream name servers: at most three, IPv4 (the run's web
network has none of IPv6), never a loopback stub such as systemd-resolved's
`127.0.0.53`, which is the container's own loopback inside it. The same
servers answer every class that reads them. The address
rule of `web_read` still holds on every address a name resolves to, at every
connection.

Under a runtime with no resolvers, `agentry draft` is refused at compile
(exit 11) rather than left to read nothing, and `agentry doctor` warns about
it as `docker:resolvers`. On the daemon's default runtime nothing needs
setting. The resolvers are part of the compiled plan, and the receipt's
runtime line and its `web.resolvers` line name them. A sandbox host's runhost
renders them from `AGENTRY_RUNHOST_RESOLVERS`: on production, the host's own
resolvers, the only ones its firewall admits on port 53.

A set runtime is enforced, not preferred. Before anything is pulled or
started, `agentry run` asks the daemon which runtimes it has and stops the run
when the named one is absent (exit 13, naming the one wanted and the ones
present); it never falls back to another, because a run that quietly landed on
`runc` after asking for `runsc` would carry a receipt claiming an isolation it
did not have. `agentry doctor` reports the same check as `docker:runtime` —
ok when the daemon has the runtime, fail with the same two lists and the fix
when it does not. `docker.gatewayRuntime` is held to the same check, and
by what it runs as well as its name, since the receipt says the gateway ran
under it: its registration must run `docker.runtime`'s binary with
`docker.runtime`'s own `runtimeArgs` plus `--host-uds=open`, in any order
and nothing else. A registration that runs `runc`, lacks the flag, or adds
another beside it (`--network=host`, `--host-uds=all`) stops the run at
ensure (exit 13) with the extra or missing flags named, and doctor reports
the same as `docker:gatewayRuntime`. A sandbox host's runhost renders it
from `AGENTRY_RUNHOST_GATEWAY_RUNTIME` and, before it takes a job, also
checks that the registration runs `docker.runtime`'s binary with
`--host-uds=open`.

The runtime is part of the compiled plan, so changing it recompiles rather
than reinterpreting a cached plan. `capabilities_enforced.runtime` in the
receipt is written at run time, because two of its facts are the run's:
whether the docker filter runs (not on Docker Desktop, agentry-cli#322) and
what the run started. It names what was created under the runtime, what the
gateway's containers were given through the filter, and each class on the
daemon's default with its measured reason.

Hosted runs are why the knob exists: the platform's run worker renders
`docker.runtime: runsc` into the policy of every run it drives. That side is
[Hosted runs](hosted-runs.md).

## What a run enforces

| Contract line | Mechanism |
|---|---|
| `egress: none` | tools container networking disabled; no `fetch` tool |
| `egress: [hosts]` | gateway per-server proxies + DNS interception (`--block-network`, always on) pin the tools container to `host:443`; the `fetch` tool re-checks the host per request and per redirect hop |
| `filesystem.*` | mount table on the tools container (`:ro`/`:rw`, per-path binds) + server-side grant checks; the agent container never mounts the workspace |
| `exec: {commands}` | `run_command` argv0 allowlist + a shim `PATH` containing only the declared commands |
| `secrets: [names]` | values only in the profile, the per-run secrets file (0600, deleted at teardown), the tools container env (a declared server's own: that server's container env), and the MCP gateway's container, which reads the whole secrets file to inject them — never in plans, receipts, or process listings |
| run inputs | `--file` items land in a per-run folder mounted **read-only** at `/inputs` on the tool plane, served by always-granted `list_inputs`/`read_input`; job output and receipts live on the separate `/out` volume |
| the agent container itself | internal-only network; reachable endpoints: the gateway (Bearer token) and the egress proxy (allowlist = `model.proxyAllow`); `/plan` is its only mount |
| the gateway on an SELinux host | the gateway is the one container that drives the host's docker daemon, so on a daemon with SELinux enabled it runs with label confinement off (`--security-opt label=disable`) — a confined container cannot open that socket at all. Everything else in the run stays confined, and the run's own directories are relabelled so the tool containers can use them; the socket itself is never relabelled, which would hand daemon access to every container on the machine. |
| a tool **result** that looks like a secret | the pinned gateway refuses it before the harness sees it, and the agent gets `Error calling tool: … a secret is being returned by the …` instead of the value. This is docker/mcp-gateway's own `--block-secrets`, on by default in the pinned version rather than something the run asks for, so it guards every tool — including `run_command`. Worth knowing when writing a QuickAgent whose job is to *find* credentials: a `git log -p` that would print one is refused, and the work has to be done on patterns that are not themselves secret-shaped. |
| a **host-run** harness instead (`--adapter claude`) | no agent container: the gateway's catalog is still the whole tool surface, and the proxy variables are still the route to the model, but they are configuration the harness is asked to honour rather than a network it cannot leave. The receipt says so in `capabilities_enforced["harness.isolation"]`, and `receipts/proxy.log` shows every CONNECT it actually made. Beside it, `capabilities_enforced["harness.env"]` names the variables of your own environment the harness is given unchanged, where they are set: the ones its adapter asks for (`HOME` and `PATH` for `claude` and `codex`), and on Windows also `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`, `PATHEXT`, `ComSpec` and `SystemRoot`. Everything else it has is set by the plan and the run. |

Every claim above appears, mechanism named, in the run's
`capabilities_enforced` — the receipts stay honest about what is enforced
versus declared.

Teardown deletes the run's `secrets.env` and its copies of any knowledge
packs, even with `--keep-run-dir`. On Windows it retries a failed delete for
a few seconds, since Docker Desktop can hold a file briefly after its
container is removed. The `teardown` line appears only when one of those
files still stands after the whole teardown. The file is named in a warning
on stderr and in `capabilities_enforced.teardown`, the envelope's `status`
becomes `error` with the same message in `error`, `result.json` is written
again when the run has an output folder, and the run exits 1 even when the
QuickAgent itself succeeded. The named files may hold secret values or a
pack's pages in the clear: delete them by hand.

When a QuickAgent declares `exec: {commands: […]}`, its tools server runs in a
per-QuickAgent **exec image**: the runner image with the packages the
operator's exec catalog maps those commands to installed, then every
executable deleted except the declared commands (and the runner binary that
serves the tools), built once at install time from a generated Dockerfile
(`agentry-runner-exec:<version>-<hash>`; the hash covers the commands, the
packages and the mirror, so a changed catalog entry is a new image).
`run_command` is still gated by the argv0 allowlist and shim `PATH`; the
image contains nothing else to run.

The catalog is the operator's, not the manifest's — the same stance as
`mcpRegistries`. Policy `exec.packages` maps a command name to the apk
package that provides it on this machine, optionally pinned (`git: git`,
`openssl: openssl=3.5.1-r0`; a busybox applet the runner image already has,
such as `sort`, is catalogued as `busybox`). A manifest that declares a
command the catalog does not carry is refused when the plan is compiled
(exit 11, naming the command and the key), not reported absent at run time;
`agentry doctor --local <dir>` says so first. The build records the versions
apk resolved, and the run's receipt names them beside each command's package
(`capabilities_enforced.exec`, "packages resolved at image build: …"). The
default policy ships no entries: an operator opts in per tool, and an
example's README says which entry it needs. Because git refuses a
repository owned by another user as "dubious ownership", and a run's
workspace and inputs are bind mounts owned by you read by root inside the
container, an image that carries `git` sets `safe.directory` for the run's
workspace and inputs mounts — exactly those paths, and the receipt says so.

## Harness adapters

`--adapter` chooses which agent harness runs the QuickAgent. Every adapter
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
reaches a QuickAgent run, and `CLAUDE_CONFIG_DIR` points inside the run, so
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
  reports/…              whatever the QuickAgent wrote via write_report
  receipts/
    events.ndjson        the raw harness event stream
    agent-stderr.log     the harness process's stderr
    gateway.log          the gateway's own log, tool calls included
    proxy.log            the LLM egress proxy's decisions: one allow/deny line per CONNECT
    run-plan.json        the exact compiled plan that ran
    meta.json, task.txt  run identity, timing, budgets, the task input
    intake.json          the non-secret intake answers (when the release asks any)
    transcript.md        the conversation, for an interactive session
```

Every file under `receipts/`, the result text and the envelope's error
have the run's secret values masked to `[redacted]` before they are
written: the gateway token, every resolved secret (the agent's and the
declared servers'), the model API key. A value shorter than eight
characters is not masked — it is a switch, not a credential. The masking
matches values as they were resolved; an encoded copy (base64, URL-escaped)
is not recognised.

Exit codes: `0` ok · `1` other CLI error · `2` usage · `10` verify failed ·
`11` refused by policy / missing secret · `12` not compilable/runnable ·
`13` gateway or docker environment · `14` the QuickAgent failed ·
`15` timeout · `16` budget · `17` output schema.

## The desktop app

The [desktop app](https://github.com/blaktron/agentry-desktop) mirrors
the registry (browse, report cards, the MCP servers & tools section) and
drives the same runner packages as the CLI: one-click setup with the
provider table (including a prerequisites installer for the docker engine
on Linux), guided profile configuration and intake questions as forms,
and in-app runs with task input, file/folder pickers for `/inputs` and the
output folder, a keep-profile toggle, a live log stream, and the result
envelope. An interactive release opens as a chat in the same run panel,
over the same session API the CLI uses. It signs in through the browser —
the registry's directory service handles the login, one explicit approval
page hands the app a one-time code on a loopback listener, and the app
exchanges the code for a scoped token from its own process (the token
never appears in the browser); a sign-in that stalls can be cancelled
from Settings. Its Build tab authors and submits QuickAgents through the
same pipeline as `agentry publish`, with a structured editor for
`capabilities.mcpServers`. Its Describe it drafts one with the built-in
Drafter, on this computer (the same packages `agentry draft` drives, with
your own Jev key) or In Agentry (a hosted draft), and reads the draft into
its form as data; nothing is written into a QuickAgent folder until you save.

## Verifying a runner installation

`make accept-runner` in the `agentry-cli` repo: plan-matrix and
determinism checks (no docker), a live MCP-stdio exercise of the tools
server, and — on a machine with a docker engine and the model key named by
the operator policy's `apiKeyEnv` in the environment (`ANTHROPIC_API_KEY`
when there is no policy yet) — the full end-to-end run with teardown leak
checks (`scripts/acceptance/runner-r2.sh`). Each script points
`AGENTRY_CONFIG_DIR` (r0 and r2 the runner home as well) at its own
throwaway directory, so the consent records `agentry run` writes never
reach your `~/.config/agentry/installed.yaml`.

Test the runner's Windows behaviour natively, on Windows with Docker
Desktop, where you can. Where you can't, run the tests as Windows binaries
under Wine in `agentry-cli`'s `scripts/windows-tests` box: a throwaway
container with no network, no capabilities and read-only mounts. From the
module root, build it once (`docker build -t agentry-winebox:local
scripts/windows-tests`), then run `scripts/windows-tests/run.sh ./pkg/...`.
Never run those binaries under Wine on your own machine: Wine's `Z:` drive
is your whole filesystem and its deletes follow directory links, so a test
that cleans up after itself can delete real files. A pass under Wine is
evidence, not proof. Wine does not reproduce every Windows rule about open
handles: a rename that Windows refuses because a handle is still open can
pass under Wine.

## Knowledge packs

A knowledge pack is an LLM wiki of at most 10 MB: cited pages with an
index, together with the documents they were compiled from. It is one
directory holding `manifest.json` (name, id, dates, the page and byte
counts, the tree's digest, the scan record), `wiki/` (`index.md`, generated;
`log.md`, append-only; the pages) and `sources/` (the documents as given,
and each one's decoded text as `<name>.txt`). The digest is the SHA-256 of
a canonical tar of `wiki/` and `sources/`, the form the registry's store
checks too ([Knowledge packs in the registry](knowledge.md)).

**Making one.** `agentry knowledge create NAME --file PATH…` makes a pack
and keeps it sealed in the local store (below), and `agentry knowledge add
NAME --file PATH…` extends a kept one. `create --dir DIR` makes a plain pack
directory instead, in the clear, and `add DIR` extends one. The built-in Knowledge Creator does the work. It is a package
this binary embeds and runs with the attestation state `builtin`, never a
release anyone installs. The runner first decodes the documents in an
image that holds only `pdftotext`, `pandoc` and `tesseract`, with no
network and every capability dropped. Markdown, text, HTML, CSV, JSON,
YAML and source files pass as they are. Then the Creator compiles their
text into pages against the model your policy names, and the build applies
what it wrote. A local build costs no credits and is not scanned; the pack
records `not scanned`. `--timeout`, `--max-turns` and `--max-cost` bound
the run, and an `add` with the same documents continues a build that
stopped.

**Keeping packs: the local store.** Packs are kept under the runner home,
in `~/.agentry/runner/knowledge/<pack id>/`, which Agentry Desktop shares.
Each is a `manifest.json` in the clear, the tree as one sealed file
(`pack.sealed`: AES-256-GCM frames under a random data key per pack, the
format of the core's `pkg/packseal`), and `key.json`, that data key as it is
wrapped:

- **Signed in**, the registry wraps the key for your account
  (`POST /api/v1/knowledge/keys/wrap`). The pack then opens on any computer
  you sign in on, and the unwrapped key is cached in the OS keychain so it
  opens offline afterwards. What holds the wrapping key is the registry's:
  on a core registry its deployment key, on SecureAgentry your account's
  key, which Agentry holds.
- **Signed out**, this computer's key in the keychain wraps it. That is not
  portable, and the next signed-in command rewraps it to your account.
  With `AGENTRY_NO_KEYRING` and no sign-in, nothing can be kept sealed.

| Command | What it does |
|---|---|
| `knowledge list` | the packs kept here: pages, size, scan record, what their key is wrapped to |
| `knowledge list --org ORG` | the packs organization ORG shares in the registry, and whether its members may export each |
| `knowledge import DIR` | keep a pack directory sealed here (DIR is left as it is) |
| `knowledge upload NAME` | send it to the registry, sealed, where it is scanned and counted against your allocation |
| `knowledge download NAME` | keep the registry's copy here, checked in full |
| `knowledge download --org ORG NAME` | keep ORG's shared pack here; its key stays the organization's, asked for at every open and never cached, so it opens only while you are a member and signed in |
| `knowledge export NAME --to DIR` | write it out unencrypted into a new or empty DIR, after a typed `yes` (`--yes` for scripts); a shared pack is exported through the registry, which allows it to the organization's admins, and to its members once an admin marks it exportable |
| `knowledge delete NAME` | delete it and its cached key; `--remote` also deletes the registry's copy; the only copy goes after a typed `yes` |

A kept `create` or `add` opens the pack into a 0700 directory inside the
store, and removes it with the Creator run's output unless `--out DIR`
keeps that output. The registry's side of all this (the routes, the
wrapper, the scan, an organization's shared packs) is
[Knowledge packs in the registry](knowledge.md).

**Attaching one.** `run … --knowledge NAME` (or `DIR`) loads and verifies each pack
(the manifest, the layout, the 10 MB cap, the digest) before anything is
resolved. It mounts one read-only `/knowledge` volume, and the tools server
grants `knowledge_list`, `knowledge_search` and `knowledge_read` for that
run only. Attaching a pack changes neither the compiled plan nor its hash.
The receipt's `capabilities_enforced.knowledge` names each pack by digest
and says whether a registry scanned it. A bare `NAME` is looked up in the
store first, and a directory of that name in the working directory is
taken only when the store keeps no such pack. A kept pack is opened into a
0700 directory inside the store for the run to copy, and removed at
teardown; the run's copy goes at teardown too, even with `--keep-run-dir`.
A pack that is not kept, or will not open (signed out of the registry that
wraps its key, another account's, altered), is refused before the run
with exit 11, naming the pack.

**A pack the release ships.** A release can carry packs of its own under
`knowledge/<name>/`, named in its manifest's `knowledge.ships`
([quickagents.md](quickagents.md#knowledge-packs-the-release-ships)).
A run mounts each one read-only at `/knowledge/<name>`, beside any pack
attached with `--knowledge`, through the same run-time grant. The plan
names no pack.

- The pack is loaded from the installed release's own files, once the
  manifest validates. It is staged from the run's copy of the release,
  after that copy is checked against the install record. So what is
  mounted is what the archive digest and the attestation cover, and it is
  never fetched again.
- A shipped pack that does not load, or a file of it changed after the
  install, is exit 10 before any container starts.
- A pack attached with `--knowledge` cannot take a shipped pack's name
  (exit 1).
- The receipt names a shipped pack as the release's, with no scan field
  of its own: the attestation line says what covers the archive.

  ```
  <name> shipped with the release (archive sha256:…) mounted read-only at /knowledge/<name> (sha256:…, N pages, M bytes)
  ```

  For `--local` it names the `local package tree` digest instead.
- The consent lists `knowledge: ships <name> (<size>)` with the other
  capabilities, and `installed.yaml` records the names under
  `capabilities.knowledge`, so an update that ships one more pack asks
  again.
- `agentry publish` refuses, before uploading, a release whose
  `publish.include` leaves a shipped pack out. It also refuses an upload
  past 16 MiB compressed, the most the registry's upload takes; publish a
  larger release from its tag.

## Machine-readable output

A client that drives the CLI — the desktop app, the `agentry-mcp` server
([from your own agent](agentry/mcp.md): Claude Code, Codex or any MCP host
driving this CLI through its plan modes), a script — reads JSON, never
prose. With the root `--json` flag a command
prints one JSON document on stdout and keeps its narration on stderr; `run`
takes `--output-format json` instead, because its stdout is the result. Each
shape is a Go struct in `cmd/agentry` with a doc comment, and a test decodes
it. Values that name a secret never appear: `setup` and `doctor` print the
key variable's **name** only.

| Command | Shape (top-level fields) |
|---|---|
| `search --json` | `results[]` (`namespace`, `name`, `modes`, `summary`, `installs30d`, `quarantineState`), `facets`, `total` |
| `info ns/name --json` | `agent`, `latest` (the resolved release: `manifest` — the capabilities live under it — `digest`, `attestationUrl`, `yanked`, …), or `latestError` when the resolve itself failed |
| `verify ns/name@v --json` | `ref`, `version`, `registryDigest`, `computedDigest`, `digestMatch`, `yanked`, `attestation` (`state`, `detail`, `keyId`) |
| `doctor --json` | `ref`, `checks[]` (`name`, `status` ok\|warn\|fail, `detail`); the report prints and the exit is 1 when a check fails |
| `install ns/name --plan --json` | `ref`, `namespace`, `name`, `version`, `digest`, `modes`, `summary`, `yanked`, `contract` (the capabilities as canonical JSON), `contractDigest` (sha256 of exactly those bytes — the document is compact so they arrive unchanged), `attestation` verified\|unsigned\|unscanned\|mismatch\|unverifiable, `keyId`, `signed`, `installed` (`version`, `dir`, when a record exists), `diff` (`widened[]`, `narrowed[]`), `needsConfirmation`, `reason`, `target` runner\|claude-skill\|agents-md, `dir`, `managed`, `refusal` (what an install would stop on: an attestation verdict, unsigned without `--allow-unsigned`, or unscanned without `--allow-unscanned`). Nothing is written; the exit is 0 whether or not an install would be refused |
| `install ns/name --json` | `ref`, `namespace`, `name`, `version`, `digest`, `target`, `dir`, `managed`, `attestation`, `signed`, `contract`, `contractDigest`, `recorded` |
| `uninstall ns/name [--plan] --json` | `ref`, `plan`, `installs[]`, `profiles[]`, `keptProfiles[]` (under `--keep-mcp`), `consentRecord` — with `--plan`, what would be removed and nothing removed |
| `list [--check] --json` | `path` (the state file), `records[]` (each `installed.yaml` record plus `present`: its directory exists; with `--check`, `latest`, `updateAvailable` and `checkError` per record) |
| `validate DIR --json` | `passed`, `manifest`, `issues[]` (`rule`, `severity`, `path`, `message`), `inventory[]`, `findings[]` (`ruleId`, `scanner`, `severity`, `confidence`, `title`, `filePath`, `lineStart`, `lineEnd`, `excerpt`, `detail`), `readErrors[]`, `fileCount`, `bundle`, `counts`, `strict`; the report prints and the exit is 1 when it failed |
| `setup --json` | `policyPath`, `provider`, `model`, `apiKeyEnv` (a name), `baseUrl`, `images` ready\|skipped |
| `run ns/name --plan --json` (or `--local DIR`) | the consent-free preview a client shows before a person consents: `ref`, `version`, `digest`, `mode`, `modes`, `plan` (the compiled plan, canonical — what a run would enforce), `planSha256` (the receipt's `runPlanSha256`, over the plan's canonical indented form — match it, do not re-derive it from the compact `plan` bytes), `contract`, `contractDigest`, `attestation` verified\|unsigned\|local\|mismatch\|unverifiable, `keyId`, `signed`, `installed`, `diff`, `needsConfirmation`, `reason`, `refusals[]` (every refusal the attestation and vulnerable-server gates would meet, in the order a run meets them: `kind` attestation\|vulnerable_server, `message`, `lift` — the flag that lifts it, `--allow-unsigned`, `--allow-unscanned` or `--allow-vulnerable-mcp`, absent when none does), `refusal` (deprecated: the first refusal's message). Asks nothing, records nothing, materializes into a temp home; exit 0 whether or not a run would be refused (`--dry-run` is the plan for a person who consented on the terminal) |
| `run … --output-format json` | the result envelope: `agentry` (`run/v1`), `status`, `exitCode` and `exitClass`, `error`, `runId`, `ref`, `digest`, `attestation`, `capabilities_enforced`, `harness`, `usage`, `result`, `outDir`, `resultFile`, `receipts` (`dir`, `runPlanSha256`), and `policy` (`path` of the operator policy file the run enforced, absolute; `source` default\|flag\|env — the runner home's file, `--policy`, or a home relocated by `AGENTRY_RUNNER_HOME`; `sha256`, the plan's `policySha256` — the digest of that file) |
| `draft … --json` | the draft itself, `draft.json`: `manifest` (the v2 manifest as JSON), `instructions`, `notes`, `matches[]` (`ref`, `why`), `sources[]` (`url`, `used`, `withheld`), `openQuestions[]`, `drafter` (`ref`, `build`, `model`, `runId`), `aiReview` (the description's verdict, the receipt's web counts as its own fields — `scan`, `pages`, `read`, `passed`, `withheld`, … — `withheldSources[]` with `tool`, `url` and `reason`, and `check`, AI Review's check of the finished draft: `rubric` (`verdict` pass, flagged or not_scanned, `scores`, `findings[]` with `id`, `score` and `path`, `rubricHash`, `failure`), `draft` (`verdict`, `score`, `scores`, `flagged[]`, `questionSet`, `failure`), `model`, `requests`, `inputTokens`, `checks` (how many checks were asked, at most 2), or `unanswered`, the reason it has no answer, with no verdicts), `validation` (the `validate --json` report on the rendered package), `manifestError` |
| `draft … --output-format json` | the Drafter run's result envelope, as `run … --output-format json` writes one (its `usage`, the attestation `builtin`, the `web` counts), with an empty `result` and the draft's report under `draft`: `file` (where `draft.json` is), `rendered`, `passed`, `manifestError` (a flag), `matches`, `openQuestions` and `withheld` (counts), `corrections` (how many slips were corrected), `repaired` (whether the one repair turn ran) and `check` (AI Review's check as one word: `pass`, `flagged`, `not_scanned`, or `unanswered`; absent for a draft that could not be rendered). The envelope's usage is both turns' together. A draft that stops before the Drafter runs still writes one envelope with its class and stage |
| `knowledge create NAME --json` / `knowledge add DIR --json` | `dir`, `manifest` (the pack's `manifest.json`: `schema`, `name`, `id`, `created`, `updated`, `creator`, `pages`, `bytes`, `sha256`, and `scan`, the string `not scanned` or a registry's record), `documents[]` (what the run was given), `skipped[]` (documents not ingested), `written[]` (the paths the build applied), `dropped[]` (`path`, `reason`, `kept`), `receipts` (the Creator run's receipt directory), `decode` (the decode step's report, when documents were decoded), `stopped` (the budget or error that stopped the run early, when one did) |
| `--version` | `agentry version <v>` — a release version, or a git describe on a source build |

One example, `install --plan --json` on a first install of a QuickAgent
that declares egress, against a registry that publishes no attestation:

```json
{"ref":"acme/demo@1.0.0","namespace":"acme","name":"demo","version":"1.0.0","digest":"sha256:…","modes":["autonomous"],"contract":{"filesystem":{"read":"workspace"},"network":{"egress":["api.example.com"]}},"contractDigest":"sha256:…","attestation":"unsigned","signed":false,"diff":{},"needsConfirmation":true,"reason":"a first install of a QuickAgent that declares network egress or exec","target":"claude-skill","dir":"/home/me/.claude/skills/demo","managed":true,"refusal":"unsigned — registry offers no attestation for acme/demo@1.0.0 (…); re-run with --allow-unsigned to install it anyway"}
```

`--plan` adds no way past a gate: it reports what `--yes` and
`--allow-unsigned` would be needed for, and a client that shows the contract
and confirms against `contractDigest` is confirming exactly what it showed.
Two facts a client should know: a plan against a registry whose signing keys
are not yet pinned pins them on first use, as `verify` does — the one thing
`--plan` writes; and a command that fails before its result exists (a digest
mismatch, a refused attestation, a failed download) exits non-zero with the
reason on stderr and no JSON on stdout — the exit class is the answer then.

**Exit classes.** Every command exits with one of the §R8 classes, which
`run`'s envelope names in `exitClass`: `0` ok, `1` cli, `2` usage, `10`
verify, `11` policy, `12` compile, `13` gateway, `14` harness, `15` timeout,
`16` budget, `17` outputSchema. An interrupted run (SIGINT, SIGTERM) tears
down and writes its envelope with `error: interrupted` under `cli`, receipts
kept; the unsigned gate asks for `--allow-unsigned` on every run of an
unsigned or local release, a cached install included.

## The other commands

The rest of the CLI, one line each; the [package format](quickagents.md)
page covers authoring and publishing in depth.

| Command | What it does |
|---|---|
| `agentry login [--browser \| --paste]` | signs in to a registry: the browser flow hands the CLI a one-time code on a loopback listener and the CLI exchanges it for a scoped token from its own process; `--paste` reads a token from stdin for machines without a browser. Signing in also pins the registry's signing keys (TOFU) |
| `agentry init [--from PATH]` | scaffolds a workspace, or imports a `SKILL.md` or an MCP registry `server.json` |
| `agentry validate DIR` | the registry's manifest rules and offline scanners (V1–V11, S1/S3/S4) |
| `agentry list` | every install record in `installed.yaml` — the embedded installs and the runner consents — with whether each directory is still present (`--json`) |
| `agentry info ns/name` / `agentry search` | a QuickAgent's page and capability contract; full-text search with the mode, capability, license and verified-org facets (`--json` on both) |
| `agentry verify ns/name@version` | digest and DSSE attestation check against the pinned keys — an exit code for CI |
| `agentry publish` | submits a workspace and follows the pipeline's event stream to the verdict |
| `agentry yank ns/name@version` | yanks a published version |
| `agentry install` / `uninstall` / `profiles` / `doctor` / `setup` | above |

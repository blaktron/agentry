# QuickAgents

*This page covers the package format. The complete runtime side — every
command, flag, policy key, MCP profiles, and enforcement mechanism — is
the [Runner reference](runner.md).*

A **QuickAgent** is a single-purpose AI agent packaged for Agentry:
one manifest declaring what it is and what it may touch, the instruction
itself, and any support files the manifest lists. QuickAgents carry **no
tool code**. At run
time the Agentry runner serves exactly the tools the manifest declares
through an isolated MCP gateway, and when a QuickAgent is installed into an
existing coding agent, the host's built-in tools stand in under the same
declared contract.

Start from the **[QuickAgent template](https://github.com/blaktron/agentry-template)**
(`github.com/blaktron/agentry-template`), a runnable package with every
option below shown in a commented `agent.yaml`. Or scaffold one with
`agentry init`, have the built-in Drafter write one with `agentry draft
"<what it should do>"` ([the runner reference](runner.md#agentry-draft-description)),
or use the [Builder](agentry/builder.md) on the site or in the desktop app.

`agentry init --from PATH` imports an existing source instead of
scaffolding. From an Agent Skills `SKILL.md` it maps the frontmatter name,
description, license and `metadata.version`, copies the sibling files and
lists them in `publish.include`. From an MCP registry `server.json` it
writes a QuickAgent that declares the published package under
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
echo "task" | agentry run --local . --allow-unsigned --out ./agentry-out --file notes.pdf
agentry review .                                     # the built-in Examiner, before you submit
agentry publish                                      # scanned, signed, immutable
```

A first `agentry publish` needs the QuickAgent's record, which the CLI does
not create: make it at `/new` on the site first ([Publishing](#publishing)).

## Machine setup (`agentry setup`)

One idempotent command prepares a machine for QuickAgent runs before any
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
| `openrouter`, `poe`, `huggingface` | none: you type the model id | `OPENROUTER_API_KEY`, `POE_API_KEY`, `HF_TOKEN` | openrouter.ai, api.poe.com, router.huggingface.co :443 |
| `copilot` | asked | none: your Copilot plan, signed in with GitHub | the Copilot API host of your plan |
| `custom` | asked | asked | derived from `--base-url` |

Instead of a key, a local run can be paid by your own ChatGPT, Claude or
Copilot plan, or by an account you connect at OpenRouter, Poe or Hugging
Face, signed in through your browser. These are
[model sign-ins](runner.md#model-sign-ins); setup asks which way to pay
where there is a choice.

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

The first run of a QuickAgent that declares secrets starts a **guided
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
my-quickagent/
├── agent.yaml                  # the manifest (required)
├── AGENT.md                    # the instruction file (entrypoints.instruction)
├── README.md                   # rendered on the registry page; required for public publication
├── LICENSE                     # required for public publication
├── output.schema.json          # optional: structured-output contract
└── knowledge/<name>/           # optional: a knowledge pack the release ships
```

Support files (scripts, templates, examples) ship too when
`publish.include` lists them; the archive holds nothing else.

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

A QuickAgent is an instruction package. What varies is how it runs, and a
release declares the set of run modes it supports:

| Mode | What a run is | Status |
|---|---|---|
| `autonomous` | starts from its files — after the up-front questions, if any, and MCP profile authentication — does the job, writes its output and receipts, and ends | this is `agentry run` today |
| `interactive` | starts from the same plan and controls, but the run is a conversation: in the CLI a chat in the terminal (`agentry run --mode interactive`), in the desktop the run panel's chat. The agent can ask for information as the work reveals the need; you can answer and drop files into the read-only inputs folder (`/add PATH`), then `/finish` for the final result. You **cannot** give it more access than the manifest declares — the capability contract, the gateway and the egress allowlist are exactly those of an autonomous run of the same release, and a permission request from inside the sandbox is granted only for a tool the plan already serves, refused otherwise | `agentry run --mode interactive`; a release with one mode runs in it, one with both is asked on a terminal and runs autonomous otherwise |

The instruction is one file:

| Field | Meaning |
|---|---|
| `entrypoints.instruction` | the repo-relative instruction file, `AGENT.md` when omitted. A leading YAML frontmatter block (the Agent Skills `SKILL.md` shape) is stripped; the body becomes the harness instruction, so a `SKILL.md` works unchanged as `entrypoints.instruction: SKILL.md`. The file must exist and be matched by `publish.include` |

There are no other package kinds. An MCP server is something a QuickAgent
*uses* — declared under `capabilities.mcpServers` and installed with the
release — not a package of its own.

### `intake`: questions asked before a run

Both modes may ask a few things up front. The runner asks them through
the same prompter that collects MCP profile secrets (a terminal prompt in
the CLI, a form in the desktop) and stages the answers read-only for the
agent at `/inputs/intake.json`.

```yaml
intake:
  - id: dataset            # [a-z0-9_]+, unique
    prompt: "Path to the dataset to analyse"
    type: file             # text (default) | secret | choice | file | host | repository | url
    required: true
  - id: region
    prompt: "Which region?"
    type: choice
    choices: [emea, apac, amer]
```

| Rule | |
|---|---|
| `id` | `[a-z0-9_]{1,64}`, unique within the manifest |
| `prompt` | required; one plain line, with no control character (an escape, a carriage return, a newline) and no format character (a bidi override, a zero-width space), since the CLI prints it on the terminal before the run and the desktop shows it as written (V10) |
| `type` | `text`, `secret` (injected as a run-scoped secret, never written as text or recorded; the upper-cased id must be listed under `capabilities.secrets`, or the run refuses it; and `required` must agree with that secret: `true` for a required secret, absent or `false` for one under `capabilities.optionalSecrets`, or publishing refuses it, V10), `choice` (needs `choices`), `file` (a host path the runner stages into the inputs folder), `host` (a target host, below), `repository` and `url` (an input source, below) |
| `choices` | only with `type: choice`; each one plain line, as `prompt` |
| at most 20 questions | |

Non-secret answers are part of the run's receipts.

#### Input sources: `repository` and `url`

An **input source** is where a run's inputs come from. Every run has one,
the files a person uploads. Two more kinds are asked for by an intake
question whose `type` names the kind:

```yaml
intake:
  - id: repo
    prompt: "The repository to audit"
    type: repository       # an https git URL and an optional ref
    required: true
  - id: advisory
    prompt: "The advisory to check it against"
    type: url              # one https URL
```

| Type | The answer | What the agent is to get |
|---|---|---|
| `repository` | an https git URL and an optional ref (a branch, a tag or a commit) | the repository's files at that ref under `/inputs/<id>/` |
| `url` | one https URL | the file at that address under `/inputs/<id>/` |

**Which runners fetch them.** The CLI fetches a `repository` answer from
v0.6.97 and a `url` answer from v0.6.98;
[the runner reference](runner.md#input-sources-a-repository-or-a-file-at-a-web-address)
describes the clone, the download, their caps and the token's path. A run
in Agentry fetches them too, on its sandbox host. A CLI or desktop older
than the core release that added the two types refuses a manifest
carrying either as an unknown intake type.

- **The id names the folder.** A runner that supports sources fetches the
  answer before the run starts into `/inputs/<id>/`, where the input tools
  read it as they read an upload. V10's id rules (the pattern, which allows
  no `.` or `/`, and uniqueness) therefore give each source a folder of its
  own.
- **The token belongs to the run.** The run setup asks for an optional
  access token beside the answer, for a private repository or file. A
  release never declares it, and it is used by the fetch step alone.
- **A source grants nothing.** Giving the source is the grant, as
  attaching a file is. A source question needs no `capabilities` entry:
  no egress to the source's host and no secret for its token. Adding or
  removing one leaves the capability diff unchanged, so a new version that
  adds one asks for no new consent; the person running it chooses the
  source. The agent's own `fetch` stays inside the contract as before.
- **A `repository` question expects code.** When `inputs.kinds` is
  declared and takes neither `code` nor `any`, validation warns, without
  failing, that the release does not say it takes code (V13).
- `choices` are refused on a source question, as on every type but
  `choice` (V10).

#### Target hosts: `host`

A **target host** is a machine the person names when a run starts, such as
a Linux server for the QuickAgent to set up or manage. The release says
that it takes one, never which one, so one QuickAgent serves every server
its users have. It is declared in two places that name each other: an
intake question of type `host`, and its id under
[`capabilities.targetHosts`](#capabilities-the-security-contract).

```yaml
intake:
  - id: server
    prompt: "The server to set up"
    type: host             # the person answers [user@]host[:port]
    required: true
capabilities:
  targetHosts: [server]
```

- **The answer belongs to the run.** The person writes `[user@]host[:port]`
  (an IPv6 address in brackets) when the run starts, and gives its
  credential then. The user defaults to theirs and the port to 22. The
  manifest never carries an address, a user, a port or a credential.
- **The runner makes the connection, not the agent.** A runner that
  supports target hosts opens the SSH session from a container of its own,
  and the agent works the machine through the runner's host tools, a
  command at a time or in a shell. Target hosts are for local runs: a
  hosted run refuses a release that declares one.
- **A target host is part of the contract.** Unlike a source, it lets the
  agent act on the machine: run any command the account can run there. So
  the install consent shows it, a new version that adds one asks for
  consent again, the registry's AI Review reads it as a declared
  capability, and `GET /search?capability=targetHosts` finds such releases.
  It is not network egress. A support script the release ships that runs
  `ssh` itself is still the release reaching a host on its own, and the
  scan reports it as such (stage S6).
- **The rules (V14).** Every `host` question is listed in
  `capabilities.targetHosts`, and every entry there names a `host`
  question, once. A release declares at most four. `choices` are refused
  on a `host` question, as on every type but `choice` (V10). An `exec`
  declaration that names `ssh`, `scp`, `sftp` or `rsync` is warned, without
  failing, toward `targetHosts`, and the scan reports it low (S1).

**Which runners reach them.** The CLI reaches a target host from v0.6.105:
the host link and its tools (`host_run`, `host_read`, `host_write`,
`host_put`, `host_get`) are in
[the runner reference](runner.md#target-hosts-a-server-named-at-run-time),
and from v0.6.106 so is an interactive shell on the host
(`host_shell_open`, `host_shell_send`, `host_shell_read`,
`host_shell_close`). A run in Agentry refuses a target host. A CLI or desktop older than the core release that
added the type refuses a manifest carrying it as an unknown intake type.

#### The browser's site: a `url` question named in `capabilities.browser`

A QuickAgent that tests websites declares a **browser**: a headless
Chromium the runner gives the run, driven through the runner's browser
tools. The site to test is named by the person when the run starts, as the
answer to a `url` question listed under
[`capabilities.browser.sites`](#capabilities-the-security-contract):

```yaml
intake:
  - id: site
    prompt: "Which site should I test?"
    type: url
    required: true
capabilities:
  browser:
    sites: [site]                       # url questions: the person's answer is the site
    hosts: [fonts.googleapis.com, "*.stripe.com"]   # fixed hosts its pages need
    scope: site                         # the default; or public
    secrets: [SITE_USER, SITE_PASSWORD] # declared secrets it may type into the site's forms
  secrets: [SITE_USER, SITE_PASSWORD]
```

- **Where the browser may go.** In `site` scope, the default, the site the
  person names, its subdomains, and the `hosts` the release lists, each an
  exact name or a `*.` suffix. In `public` scope, any public site. The
  runner holds the scope in a proxy of its own, the browser's only route
  out; private addresses are refused, except in a local run the site the
  person typed, which may be on a LAN or a Tailscale network.
- **Signing in.** `secrets` names declared secrets the browser may type:
  the agent passes a secret's name and the runner's browser server types
  its value, which the agent never reads back. A browser that types
  secrets cannot have `public` scope, so the contract admits a secret only
  on the person's site, its subdomains and the declared hosts. The secrets are stored and asked
  for as any declared secret is.
- **The browser is part of the contract.** The install consent shows the
  line, a new version that adds a browser, a site, a host or a secret, or
  moves from `site` to `public`, asks for consent again, the registry's AI
  Review sees it among the declared capabilities, and
  `GET /search?capability=browser` finds such releases. It is not network
  egress: the tools container's `fetch` still follows `network.egress`, and
  a support script that reaches a host itself is still the release's own
  network (stage S6). `public` scope is held at publication as `"*"` egress
  is: under the platform's policy it goes to a reviewer.
- **The rules (V15).** `schemaVersion: 2`. `sites` names `url` questions,
  at most four, each once. `hosts` are DNS names of two labels or more, or `*.` suffixes of one, at
  most 32: no `"*"`, no address, no single-label name such as `localhost`, no
  port, and no suffix that is itself a public suffix (`*.co.uk`, `*.github.io`),
  which would admit every site registered under it.
  `scope` is `site` or `public`. The line names at least one site or host,
  or `public`. Each name in `secrets` is also in `capabilities.secrets` or
  `optionalSecrets`, and `secrets` with `public` is refused.

**What a runner does with it.** The core accepts the line and checks it as
above. From agentry-cli v0.6.117 a local run gives the release its browser: Microsoft's Playwright MCP server on the
pinned `agentry-browser` image, whose one route out is a browse proxy of the
run's own, the site answer opened and never downloaded, the browser secrets
typed by name, and the screenshots and PDFs in `reports/browser/`
([the runner reference](runner.md#the-browser-a-site-to-test-named-at-run-time)).
From agentry-cli v0.6.118 and the enterprise build's v0.6.57 a run in
Agentry gets one too, its sites public addresses on ports 80 and 443 only
([hosted runs](hosted-runs.md#a-run-with-a-browser)). A CLI or desktop
older than this core release
refuses a manifest carrying the line as an unknown field. `public` scope
runs only on a machine whose runner policy sets `browser.allowPublicWeb`.

### `interactive`: session hints

```yaml
interactive:
  opening: "Which incident, and what do you need from it?"   # ≤ 500 characters
  idleTimeoutSeconds: 900                                    # policy caps it
```

`opening` is the assistant's first message when a session starts with no
task text. It may span lines and use tabs, and carries no other control
character and no format character, as the guide's overview does (V10).
Everything else about a session — budgets, idle timeout, wall
time — is the operator's runner policy, which a manifest can only
tighten. A release that does not list `interactive` may still declare
hints: validation warns, and they never apply.

### `guide`: what a person reads before a run

A few lines in the author's own words for the run setup, the steps a
person goes through on the site and in the desktop before a run starts
(Before you start, Files, Connect tools, Details). It is shown to people
only: it never reaches the agent, the run plan, the capability diff or
the consent, so changing it asks no one to consent again. Without a
`guide`, the clients derive the same steps from the summary, the intake
questions and the declared capabilities.

```yaml
guide:
  overview: |              # markdown, ≤ 4096 bytes
    Reads your contract and your playbook and returns a clause-by-clause
    review with the asks written out.
  prepare:                 # ≤ 10 plain lines of ≤ 200 characters
    - The contract, as text
    - Your negotiation playbook, if you have one
  files: "The contract, and optionally your playbook."   # ≤ 500 characters
  task: "e.g. 3-year SaaS subscription, 200 seats, EU data"   # the task field's placeholder, ≤ 200 characters
  connect:                 # help per declared secret, markdown, ≤ 2,000 characters each
    GITHUB_TOKEN: |
      A fine-grained token with **read** access to pull requests:
      GitHub → Settings → Developer settings → Fine-grained tokens.
```

| Rule | |
|---|---|
| `overview`, `connect` values | markdown a person reads, never the agent; clients render it with no HTML and no images; a `connect` value is at most 2,000 characters (counted as characters, not bytes) and may not be empty or blank |
| `prepare`, `files`, `task` | one plain line each: no control characters and no format characters (bidi overrides, zero-width characters); a `prepare` item may not be empty or blank |
| `overview` and `connect` characters | newlines and tabs, and no other control character (no ESC, CR, BEL, NUL, DEL or C1 control); no format character |
| `connect` keys | each must be a secret the release declares, under `capabilities.secrets` or a declared MCP server's `secrets` |
| schema | v2 only; a v1 manifest carrying `guide` is refused (V1) |

The guide is validated under V10 with the intake and the interactive
hints. A CLI or desktop older than the core release that added it
refuses a manifest carrying one as an unknown field, in the release's
archive and in the registry's answer about it, so use it once your
tools are current.

### `knowledge`: packs the release ships

A release may carry its own reference set: one or more
[knowledge packs](knowledge.md) made with the Knowledge Creator
(`agentry knowledge create`), each in the archive under
`knowledge/<name>/` exactly as the CLI keeps it: `manifest.json`, `wiki/`
with its `index.md` and `log.md`, and `sources/`. The runner mounts each
read-only at `/knowledge/<name>`, searched with the three knowledge tools
(CLI v0.6.11 or later). The block also says what a person
may attach of their own, which the run setup shows and the agent never
sees.

```yaml
knowledge:
  ships:                          # ≤ 5 packs, each in the archive under knowledge/<name>/
    - name: aws-docs
  accepts:                        # optional: what to attach, shown to the person only
    prompt: "Your own runbooks, if you have them"   # one plain line, ≤ 300 characters
    required: false               # true: the setup's Knowledge step cannot be skipped

publish:
  include: [agent.yaml, AGENT.md, knowledge/**]    # the packs must be in the archive
```

| Rule | |
|---|---|
| `ships[].name` | a pack name (1–64 lowercase letters, digits, `.`, `-` or `_`, starting with a letter or digit), once each; the pack's directory under `knowledge/` (V11) |
| the pack in the archive | matched by `publish.include`; `manifest.json`, `wiki/index.md` and `wiki/log.md` present; nothing but those, `wiki/` and `sources/` (V11) |
| the pack's `manifest.json` | schema `knowledge/v1`, names the pack, and its `sha256`, `bytes` and `pages` are the files beside it — the check the CLI's pack loader makes before it uses a pack, so edit a pack with `agentry knowledge add`, never by hand (V11) |
| the instruction file | not under `knowledge/`: it is the release's own, judged against its contract (V11) |
| size | at most 10 MB a pack, `manifest.json` included, and 2,000 files; a pack's files are outside the release's own quotas — the file count, the per-file sizes, the 1 MiB text total and the archive total — so the archive's cap is raised by what it ships (V8). An upload through the API (`agentry publish`) is at most 16 MiB compressed, the edge's request cap; a larger release is published by pushing its tag, which has no such cap |
| `knowledge/` | holds shipped packs only: a file there outside a pack `ships` names is refused (V11) |
| `accepts.prompt` | one plain line: no control or format characters, not blank |
| schema | v2 only; a v1 manifest carrying `knowledge` is refused (V1) |

**The contract.** The names a release ships are part of the capability
contract a person consents to: the version's `capabilities` carry them as
`knowledge`, and a release that ships a pack the installed one did not
asks for consent again ("ships knowledge: aws-docs"), as any widening
does. A pack's contents changing under the same name does not re-ask; the
scan reads every release's packs. What `accepts` asks for never widens
the contract: attaching a person's own pack is the grant, as handing over
inputs is.

**The scan.** The registry scans each shipped pack as part of the
version's scan, with the reading it gives a pack it stores
([knowledge.md](knowledge.md#the-scan)): the secrets, hidden-content,
signature and URL stages over every page and source, then AI Review over
the pack's `sources/` and then its `wiki/`, in chunks no larger than the
judge reads. Its findings are the release's (scanner `SK/…`, file paths
under `knowledge/<name>/`) and the gate decides on them as on any other; a
pack the scan could not read in full sends the version to review. The
release's own stages, its own AI Review included, read the release's own
files and not a pack's text; a pack's other files (an image, a source's
original) are read by the release's stages as anywhere in the archive,
and a text file in a pack that is not UTF-8 is a finding that sends the
version to review. The report's `knowledge` section names, for each pack,
the stages that read it, what they read, the judge and its model, and the
chunks of each half, or "AI Review not configured". The attestation
covers the archive digest, so a shipped pack is signed with the rest of
the release, and a client that verifies the release verifies the pack
with it.

A CLI or desktop older than the core release that added the block refuses
a manifest carrying one as an unknown field; use it once your tools are
current.

### `inputs`: what files it takes, and how it reads them

The files a person hands a run reach the agent through the input tools
(`list_inputs`, `read_input`, `search_inputs`), which offer every input in
two views: `text`, the text a decoder made of it (a PDF's or an office
document's text, an image's recognised text, HTML as Markdown), and
`original`, the file as uploaded (a binary file in base64 pages). Without
this block a QuickAgent takes any kind of file, and each file keeps its own
default view: the decoder's text where one made it, and anything else
(code, markup, HTML, configuration, data) as uploaded. That is how every release published
before the block reads, and it stays so. The block lets the author say
what to bring and which view the agent reads first:

```yaml
inputs:
  kinds: [code, data]   # documents | code | data | images, or any alone; absent: any
  view: original        # text | original | both; absent: both
```

| Kind | Means |
|---|---|
| `documents` | prose to read: PDFs, office documents, e-books, rich text |
| `code` | a codebase or its files: source, markup, build and configuration files, a repository (loose or as an archive) |
| `data` | structured data: CSV, JSON, YAML, spreadsheets, logs |
| `images` | photographs, scans, screenshots, diagrams |
| `any` | no particular kind; declared alone |

| View | The agent reads an input by default |
|---|---|
| `text` | as its decoded text, and as uploaded when it has none (a summariser of saved web pages wants their Markdown) |
| `original` | as uploaded (a reviewer of a site's pages wants the HTML with its scripts); a PDF, an office document or an image is then base64 pages, so pair `original` with `documents` or `images` only when the agent works on the bytes |
| `both` | each file's own default; the runner reads it exactly as leaving `view` out, and it tells the run setup and the Drafter that the agent uses both |

| Rule | |
|---|---|
| the block | at least one of `kinds` and `view`; no other key (V12) |
| `kinds` | from the list above, each once, at least one when present; `any` alone (V12) |
| `view` | `text`, `original` or `both` (V12) |
| schema | v2 only; a v1 manifest carrying `inputs` is refused (V1) |

The default is only a default: the agent can still ask for any view an
input has, so declaring `text` never hides an original. (Some inputs have
one view: a file decoded out of a document inside an archive has only its
text, and a file the malware check found, a refused file and `.git`
internals have neither.) The kinds are for
the run setup, which asks for them, and for the Drafter, which fills the
block when it writes a QuickAgent. Neither grants anything: attaching a
file is the grant, so the block is outside the capability contract, and a
release that changes only its inputs asks no one to consent again. Write
`guide.files` to match it.

The runner sets the default view from the block (CLI v0.6.73 or later):
`list_inputs` marks it, and the System Prompt names it. The Drafter fills
the block from Drafter 1.9.0. A hosted run takes the block; a CLI before
v0.6.73, or a desktop built on one, refuses a manifest carrying it as an
unknown field. The site's and the desktop's run setups show it.

### `runtime`: informational hints

| Field | Meaning |
|---|---|
| `runtime.models` | free-form model hint patterns (e.g. `["claude-*"]`). A hint, never a lock: the **operator's** runner policy chooses the model and owns the API key |
| `runtime.interfaces` | which coding-agent exports the package supports: `claude-skill`, `agents-md`. Independent of mode — an interactive agent still exports as a Claude skill; what it loses in that host is the Agentry session, not its instructions. It does not pick `agentry install`'s default, which is the runner home (below); the exports are asked for by name |

### `capabilities`: the security contract

Closed vocabulary. Omitted or empty means a **pure-text QuickAgent**
(its run-time tools are `write_report`, the read-only `list_inputs`,
`read_input` and `search_inputs`, its scratch folder's `scratch_list`,
`scratch_read`, `scratch_write` and `scratch_search`, `export_pdf`, and
`grep` and `glob` over its inputs, its scratch folder and any attached
knowledge, nothing else; the last seven are the runner's grants to every
release but a built-in, not
lines of the contract). The registry scans releases
against these declarations, an install prompts on them (egress/exec need
typed consent; a widened contract re-asks on upgrade), and the runner
turns each line into a concrete control. The same contract covers support
scripts. The scan reads every shell, Python or JavaScript file in the
package, and reports as high a script under `exec: none`, a network call
to a host outside `network.egress`, a file write under
`filesystem.write: none`, an undeclared subprocess or `eval`, and any
`curl … | sh` remote execution; an environment variable read outside
`secrets` is high as well. It matches text without running anything,
and a host only counts inside a network call, so a documentation URL in a
comment is not a finding (see [trust](trust.md), stage S6).

**`network.egress`**

| Value | Meaning | Run-time enforcement |
|---|---|---|
| `none` / omitted | no outbound network | tools container runs with networking disabled; no `fetch` tool |
| `[exact.dns.host, …]` | outbound only to these hosts | `fetch` granted, restricted to the listed hostnames (checked per request and per redirect hop); the gateway pins the tools container to `host:443` with per-server proxies and DNS interception |
| `"*"` | unrestricted egress | refused at run time unless the operator's policy sets `allowWildcardEgress: true`; the receipt then discloses it. Where the run's docker filter runs, the tools container reaches out from a network of the run's own that only it joins, and its declared commands run there too; elsewhere, from Docker's default network. Under a sandboxed `docker.runtime` the policy must also name [`docker.resolvers`](runner.md#the-hosts-name-servers-dockerresolvers), or the run is refused at plan time (exit 11). CLI v0.6.122 or later |

**`filesystem.read` / `filesystem.write`**

| Value | Meaning | Run-time enforcement |
|---|---|---|
| `none` / omitted | no access in that direction | the corresponding tools do not exist |
| `workspace` | the whole task workspace | `read` grants `fs_read` + `fs_list`; `write` grants `fs_write`; the workspace is bind-mounted into the **tools** container `ro`/`rw` accordingly |
| `{paths: [repo/relative, …]}` | only these paths | per-path bind mounts plus server-side grant checks; a directory entry covers everything under it |

A paths entry the release does not ship is made an empty folder in the
run's own copy of the workspace before the tools start, so a write grant of
`out` needs no `out/` in the package. An entry that names a file is made a
folder too when the file is missing, and a write to that name then fails:
ship a file you grant by name. An entry inside another write entry shares
that entry's mount.

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

**`optionalSecrets`** (v2): the declared secrets a run can do without, by
name. Each must already be declared, under `capabilities.secrets` or a
declared MCP server's `secrets`, so the list marks a secret optional and
never adds one to the contract; every declared secret it does not list is
**required**. Moving a secret between optional and required is no change of
capability, and asks for no consent again; a newly declared secret is a
widening either way. That holds because a consent lists every declared
secret by name, optional or not.

```yaml
capabilities:
  secrets: [GITHUB_TOKEN]          # private repositories as well as public ones
  optionalSecrets: [GITHUB_TOKEN]
```

A run starts without an optional secret that has no value (agentry-cli
v0.6.66 and later). The runner writes it empty into the gateway's secrets
file, so the runner's own `fetch` answers that the secret is not set; the
System Prompt tells the QuickAgent which optional secrets it was not given;
and the receipt's `capabilities_enforced["secrets.absent"]` names them. A
declared MCP server that reads the secret sees its variable set but empty,
and what it does then is its own. A missing required secret still refuses
the run (exit 11), naming only the required ones. A hosted run asks only
for the required secrets ([Hosted runs](hosted-runs.md)). Write the
instruction for both cases: say what the QuickAgent does without the
optional secret, never that it stops.

A CLI or desktop that pins a core older than this field refuses a manifest
that carries it, by name, so a release that marks a secret optional needs
agentry-cli v0.6.66 or later to run. The Builder on the site and in the
desktop marks each secret Optional or Required, and the Drafter behind
Describe it marks each secret it declares, from its 1.10.0 (agentry-cli
v0.6.75).

**`targetHosts`** (v2): the ids of the release's `host` intake questions,
at most four. Each is a machine the person names when the run starts,
which the agent may run any command on, as the account the person signs
in with, through the runner's host tools ([Target hosts](#target-hosts-host)).
It names no host: the answer does. Adding one is a widening, so an upgrade
that adds one asks for consent again.

**`browser`** (v2): a headless web browser for the run, with the sites
the person names (`url` questions), fixed `hosts`, a `scope` (`site`, the
default, or `public`) and the declared `secrets` it may type
([The browser's site](#the-browsers-site-a-url-question-named-in-capabilitiesbrowser)).
A new browser, site, host or secret, or `site` to `public`, is a widening,
so an upgrade that does one asks for consent again.

**`dataAccess`** holds semantic categories for review and audit: `email`,
`calendar`, `files`, `tickets`, `code`, `messages`, `payments`, `other`.
Operators may catalog extra MCP servers per category in their runner
policy; undeclared categories are never wired in.

**`mcpServers`** declares the MCP servers the QuickAgent requires at run
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
egress). A server's `egress` counts as network the release reaches: a
namespace's `blockedCapabilities: [network]` refuses it, and a host an
update adds that the previous release did not reach is a low
`S9/new-egress` finding (medium for `"*"`). An update that keeps a server
at the same pin but adds an egress host, a secret or a tool, or lifts its
`tools` list, is a widening and asks for consent again, as a new pin
does. Removing the agent removes the server configuration and keys by
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
file, and the secret scanner also reads the `env` values themselves, out
of the manifest the registry stores, whatever the YAML's spelling: a key
named like a credential (`…_TOKEN`, `…_SECRET`, `…_PASSWORD`,
`…_API_KEY`) carrying a value of eight or more characters, or a
token-shaped value under any key, is a medium finding: the default gate
publishes the version with it on the report, and an organization at
threshold `low` sends it to review. Both are a backstop, not a place to
keep one. In
the example above,
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
every advisory as a finding, CVE ids and fixed versions included. A
Critical advisory rejects the version. A High one goes to review when its
CVSS base score is 8.5 or more, or when it carries no score. A High below
8.5, a Moderate and a Low are shown on the report and do not hold it, like
a finding of that severity in your own files. Pin a
version with a fix rather than asking for an exception; the [trust
model](trust.md) page describes what the check does and does not prove.

**Remote servers and OAuth sign-in** (v2). Many MCP servers run at their
vendor and sign a person in on the vendor's own consent screen. A
QuickAgent declares one by its address, and may give a package server an
OAuth sign-in:

```yaml
capabilities:
  mcpServers:
    - url: https://mcp.linear.app/mcp   # a remote server: exactly one of npm, pypi, url
      auth: oauth                       # oauth | secret | none
      scopes: [read]                    # what consent asks for (auth: oauth only)
      tools: [list_issues]
    - url: https://api.githubcopilot.com/mcp/
      auth: secret                      # its one secret, sent as a bearer header
      secrets: [GITHUB_TOKEN]
    - pypi: workspace-mcp               # a package server signed in by OAuth
      version: 2.0.1
      tools: [search_gmail_messages, get_gmail_message_content]
      egress: [gmail.googleapis.com]
      env:
        MCP_SINGLE_USER_MODE: "1"
        WORKSPACE_MCP_TOOLS: gmail
        WORKSPACE_MCP_READ_ONLY: "true"
        USER_GOOGLE_EMAIL: me@agentry.invalid   # names the token file below
      oauth:
        issuer: https://accounts.google.com
        scopes: [https://www.googleapis.com/auth/gmail.readonly]
        files:                          # written into the server's own token folder
          - path: me@agentry.invalid.json
            template: '{"token": "{access_token}", "expiry": "{expiry}", "scopes": ["https://www.googleapis.com/auth/gmail.readonly"], "token_uri": "https://oauth2.googleapis.com/token", "client_id": "agentry", "client_secret": "agentry"}'
        env:
          WORKSPACE_MCP_CREDENTIALS_DIR: "{dir}"
```

- **A remote server** takes an `https://` address on a public host name
  (lowercase, a top-level label that starts with a letter, port 443, no
  user information, query or fragment, and no space, quote, `$` or brace;
  at most 512 characters). Its host counts as network: a namespace's
  `blockedCapabilities: [network]` refuses it, and a new host in an update
  is a low `S9/new-egress` finding. The address's host is the server's one network
  destination, so it takes no `version`, `egress`, `env` or `oauth`.
  `auth` is required. `auth: secret` sends exactly one declared secret as
  the bearer header, `auth: none` sends nothing, and `auth: oauth` needs
  the person's **connection**.
- **A connection** is the person's OAuth grant to one server, made on the
  vendor's consent screen the first time a run of that QuickAgent version
  needs it, and kept for that version's later runs. It belongs to that one
  version. Another QuickAgent, or another version of this one, makes its
  own.
- **An `oauth` block on a package server** names the authorization server
  (`issuer`, `https://`), the `scopes` consent asks for, and how the access
  token reaches the server:
  - `files`: at most four, each a plain file name in the server's token
    folder (letters, digits, `.`, `_`, `-` and `@`, at most 64; `@` for a
    server that looks its file up by an account's email, as
    `workspace-mcp` does) and a template of at most 2,048 bytes. A template's placeholders
    are `{access_token}`, `{expiry}` (RFC 3339, UTC) and `{expiry_ms}`
    (Unix milliseconds).
  - `env`: at most eight variables. An env value's placeholders are
    `{access_token}`, and `{dir}`, the token folder's path, which needs at
    least one file declared.

  `{access_token}` must appear somewhere. A name may not repeat the
  server's `env` or a secret.
- **What a run will receive.** Once the runner carries connections
  (below), a run receives an access token and nothing else of the
  connection: never a refresh token or a client secret. A value a server's
  file needs for a client id or secret is a fixed dummy (as `agentry`
  above). The runner writes the files itself, never through the gateway,
  so a template's `$` and braces are content. The secret scanner reads
  every value of the `oauth` block's templates and env, in any format,
  with the placeholders taken out, and reports a token-shaped one
  (`S2/oauth-token-value`, medium), as it reads `env`. It is a backstop:
  a value that does not look like a token passes it.
- **Servers that cannot run on an access token alone** refuse an `oauth`
  block by name, with an alternative to declare:

  | Package | Declare instead |
  |---|---|
  | `pypi:mcp-gsuite` | `pypi:workspace-mcp` |

- **At the gate**, stage S7 reports each remote server as
  `S7/remote-server`, a low finding naming its address, auth and scopes.
  There is no package to look up and no code the pipeline reads, and the
  report says so. A version publishes with it. A publication policy's
  `blockedMcpServers` blocks a remote server by its host (`url:<host>`,
  globs allowed, as in `url:*.example.com`).
- **Consent.** The capability diff the clients ask consent from
  (`DiffCapabilities`) calls each of these wider than before: a new remote
  server or address, a changed auth or issuer, a new scope, a remote
  server's tool added or its allowlist lifted, a different bearer secret,
  an added OAuth sign-in, and a changed `oauth` file or env. The CLI and
  the desktop show them once their core pin carries this change.

The CLI runs a remote server with `auth: none` or `auth: secret` through
the runner image's bridge, `auth: oauth` on the person's connection, and a
package server's `oauth` block
(see [the runner reference](runner.md#connections)): the access token is
written into the files the block declares, in a folder of the server's own,
or into its env, and renewed before it expires while a local run lasts
where the server reads it from a file (an env token is fixed for the run,
so a server that reads its token from env alone stops working once the
token expires, about an hour for Google). A file's client id or secret, if
the server's format has one, is a fixed placeholder the author writes (as
`agentry` above), never a real value: the runner substitutes nothing but
the placeholders. A run in Agentry uses the connection Agentry keeps for
the account and the release
([Hosted runs](hosted-runs.md#a-runs-connections)). A CLI or desktop older
than its core pin refuses such a manifest by its unknown field.

### `dependencies`

`dependencies.agents: [{ref: ns/name, version: "^1.2"}]` is informational:
recorded and displayed, not auto-installed.

### `publish`

| Field | Meaning |
|---|---|
| `publish.include` | **required**; the release archive allowlist of glob patterns (`path.Match` segments; a whole segment `**` matches any depth). Nothing outside it ships, and a v2 manifest must match `agent.yaml` itself: the runner reads the manifest from the installed archive |
| `publish.channel` | `stable` (default) or `beta` |

## Installing on this machine

`agentry install ns/name` resolves the release, verifies its sha256
digest and its DSSE attestation against the keys pinned for the registry
(unsigned requires `--allow-unsigned`; a version admitted without a scan
requires `--allow-unscanned`), shows the declared capability contract
diffed against the version installed here — declared egress or exec
needs typed consent on a first install, and so does anything widened
since (`--yes` for CI; off a terminal, without it, the install refuses)
— and lays the release down in the runner home:
`~/.agentry/runner/agents/<ns>/<name>/<version>-<digest12>/`, the
directory `agentry run` reads, so a run after the install fetches
nothing and the consent given here covers it. Inside it, under
`export/`, lands the shape a coding agent reads, in the style the
operator policy implies: a Claude skill when the policy names Claude
Code (`harness.claude`), AGENTS.md when it names Codex, else a Claude
skill for an Anthropic key and AGENTS.md for any other provider. A newer
version replaces the older; one record per QuickAgent in the install
state (`agentry list`; `--check` asks the registry whether a newer
version exists). `--dir` is for the two exports; the runner home is one
(`AGENTRY_RUNNER_HOME`). `agentry uninstall ns/name` removes the
directory, the record and, unless `--keep-mcp`, the MCP profile.
Installing into an existing coding agent instead is `--target` or
`--provider`, [below](#installing-into-an-existing-coding-agent).
This record is this machine's. The registry keeps a separate one per
account — the release a signed-in person accepted on the web and the
contract they consented to, `GET /user/installs` in the
[API conventions](api-conventions.md#account-installs) — and the two are
never synced: installing here records nothing there, and the reverse.

## What a QuickAgent gets at run time

`agentry run` verifies a release it has not installed exactly like
`agentry install` (sha256 digest + DSSE attestation against pinned keys;
unsigned requires `--allow-unsigned`), asks the registry whether any declared MCP server
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
| (always) | `list_inputs`, `read_input`, `search_inputs`: the run's provided input files, read-only |
| (always, but for the built-ins) | `scratch_list`, `scratch_read`, `scratch_write`, `scratch_search`: the run's [scratch folder](runner.md#the-scratch-folder) at `/scratch`, private to the run and deleted at its end |
| (always, but for the built-ins) | `export_pdf`: a Markdown report as a PDF in `reports/`, in the form the agent picks (`report`, the default, `letter` or `memo`) and laid out in the person's [report theme](runner.md#the-report-theme) |
| (always, but for the built-ins) | `grep`, `glob`: [search file contents](runner.md#searching-files-grep-and-glob) by regular expression and list files by path pattern with ripgrep, one area a call, only what the run's other tools read: `/inputs`, `/knowledge/<pack>`, `/scratch`, and `/workspace` only with `filesystem.read`. ripgrep runs with an empty environment, as a user of its own when the tools server is root, a fixed argument list that never starts another program, and caps on memory and time; where the machine has Landlock it also reads only the searched area and writes nothing, and at Landlock ABI 4 or later opens no TCP connection |
| `filesystem.read` | `fs_read`, `fs_list` |
| `filesystem.write` | `fs_write` |
| `network.egress` hosts | `fetch` (with optional declared-secret auth) |
| `exec.commands` | `run_command` |
| `browser` | the [browser tools](runner.md#the-browser-a-site-to-test-named-at-run-time) (`browser_navigate`, `browser_click`, …), from the browser server |
| `targetHosts` | the host tools (`host_run`, `host_read`, …), from the host link |
| `mcpServers` | each declared server's own tools |

A tool whose line the manifest does not declare is absent from the run, not
present and refusing, so an instruction that calls for one describes a run
that cannot happen. The registry reads the tool names an instruction calls
for against these lines at publication, and a release that names a tool it
is not granted goes to a person rather than publishing (stage S6, since
ruleset 0.4.10; [trust](trust.md#s6)); the check of a finished draft lists
the same tools before Submit ([model input](model-input.md#the-check-of-a-finished-draft)).

The runner puts the **System Prompt** before every instruction. Its fixed
head says the run is in a locked sandbox, puts attached knowledge first, and
keeps the model on the instruction's task. Its body is composed from what
the manifest grants, and never states a grant the manifest does not make.
It covers the tools (only from the gateway), the network, the workspace at
`/workspace`, the scratch folder at `/scratch`, searching files with
`grep` and `glob`, the commands, the secrets
by name, and the inputs under `/inputs`. It explains how to read an
attached knowledge pack, that reports go through `write_report`, when to
also export one as a PDF with `export_pdf`, and that the final message is
the run's result.
So an instruction need not repeat any of this. The text is in the run
plan's hash, and [the runner reference](runner.md#the-system-prompt) shows it word
for word for a sample QuickAgent.

**Input files.** Files and artifacts from outside the container reach a
run through `agentry run --file PATH` (repeatable; files or directories),
a `file` intake answer, a file added to a session, or the uploads of a
hosted run. They are copied into a per-run folder mounted **read-only** at
`/inputs` on the tool plane — a channel like stdin, operator-controlled per
run, so it needs no manifest capability. Job output and receipts stay on
the separate `/out` volume.

Before the agent starts, the runner checks every file for malware and
turns it into text where it can, in a container with no network
([running with files](runner.md#running-with-files)). So a QuickAgent that
takes files can count on these:

- **Common documents work**: PDF, Word (DOCX and DOC), OpenDocument,
  EPUB, RTF, spreadsheets (XLSX and ODS as Markdown tables, XLS as
  text), PowerPoint and OpenDocument slides, Outlook and other mail (MSG, EML, mbox),
  and images, whose text is read by OCR. Code, markup and data (source,
  HTML, XML, CSV, JSON, YAML, logs) arrive as uploaded.
- **Archives work**: zip, tar, 7z, rar and gzip, bzip2, xz or zstd
  streams are unpacked, and each file inside is read by its path,
  `bundle.zip/folder/file.docx`, up to three archives deep, 2,000 files
  and 512 MiB unpacked.
- **Every file is checked**: by ClamAV, and the risky types (executables,
  scripts, macro and legacy Office, RTF, PDF and a few more) by their
  SHA-256 on Hybrid Analysis, never by upload. A file either check
  refuses stops the run before the agent starts (exit 11), naming it; on
  Agentry that costs nothing. On Agentry, AI Review also reads every
  input's text, and one it flags refuses the run for one credit.
- **The agent never needs `exec` to read them**: `list_inputs`,
  `read_input` and `search_inputs` serve each file's text and its
  original, and the [`inputs`](#inputs-what-files-it-takes-and-how-it-reads-them)
  block chooses which view is read by default.

A hosted run takes at most 20 files of at most 10 MB each
([hosted runs](hosted-runs.md#what-a-run-is-refused-for)). Write `guide.files` to say which
files the QuickAgent wants, and the run setup shows it.

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
environment · `14` the QuickAgent failed · `15` timeout · `16` budget ·
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

`--provider` picks the right target below (the web Downloads page lists
these flows); the explicit `--target` forms remain, and either names the
export — with neither, `agentry install` goes to the runner home:

| Target | What lands | Contract mapping |
|---|---|---|
| `claude-skill` | `~/.claude/skills/<name>/` with SKILL.md frontmatter | capabilities compile to `allowed-tools`: `Read`/`Grep`/`Glob` ⇐ read, `Write`/`Edit` ⇐ write, `Bash(cmd:*)` ⇐ exec, `WebFetch(domain:host)` ⇐ egress |
| `agents-md` | `./agents/<name>/` + a section in `./AGENTS.md` | the section records the same contract as a Tools note |

Enforcement in embedded mode is the host's. The
[trust model](trust.md) page explains what each layer does and does not
prove.

## Publishing

Three doors, one pipeline. `agentry publish` submits a workspace from the
command line; the hosted site's **QuickAgent Builder** (`/build`, on a
registry with the site in front) authors one in the browser — anyone can
download the packed archive for local use, and signed-in users can submit
it; and the **desktop app**'s Build tab does the same from a form. Repos
hosted on the registry can also publish by pushing a release tag (the
agent's auto-publish-tags setting). Whichever door, the submission is
identical server-side: manifest validation, content scanning against the
declared capabilities, human review where findings demand it, and DSSE
signing. A publish to a public namespace needs a second factor on the
account, asserted by the identity provider you sign in with, when the
registry has that on — `/meta` reports it as `features.publicPublish2FA`.
Published releases are immutable and content-addressed. The language rule
applies to QuickAgents as it does to everything here: a release is
*scanned, with N findings, signed*, never "safe". Declare the least you
need: the contract is what the scan, the install's consent and the runner
all work from.

`agentry publish` and a tag push both need the QuickAgent's **record**,
which the CLI never creates: a first publish of a name with no record is
answered 404. Create it at `/new` on the site, which asks for the
namespace, the name, the run modes and the visibility and sets up the git
repository a tag is pushed to, or with `POST /agents`. The Builder's and
the desktop's Submit create the record themselves.

Before submitting, `agentry review .` runs the built-in Examiner on your
own computer: the registry's rules, AI Review's questions and a model's
reading of the files, with the outcome the gate would be expected to
reach. It submits nothing, and the registry's scan at submission is the
one that counts.

Every door checks the same quotas (V8): at most 2,000 files and 10 MiB in
the archive, 2 MiB per file (5 MiB per image), and 1 MiB of text files in
total — the prose the scanners read in full, so an instruction set cannot
grow past what a reviewer can read by being split across files.
`agentry validate` reports the same limits offline.

# Hosted runs

A hosted run is `agentry run` on the platform's machine instead of yours.
An account asks the registry to run a published release, the registry queues
it and holds credits for it, and Agentry pushes it to a sandbox host, which
runs the CLI against it and sends back one output encrypted to the person
who ran it. The account sees that the run was done, whether it passed, the
credits it used, its receipt and its output; no log is kept
([the execution plane](#the-execution-plane)). The release, the compiled
plan, the gateway and the receipts are the ones the
[Runner reference](runner.md) describes; what differs is who owns the docker
daemon, what bounds the run, and that it costs credits.

Hosted runs are not part of this repository's server. They are an extension a
deployment mounts (the runs extension of the enterprise build): the routes
sit under `/api/v1/x/runs/` and `GET /api/v1/meta` lists the extension where
one is loaded. A registry built from this repository has none, and a token
carrying only `run:read` and `run:write` is refused there exactly as a token
without the right scope is anywhere else
([API conventions](api-conventions.md#personal-access-tokens-and-their-scopes)).
The secrets a run declares are kept by a second extension, the vault
(`/api/v1/x/vault/`), which returns no value on any route. `secret:write` is
the scope it is to admit a token by to set and delete the account's secrets;
listing them stays a signed-in session's.
[A run's secrets](#a-runs-secrets) says how a run gets them.

`GET /api/v1/x/runs/status` answers anyone: whether this deployment can take
runs at all (it needs a database, a credit ledger and an object store) and
how many runs are queued. It also answers the price list, to anyone, since it
is the deployment's configuration and not a secret: every tier's caps and
hold under `tiers` (each with the `build` caps and hold of a [knowledge
build](#a-knowledge-build)), and `knowledgeBuild` — whether a build can run
here, what it holds, and the pack scan's credit — and `draft`, the terms of a
[hosted draft](#a-hosted-draft), and `voiceBuild`, the terms of a [hosted
Voice Writer run](#a-hosted-voice-writer-run). A signed-in caller also gets
`caller` — the tier a run of theirs is held at, `account` (whose row it is
held on: their own, or the organization whose pool pays for their runs), that
tier's caps, the credits a run holds, the tier's `build` and the `draft`
hold, and `voice`, whether their payer may start a Voice Writer run now — so
a client can state the cost, and whose credits it is, before any run exists.
`sessions` states a [hosted session](#a-hosted-session)'s terms to anyone:
whether this deployment runs sessions (`enabled`), the free minutes, a paid
minute's credits, the balance one needs to start, the idle close, and per
tier whether its payers may start one (`allowed`). A signed-in caller's
`caller.session.allowed` says whether their own payer may. `hostsOnline` is
how many sandbox hosts are taking runs: seen within the stale window, neither
retired nor draining, with capacity. A session starts only when there is one.
`workersOnline` is deprecated and always 0: it stays in the answer so that
older clients still read a number. Its prices are in credits and its caps in
seconds and turns; the per-credit rates and the token caps are not served
([in credits, never in tokens](#in-credits-never-in-tokens)).

## Who may do what

Three credentials reach these routes and never overlap.

An **account** acts through a browser session or a personal access token
carrying `run:read` (list, read, events, outputs) or `run:write` (create,
input upload, cancel), and reaches only its own runs. Another account's run,
and another account's artefact, is `404` — a fellow member of the
organization whose pool paid for the run included: the pool is shared, the
run is not.

**Platform staff** act through a signed-in session. Their read routes (the
`GET`s on hosts, enrolments, the fleet, its scaling and the hosted model)
also admit a personal access token carrying `audit:read`.
Every staff change is a session's alone, and a
token on one is `403`.

A **sandbox host** holds no credential of Agentry's but its one-use enrolment
token, good for the enrol route alone. After that Agentry calls the host over
mutual TLS, and the host calls no other route in this table.

| Route | Credential |
|---|---|
| `GET /api/v1/x/runs/status` | anyone; `caller` is added for a signed-in one |
| `POST /api/v1/x/runs/` | session or PAT with `run:write` |
| `GET /api/v1/x/runs/` | session or PAT with `run:read` — the newest fifty |
| `POST /api/v1/x/runs/inputs?name=` | session or PAT with `run:write` |
| `GET /api/v1/x/runs/{id}` | session or PAT with `run:read` (platform staff read any, [without its text](#a-runs-data-at-rest)) |
| `GET /api/v1/x/runs/{id}/events` | session or PAT with `run:read` |
| `GET /api/v1/x/runs/{id}/outputs/{name}` | session or PAT with `run:read` |
| `POST /api/v1/x/runs/{id}/cancel` | session or PAT with `run:write` |
| `GET /api/v1/x/runs/{id}/session` | a hosted session's runner alone: session, or PAT with both `run:read` and `run:write` |
| `POST /api/v1/x/runs/{id}/session/turns`, `/files`, `/end` | a hosted session's runner alone, as above |
| `POST /api/v1/x/runs/hosts/enrol` | a sandbox host's one-use enrolment token alone; a session or a PAT is `403` |
| `GET /api/v1/x/runs/staff/hosts`, `GET …/staff/hosts/enrolments` | platform staff; a session, or a token with `audit:read` |
| `POST …/staff/hosts/enrolments`, `POST …/staff/hosts/enrolments/{enrolment}/revoke`, `POST …/staff/hosts/{host}/retire` | platform staff, session only |
| `GET …/staff/fleet`, `GET …/staff/fleet/scaling` | platform staff; a session, or a token with `audit:read`, where the deployment runs the fleet |
| `POST /api/v1/x/runs/staff/hosts`, `POST …/staff/hosts/{host}/replace`, `PUT …/staff/fleet/scaling` | platform staff, session only, where the deployment runs the fleet |
| `GET /api/v1/x/runs/staff/model` | platform staff; a session, or a token with `audit:read` |
| `PUT`/`DELETE /api/v1/x/runs/staff/model` | platform staff, session only |

## Creating a run

`POST /api/v1/x/runs/` takes a `ref` (`ns/name@version`, or `ns/name` for
the latest published release), the `task` text the harness receives, the
release's `intake` answers as a JSON object, and up to twenty `inputs` — ids
from `POST /api/v1/x/runs/inputs?name=<relative name>`, which stores one file
each and sweeps unclaimed uploads after a day. It may also name up to five
knowledge packs by id in `knowledge`, for the run to search
([below](#knowledge-attached-to-a-run)), and ask with `voice: true` to
write in the runner's [Writing Voice](#a-run-in-the-writing-voice). The
response is the run:
its resolved ref and archive digest, its caps, the credits held and `payer`
— the handle whose row holds them — its queue position, and `expiresAt`.

The ref must name a release the caller may read, as the registry's own agent
read decides it: a public release is anyone's; a private one needs `read` on
the agent — the namespace's owner, an admin or member of the organization
whose namespace it is, or a grant on the agent — and, on a personal access
token, the `agent:read` scope beside `run:write`. The agents of an
organization that is suspended are absent to everyone, public or not.

`mode` is `autonomous`, the default, or `interactive`, which makes the run
a [hosted session](#a-hosted-session): the release's interactive mode, which
its runner converses with while it runs. Only a run of a release takes a
mode; a knowledge build, a draft or a Voice Writer run with `interactive` is
`422`.

## Whose credits: the payer

A run is the runner's, and its credits are the **payer's**. The payer is the
runner's organization when they are an active member of one — membership is
the person's tier, and the organization's pool pays for its members' work,
their runs of the organization's agents and of their own alike — and the
runner themself otherwise. The agent's namespace does not choose the payer:
an outsider who runs an organization's public release pays from their own
row. The run records the payer and answers it as `payer`; `caller.account`
on the status route names it before a run exists.

Everything else about the run stays the runner's: the row, the one-active
rule, the artefacts under their prefix, and who may read it. An admin of the
paying organization sees the run's lines in the organization's ledger
(`run_hold`, `run_release`, `run` under `run:<id>`), not the run.

An organization whose subscription is not in force — pending payment,
restricted after a lapse, or decommissioning — pays for nothing: a member's
create is `402 subscription-inactive` naming the organization as `account`
with its `standing`, and no run is written. The first-party organization is
unmetered: its members' runs hold nothing (`holdCredits` is 0), settle
nothing, and write no ledger line.

## Caps

A run is created with the caps of the payer's tier, and the sandbox host
gives them to the CLI as its `--timeout` and `--max-turns`.

| Tier | Wall time | Turns | Tokens | Credits held |
|---|---|---|---|---|
| Standard | 300 s | 20 | 500,000 | 20 |
| Pro | 900 s | 60 | 5,000,000 | 200 |
| Business | Pro's | Pro's | Pro's | 200 |
| Enterprise | Pro's | Pro's | Pro's | 200 |

Those numbers are a deployment's configuration, not constants:
`AGENTRY_RUNS_CAPS_STANDARD`, `AGENTRY_RUNS_CAPS_PRO`,
`AGENTRY_RUNS_CAPS_BUSINESS` and `AGENTRY_RUNS_CAPS_ENTERPRISE` are
`seconds,turns,tokens` — the organization tiers take Pro's numbers unless a
deployment sets them apart, since a member has everything Pro has — and
`AGENTRY_RUNS_INPUT_TOKENS_PER_CREDIT` (50,000) and
`AGENTRY_RUNS_OUTPUT_TOKENS_PER_CREDIT` (25,000) are the two rates the hold
and the settlement are computed at: 1,000 credits buy about US$5 of
inference at US$0.10 a million input tokens and US$0.20 a million output.
`AGENTRY_RUNS_TOKENS_PER_CREDIT` is not a setting: a deployment that sets it
is stopped at start-up with a message naming the two, as is one that sets a
zero rate, an empty cap or a zero timeout, rather than running with a price
it did not mean. One that sets `AGENTRY_RUNS_DRAFT_TOKEN_CREDITS` is stopped
too, with a message naming
`AGENTRY_RUNS_DRAFT_CREDITS` and `AGENTRY_RUNS_DRAFT_MAX_TOKENS`.
`GET /api/v1/x/runs/status` reports the live seconds, turns and holds.

## Credits: a hold, then a settlement or a refund

Nothing is debited before a run. Creating one **holds**
`ceil(maxTokens ÷ outputTokensPerCredit)` credits on the payer's row — the
tier's token cap priced at the output rate, the dearer one, which bounds any
mix of input and output within the cap: 20 for Standard and 200 for Pro,
Business and Enterprise — in the same transaction as the run's row. A create the
payer's balance cannot cover is `402 credits-exhausted` carrying `account`,
`balance`, `hold`, `resetsAt` and `tier`, and no run is written.

When a run finishes, the runner's exit class becomes the outcome, and the
outcome decides what the hold becomes.

| Outcome | The runner's exit class | The hold |
|---|---|---|
| `succeeded` | `ok` | settled from the tokens |
| `failed` | `harness` (14), `outputSchema` (17) | settled from the tokens |
| `timeout` | `timeout` (15) | settled from the tokens |
| `budget` | `budget` (16) | settled from the tokens |
| `interrupted` | an envelope whose error is `interrupted`, and any run the account cancelled that ran and did not succeed | settled from the tokens when something ran; refunded when the envelope reports no tokens and no turns |
| `refused` | `verify` (10), `policy` (11), `compile` (12) | refunded in full, except a run AI Review refused for an input it flagged, which settles AI Review's one credit alone ([a run's files](#a-runs-files)) |
| `error` | `cli` (1), `usage` (2), `gateway` (13), and any exit class the mapping does not know | refunded in full |
| `blocked` | `blocked` (18), the agent could not do its task with what the run had | settled from the tokens when the receipt's reason is `agent-blocked` (the agent said so); refunded in full when it is `runner-blocked` (the runner's own tools failed the agent) or names no reason |

A run cancelled while still queued is `cancelled`, not an outcome, and its
hold is refunded in full. So is a run nobody claimed within the queue timeout;
a run whose sandbox host fell silent is closed as `error` and refunded.

A run that **ran** settles `max(1, ceil(input ÷ inputTokensPerCredit +
output ÷ outputTokensPerCredit))`, never more than the hold, with the rest
of the hold released. `input` and `output` are the stored receipt's
`usage.inputTokens` and `usage.outputTokens`; tokens its `usage.totalTokens`
counts beyond them — all of them, when a harness reported no split — are
priced at the output rate. Input counts tokens processed, cached prefixes
included, so the price leans the platform's way rather than the account's.
The minimum of one credit means a run that started and produced nothing
still costs one. The ledger records the hold (`run_hold`), then either the
whole hold released (`run_release`) and the cost charged (`run`), or the
whole hold refunded (`run_refund`) — each line unique on its reason and the
run's id, so a finish reported twice changes nothing.

## What a run is refused for

| What | Answer |
|---|---|
| The release does not declare the mode asked for | `409 mode-not-declared` |
| The release declares a browser whose scope is `public`, and the deployment keeps a run's browser to the sites named (`AGENTRY_RUNS_BROWSER_PUBLIC_WEB` off, the default) | `409 browser-public-web` ([below](#a-run-with-a-browser)) |
| A browser's site answer that is not an `http` or `https` address | `422 validation` |
| A browser's site answer no sandbox host can open: an address that is not public, a name only a local network answers (one label, `.localhost`, `.local`, `.internal`, `.home.arpa`), or a port other than 80 and 443 | `409 browser-site`, with `question` |
| A session where the deployment does not run them (`AGENTRY_RUNS_SESSIONS` off, or no sandbox hosts), or no sandbox host is taking runs (`hostsOnline` 0) | `409 sessions-unavailable` — a person waits on a session as it starts, so it is refused rather than queued |
| A session whose payer is on Standard | `403 session-tier`, with `account`, `tier` and `requires: pro` |
| A session whose payer's balance is short of `AGENTRY_RUNS_SESSION_MIN_CREDITS` | `402 credits-exhausted`, as for a hold |
| The release, or an MCP server it declares, requires a secret the caller has not set | `409 secret-missing`, with `missing` (the required names not set), `secrets` (every declared name) and, when there are any, `optional`; set them, then create the run again ([below](#a-runs-secrets)). With `ask_optional_secrets: true`, `missing` also names each optional one not set ([below](#at-create)) |
| The release requires a secret and the deployment keeps none, or pushes to no sandbox host | `409 secrets-declared`, with `required` and `secrets` — such a release runs on your own machine, where its keys are yours |
| The release requires more than 32 secrets, or the run would carry more than 32, where the deployment keeps secrets | `422 validation` |
| An MCP server the release declares signs in by OAuth, and the caller keeps no working connection to it for this version | `409 connection-missing`, with `missing` (the servers to connect) and `connections` (every one that signs in); connect them, then create the run again ([below](#a-runs-connections)) |
| An MCP server the release declares signs in by OAuth, and the deployment keeps no connections or pushes to no sandbox host | `409 connections-unsupported`, with `connections` — such a release runs on your own machine |
| The account already has a run queued, claimed or running | `409 run-active` — one active run per account, held by a partial unique index rather than a read-then-write |
| The payer's balance is short of the hold | `402 credits-exhausted`, with `account`, `balance`, `hold`, `resetsAt` and `tier` |
| The payer is an organization whose subscription is not in force | `402 subscription-inactive`, with `account`, `standing` and `tier` |
| A task over 64 KB, more than twenty inputs, or an input over 10 MB | `413 too-large` |
| The ref names nothing published, or nothing this caller may read | `404` — a private release the caller holds no `read` on, or any release of a suspended organization, is `404`, never a leak that it exists |
| Malformed intake, an input id that is not the caller's, or a knowledge pack named twice | `422 validation` |
| Knowledge attached on a token without `knowledge:read` | `403 forbidden` |
| A knowledge pack that is neither the caller's nor shared by their organization | `404 knowledge-not-found` — the same answer for another account's pack as for none |
| A knowledge pack being scanned, whose stored tree could not be read, or with no pages yet | `409 knowledge-scanning`, `409 knowledge-failed`, `409 knowledge-empty` |
| More than five knowledge packs, or a pack past 10 MB | `413 too-large`, `413 knowledge-too-large` |
| Knowledge attached on a deployment with no sandbox hosts or no knowledge store | `503 knowledge-attach-unavailable` |
| The deployment has no database, ledger or object store | `503 runs-unavailable` |

A run's output has a cap too: 50 MB of plain output
(`AGENTRY_RUNS_OUTPUT_MAX_BYTES`). The job tells the host how large its
sealed upload may be, and the dispatcher refuses a larger object, so the run
closes as `error` and is refunded ([the
output](#the-output-encrypted-to-the-person-who-ran-it)).

One refusal happens after the run is created, because only the CLI can find
it: a release whose attestation verifies under no key the host has pinned
is refused at verify (exit 10). The run is created, held, claimed, and comes
back `refused` with the whole hold refunded, and the receipt's error says no
pinned key verifies the signature. A key rotation on the registry does not
leave it that way: the registry advertises its retired keys and, at its next
start, queues a sweep that countersigns every attestation the new key has not
signed (see [Trust and security](trust.md)), so a release published before
the current key verifies for a fresh host once the sweep has run. What does
cause it is a host whose pinned set predates a rotation — its login reports
the changed key ids; re-pin its home deliberately.

## A run with a browser

A release that declares a browser (`capabilities.browser`,
[QuickAgents](quickagents.md#the-browsers-site-a-url-question-named-in-capabilitiesbrowser))
runs here with the enterprise build v0.6.57 or later and CLI v0.6.118 or
later:

- **Its sites are public.** Each site question's answer is the address the
  browser opens, sent as a plain intake answer: it is not an input source,
  takes no access token and is never fetched or reviewed as one. The create
  refuses a site no sandbox host can open (above), and the CLI on the host
  resolves a name and refuses one that answers with any non-public address
  before anything starts. The host lets out TCP 80 and 443 alone.
- **Public scope only where the deployment allows it.** A release whose
  browser may open any public site is refused (`409 browser-public-web`)
  unless `AGENTRY_RUNS_BROWSER_PUBLIC_WEB` is on, which also renders that
  job's `browser.allowPublicWeb`.
- **Its secrets come from the vault**, refused, carried or left out exactly
  as the release's other declared secrets are ([below](#a-runs-secrets)).
  On the host they reach the browser's container alone.
- **Two job slots.** A browser run takes two of a sandbox host's slots and
  is handed only to a host whose health says `acceptsBrowser` (its CLI
  carries a hosted browser and its capacity holds two). The oldest queued
  run keeps its place: a host with one slot free hands out nothing until a
  second frees. Its metering is any run's.
- **The image is on the host already.** The host's bootstrap and update
  pull and verify the browser image its CLI pins (`agentry browser
  ensure`), so a run does not download it.

Screenshots and PDFs arrive in the run's output under `reports/browser/`,
and the receipt says where the browser was allowed to go and what the
proxy refused.

## A run's files

A run's inputs are the files uploaded with it: at most twenty, each at most
10 MB (above). The sandbox host's CLI reads them as it reads a local run's
([running with files](runner.md#running-with-files)): before the agent
starts, every file and every file in an archive is checked by ClamAV and
turned into text where it can be, in a container with no network, and the
risky ones are looked up on Hybrid Analysis by their SHA-256 with
Agentry's key ([the host's settings](#the-hosts-settings)). A file either
check refuses ends the run `refused` before the agent starts, with the
receipt's reason `input-refused` and the detail `malware`, and the hold is
refunded in full.

### AI Review of a run's inputs

Then AI Review reads the inputs' text. A run with inputs, or a session, that a host whose health
says `acceptsInputReview` claims is minted a job credential, as a draft is.
The host runs the CLI with `--review-inputs <the registry>` and the
credential in `AGENTRY_JOB_TOKEN`, and the CLI sends every text the agent
could read to the [model-input scan](model-input.md) as `input_file`. The
credential admits scans of that source alone, at most 400 a run (past that
`run-cap-reached`, any other call `run-scan-refused`), and the run's
`inputReview` record counts them.

AI Review is **one credit a run**, however many calls it takes. A run that
ran and used tokens settles it inside the hold, beside them. A run AI Review refused
for an input it flagged (`input-refused` with the detail `ai-review`)
settles that one credit alone. A run refused because a text could not be
read (`not-reviewed`), or for malware, settles nothing. AI Review reads at
most 16 MiB of text a run; a file past that is withheld from the agent and
named in the receipt, and the run goes on. A host whose health lacks the field is
handed no credential, and its runs' inputs are not reviewed.

## A run's data at rest

A hosted run's own data rests encrypted in Agentry's cloud. What is sealed:

- **A run's text:** its task, its intake answers, its receipt and its error,
  a draft's hints, instructions and problems, and the repositories and web
  addresses a knowledge build or a Voice Writer run was given (an address
  can carry a signed download's credential in its query).
- **Its files:** every upload in the core's object store, and a schedule's
  task, answers and copies of its files.
- **What is staged for a sandbox host** in the input bucket (`runs-input`):
  the task, the inputs, a session's added file, and the pack and Writing
  Voice trees a run attaches.

**How.** Envelope encryption. Each value and each object has an AES-256-GCM
data key of its own, used once. The key is wrapped by the vault's OpenBao
Transit key `hosted-runs`, with the account that owns the run as the
context, so one account's wrapped keys do not open under another's. Only
the wrapped key is stored, beside what it seals. A value is bound to its
row and field, so it does not open when moved to another one. An object is
sealed in 64 KiB chunks bound to their place, so it cannot be cut short,
reordered or spliced. A staged object's key is different: it is fresh for
each object, never wrapped and never stored, and it travels to the host
only inside the job, over the mutually authenticated TLS of [the push
path](#the-push-path).

**Who opens it, and when.** Writing never decrypts. A create, a run's
close, a draft's progress and the sweep only seal, and a create answers
with the text it was given. Three things open run data:

- **The api, for the run's owner.** It opens the run's text to answer the
  owner's own reads: the run page, the desktop and the CLI. A page of a list
  is one Transit call. It also opens what the owner hands on: an upload
  added to their session, which it stages sealed again for the host, and
  the brief and inputs of a build they continue.
- **The worker, to start a run.** It opens a schedule's task, answers and
  files when the schedule fires, and a run at its hand-off. It then reseals
  every object it stages under the job's own keys. Nothing staged ever
  rests in the clear.
- **The sandbox host, for the job.** It opens each staged object as it
  streams it into the job's own directory, holds it to its plaintext size,
  and deletes it with the job. The ClamAV scan and the file checks read the
  plaintext on the host. A host says `acceptsSealedObjects` in its health
  answer, and the dispatcher hands a run to no host that does not.

Every open is a Transit decrypt, and OpenBao's audit device records it with
the role that asked (a batch per request).

**Platform staff** read another account's run **without its text**: the
answer carries `"withheld": true`, and the task, intake answers, receipt
and error are empty. A pushed run's output answers staff `404`.

**Runs that did not use the push path.** A run recorded by a pull worker
keeps its per-file sealed outputs and its narration (event) rows until the
30-day sweep removes them ([retention](#retention)).

**What this does not protect.**

- **OpenBao is run by Agentry.** Both the api and the worker may decrypt
  under `hosted-runs`. The vault's own keys keep the stricter split, where
  the api only encrypts. The guard on run data is in the code: a route
  opens a run's text only for the run's owner. A compromised api or worker
  could still ask Transit to open any account's run data. Each such open
  would be a line in OpenBao's audit. So this keeps run data out of the
  database, its dumps and the buckets in the clear. It does not mean
  Agentry cannot read it.
- **While a run uses its data**, the data is in the clear: in the worker's
  memory at the hand-off, and on the sandbox host for the run's life.
- **Not sealed:** artefact names and sizes, the run's event lines, the
  names of attached packs, and a draft's package list, proof and revision.
  The last three are file names and digests that the provenance check reads
  at a publish.
- **Backups.** Data written unsealed is sealed in place by the seal passes
  (the [retention](#retention) section). Database backups and object
  versions taken before that pass still hold it in the clear until their own
  retention ends.

## Watching a run, and cancelling it

`GET /api/v1/x/runs/{id}/events` is server-sent events over the run's
append-only rows. Each event carries `id` (the row's sequence number),
`event` — `log`, `status`, `charge` or `error` — and the row as JSON `data`.
The stream starts after `Last-Event-ID` or `?after=`, so a client that
reconnects loses nothing; it ends with the run's terminal `status` row
followed by `done`, or with `timeout` after ten minutes, from which the
client reconnects at its last id. No transaction is held open for a reader.

A run pushed to a sandbox host writes only its `status` rows and a session's
`charge` rows, so its stream carries no log lines ([no log](#no-log)).

`POST /api/v1/x/runs/{id}/cancel` cancels a queued run at once and refunds
its hold. On a claimed or running one it records the request. The dispatcher
passes it to the sandbox host on its next pass, the CLI is interrupted, and
the run settles what ran.

## The receipt, the usage and the outputs

A finished run carries the runner's envelope minus its result text as
`receipt`, beside `usage` (`turns`, `wallMs` and `credits`), `outcome`,
`exitClass`, `settledCredits` and the `outputs` by name. A run pushed to a
sandbox host keeps the runner's parts
of that envelope alone: never its error text, its result or a path. For a
failed run those parts include `stage`, as one of the CLI's step words, and
`reason`, held to the CLI's closed list (an unknown code, a free detail or a
name outside its grammar is dropped) and then, in the registry, to the names
the run's release declares; a built-in's run keeps the code and the detail
with no name ([the runner's exit codes, stage and reason](runner.md#exit-codes-stage-and-reason)). A run pushed to a sandbox host has one output,
`output.tar`, and `GET /api/v1/x/runs/{id}/outputs/output.tar` decrypts it
for the person who ran it as it streams; to anyone else, platform staff
included, it is `404` ([the output, encrypted to the person who ran
it](#the-output-encrypted-to-the-person-who-ran-it)). No output is served by
a public URL.

A client showing a run shows the receipt's `capabilities_enforced` as it is —
item for item, sentence for sentence, never summarised or scored. Those
sentences name the mechanism behind each contract line, including
`capabilities_enforced.runtime`, the OCI runtime the QuickAgent's containers
were created with ([the `docker.runtime` knob](runner.md#the-oci-runtime-dockerruntime)).
Summarising them would replace what the run enforced with someone's reading
of it.

Three surfaces read the same run. The API above is one; the site's run page
is another, reached from **Run in Agentry** on a QuickAgent's page, with the
queue, where the run stands, the credits held and settled, the receipt and
the output; the desktop app's run panel is the third. The site's
[Running on Agentry](https://docs.secureagentry.net/agentry/hosted-runs/)
walks through what a person sees.

### In credits, never in tokens

A hosted run is reported in credits, turns and time, to everyone who reads
it: its runner, the admins of the organization that pays for it, and platform
staff alike. No answer of the runs routes or the
status route carries a hosted run's token counts, a dollar cost, a token cap
or a per-credit rate: each leaves out any member that names tokens or a
dollar figure, at any depth: the receipt is served without its `usage` block,
`caps` keep their seconds and turns, and a session's `usage` frames are not
passed on. The credits named after tokens stay, because they are credits: a
draft's and a session's `tokenCredits`, a session's `tokensUnpaid`.
`usage.credits` is what the run's model use came to at the rates of its
close, before its hold capped it. Beside `settledCredits` it says what a run
cost, including the run of an unmetered organization, which holds and settles
nothing. A draft's searches and AI Review are in its record's
`pricedCredits`, not there.

The run's stored record keeps every count, and the receipt keeps its
`usage`: the settlement is computed from them and they are its audit. The
deployment counts them in metrics: `RunsHostedInputTokens` and
`RunsHostedOutputTokens`, by the run's kind (`run`, `session`,
`knowledge_build`, `draft`, `revision`, `voice_build`) and its payer's tier
at the close, and `RunsDraftAbsorbedCredits`, what a draft's use came to
past what it settled. They are scraped from `/metrics` beside the core's own
series ([metrics](self-hosting.md#metrics)).

Apart from metrics, two places still show tokens. A run on your own machine
reports them in its receipt and in what the CLI prints, as the [Runner
reference](runner.md) describes: they are your own model's tokens. And the
receipts inside a hosted run's downloaded `output.tar` keep their counts for
now.

## What actually bounds a run

The payer's tier's wall time and turn count are the CLI's own budgets,
enforced inside the run as they are on your own machine (exit 15 and 16).

**The token cap is live.** The CLI narrates its usage as the run goes
(`usage: input=… output=… total=… turns=…` on stderr, whenever it runs with
`--output-format json`), and the execution plane interrupts the run as a
cancel does when the narrated total first passes the tier's token cap; the
run finishes `interrupted` and settles on what it spent. The cap is the
execution plane's, not a runner policy budget: the policy has no token
budget, and a run on your own machine is bounded by its turns and its time
alone. It can pass the cap by at most the tokens of the report that
crossed it, and it cannot cost more than the hold, because the settlement is
capped there. `--max-cost` is not derived — an OpenAI-compatible endpoint of
the deployment's choosing reports no cost.

Two sweeps run every minute. A run nobody takes within the queue timeout
(`AGENTRY_RUNS_QUEUE_MAX`, 1 h) is cancelled and refunded. A run whose
sandbox host has gone silent past the stale window (`AGENTRY_RUNS_STALE`, 10
min), a host retired while it held the run included, is closed as `error` and
refunded.

## Knowledge attached to a run

A run can search [knowledge packs](knowledge.md) the way a local
`agentry run --knowledge` does. The create's `knowledge` names up to five
packs by id. Each must be the caller's own, or one their organization
shares (below), `ready` and at most 10 MB, and the token needs
`knowledge:read` beside `run:write`, since the run reads the packs and its
output can carry what it found. `GET /api/v1/x/runs/status` says whether a
deployment attaches knowledge at all, as `knowledgeAttach: {enabled,
maxPacks}`. The run records each pack's `pack` and `name`, and from its
hand-off the `digest` of the tree it was given.

At the hand-off the dispatcher reads each pack's tree through the core's
store, which decrypts it there, so the pack's data key never leaves the core.
It stages the tree for the host beside the run's inputs, sealed as the inputs
are ([at rest](#a-runs-data-at-rest)), and the host opens it as it fetches it
and passes each pack to the CLI as a `--knowledge` directory. The CLI mounts
it read-only at `/knowledge/<name>` on the tools container and names it in
the receipt by digest, as for a local run ([Running
them](runner.md#knowledge-packs)). The staged trees are deleted with the
job's inputs on every path: the collect, a requeue, a cancel and the sweep.

What happens to a pack between the create and the hand-off:

- **Deleted, or no longer readable:** the run is closed and refunded
  before it starts.
- **Being scanned again** (a new tree was uploaded or built into it): the
  run waits in the queue until the scan ends, then takes the tree as it
  stands.

**An organization's shared packs.** A member of an organization can attach
a pack the organization shares, by its id in the same `knowledge` list. The
pack is read as the organization's, and the run records its `org` and
`shared: true`. Membership is read as the core's knowledge routes read it,
an active membership of an organization that is not suspended, and it is
read three times:

1. **At the create.** Someone who is not a member gets
   `404 knowledge-not-found`.
2. **At the hand-off.** A runner who has left the organization since has
   the run closed and refunded, with nothing staged. A run already on its
   host when its runner leaves keeps what it was handed until it ends.
3. **At the output download.** A run that attached a shared pack, like a
   build of one, serves its sealed output to its runner only while they are
   still the organization's member; to anyone else it is a `404`.

## A run in the Writing Voice

A run or a session can write in its runner's [Writing Voice](voice.md),
as a local `agentry run` writes in the voice kept on that computer. The
create asks with `voice: true`. The token needs `voice:read` beside
`run:write`, and the runner needs a live voice now: one AI Review has
passed. Without it the create is `409 voice-not-live`; a deployment that
cannot attach a voice answers `503 voice-build-unavailable`. A built-in
never writes in the voice: `voice` on a knowledge build, a draft or a Voice
Writer run is `422`. `GET /api/v1/x/runs/status` says whether a deployment
attaches voices, as `voiceBuild.attach`.

At the hand-off of a run in the voice, the dispatcher reads the runner's live
version as it stands then, through the core's store (`Deps.Voice.Live`, never
a pending or flagged version), and stages it for the host with its digest,
sealed as a run's inputs are ([at rest](#a-runs-data-at-rest)). The host
holds the file to that digest and passes it to the CLI as `--voice-file`, so
the run reads it through `voice_read` ([A Writing
Voice](runner.md#a-writing-voice)). The run's `voice.digest` and its
receipt's `voice` line name the version it was given. A runner with no live
voice by the hand-off (deleted since the create) has the run closed and
refunded before it starts. Downloading its output needs `voice:read` beside
`run:read`.

The voice is the runner's own, also when an organization's pool pays for
the run.

## A run's secrets

A release can declare secrets: its own, in `capabilities.secrets`, and each
declared MCP server's, in that server's `secrets`. On your own machine the
CLI resolves them from your profile or the policy's secret source
([Running them](runner.md)). A hosted run gets them from the account's
secrets in the vault, the extension named above. A declared secret is
**required** unless the manifest lists it in `capabilities.optionalSecrets`
([QuickAgents](quickagents.md)), and a run starts without an **optional**
one it has no value for. Where no vault is configured, a release that
requires a secret is refused with `409 secrets-declared` and runs on your
own machine. One whose secrets are all optional runs without them.

### What the account sets

A secret is a name and a value. The name is an environment variable's
(`^[A-Za-z_][A-Za-z0-9_]*$`, at most 128 characters, capitals significant),
and any release that declares that name can use it. The value is valid
UTF-8, at most 8 KiB, not empty, and one line with no white space at either
end. A hosted run hands it to the CLI as a line of an environment file,
which the CLI trims and does not unquote. So a multi-line value, such as a
PEM key, cannot be kept yet. An account keeps at most 100.

| Route | Credential | Does |
|---|---|---|
| `GET /api/v1/x/vault/me/secrets` | session only; every token is `403` | the account's secrets by name, with when each was set, changed and last used by a run, and `keep`; `max` is the cap |
| `PUT /api/v1/x/vault/me/secrets/{name}` | session, or a PAT with `secret:write` | sets `{"value": …}`, with an optional `keep`; `201` new, `200` replaced |
| `DELETE /api/v1/x/vault/me/secrets/{name}` | session, or a PAT with `secret:write` | deletes one; `204`, or `404` when there is none of that name |

No route returns a value, and none returns the stored ciphertext. A value
that breaks the rules above is `422 validation`, or `413 too-large` when it
is too long, and a 101st name is `409 vault-full`. The values are encrypted
by the deployment's key service (OpenBao,
[in Self-hosting](self-hosting.md#openbao-the-key-service-for-hosted-run-secrets)).
When it does not answer, the set is `503 vault-unavailable` and nothing is
stored.

**Kept, or for one run.** `keep` is `true` when it is absent. A secret set
with `"keep": false` is not kept. It waits for a run and is deleted when the
next run of the account that declares its name ends, however that run ends.
If no run takes it, it is deleted a day after it was set. A later set of the
same name decides `keep` again. The site's run setup and the desktop's
Start ask for a missing secret with **Keep it for later runs** unticked, so
a value typed for one run is gone after it unless the person chose to keep
it.

**What a token may do.** A PAT with `secret:write` sets and deletes, and
never lists. It cannot replace or delete a secret that was kept from a
signed-in session, and it cannot unkeep any kept secret. Each of those is
`409 secret-kept`, and the person does it from a session instead (on
Agentry's service, the site's Secrets page). A token's writes are audited
as the token.

### At create

The run's declared names are checked against the caller's secrets. The
release's names and its MCP servers' are one namespace. A **required** name
that is not set is `409 secret-missing`, with `missing` naming each,
`secrets` naming all and `optional` naming the optional ones, and nothing is
held or queued. More than 32 required names is `422 validation`. With every
required name set, the run **carries** every declared name the caller has
a value for: each required one, and each optional one that is set. It
records those names (`secrets`, names only) and is queued. An optional name
that is not set is not carried, and the run starts without it. A run that would carry more than 32 names is
`422 validation` too.

A create may send `ask_optional_secrets: true`.
Then, where the deployment keeps secrets, an optional name the caller has
not set is refused as a required one is: `409 secret-missing`, with
`missing` naming every declared name not set, required and optional, and
`optional` saying which are optional. A client that cannot list the
caller's secrets, such as one holding a token, learns from it which
optional keys to ask for. It sets the ones the person gives, then creates
the run again without the field, so an optional key left empty is gone
without. Without the field, or where the deployment keeps no secrets, an
optional name that is not set never refuses a create. A schedule's create
and edit take the same field for their check alone: the schedule does not
keep it, and its runs start without an optional secret the account does
not keep.

A secret that is not kept counts only for the credential that set it: the
same session, or the same token. To any other caller it is missing, so
that start asks for it again. Run create takes a PAT with `run:write`, so a
token holder can learn which of a release's declared names the account has
set, the optional ones too when it sends `ask_optional_secrets`. It never
learns a value.

### At the hand-off

The dispatcher, in the worker role, locks the run while it is claimed on its
host. Then, in one transaction committed just before the job is sent, it:

- decrypts each name the run carries, under the key of the account that
  created the run;
- sets the secret's last use;
- writes one `vault.secret_used` audit event per name, with the run and the
  host.

A hand-off the host does not take goes back to the queue. The next one
decrypts and records again, so the record is one use per name **per
hand-off**.

The run fails before any host sees it, with its hold refunded and its error
naming the secret alone, when a secret:

- was deleted since the create;
- does not open, or the key service does not answer (the run fails rather
  than waiting in the queue);
- is not one line;
- is not kept and was set by a credential other than the one that created
  the run;
- was set by another token after the run was created.

The values travel in the job, over the mutual-TLS call to the host, and
nowhere else. The host writes them to an owner-only `secrets.env` in the
job's directory, empty for a job that carries none. The policy it renders
names that file as the CLI's `envFile` secret source, so a declared secret
never resolves from the host's own environment. The CLI then does what it
does on your machine ([What a run enforces](runner.md#what-a-run-enforces)).
It gives each value to the MCP gateway's container and to the tools container
or the declared server's container, and never to the agent's. The file is
deleted as soon as the CLI exits, and so is the gateway's copy if a killed
CLI left one.

### After the run

A secret that is not kept is deleted in the same transaction that closes
the run, and audited `vault.secret_deleted` with the run and the reason
`run-ended`. An hourly sweep deletes one that no run took a day after it
was set, reason `unused`. That day is why `AGENTRY_RUNS_QUEUE_MAX` may be at
most 12 hours. A kept secret stays until the account deletes it. An
account's erasure and its data clear delete every secret it keeps, inside
their own transaction.

### What the record says

The receipt's `capabilities_enforced.secrets` names every declared secret by
name, never a value: the release's own, and each declared MCP server's with
that server. It says where each goes, and that the MCP gateway's container
holds every value it injects. An optional secret the run went without is
named again under `secrets.absent`. A sandbox host with an older CLI still writes `none declared` when only a declared server
declares a secret, although that secret was resolved and injected.

The registry's audit log, which platform staff read, holds three events.
None carries a value:

- `vault.secret_set`: the name, whether it replaced one, and `keep`;
- `vault.secret_deleted`: the name, plus the run and the reason when the
  system deleted it;
- `vault.secret_used`: the name, the run and the host.

The key service keeps its own audit, in which every value is a keyed hash.

### What this does not protect

- **The worker role can open any account's secret.** Each secret is
  encrypted under a key derived for its account, so it does not open under
  another account's. But the worker reads the database and its role may
  decrypt, so its policy limits the operation, not the account. Where the
  api runs apart from the worker, it writes the secrets and cannot decrypt
  them.
- **The value is plaintext for the run's life.** It is in the worker's
  memory at the hand-off and in the job on its way to the host. On the
  sandbox host it is in the environment file and in the containers that use
  it. A tool given a secret can send it anywhere the run's egress allows.
  The contract bounds where a secret goes, not what a tool does with it.
- **The guards on output are partial.** The gateway refuses a tool result
  that looks like a secret, by pattern, not by the declared values.
  Redaction masks the declared values in the receipts, but not a value
  shorter than eight characters or an encoded copy of one
  ([The output folder](runner.md#the-output-folder)).
- **A leaked `secret:write` token** can replace or delete a secret that was
  kept from a token, and add kept secrets under new names. Every later run
  that declares those names uses its values. It can also overwrite a
  secret that is not kept, in the moment between another start's set and
  its create, or while an abandoned start's secret waits for the sweep, and
  the value then reaches that run. It can delete or overwrite a secret
  another start's queued run waits for, and that run fails, refunded. Every
  write names the token in the audit log, and revoking the token ends all
  of it.

## A run's connections

A declared MCP server can sign in by OAuth: a remote server with
`auth: oauth`, or a package server with an `oauth` block. On your own
machine the CLI keeps a **connection** to it for each exact release, in the
OS keychain ([Connections](runner.md#connections)). A hosted run uses the connection the
vault keeps for the account and the release, a different connection from
the local one. Each connection is made once on the vendor's consent screen
and refreshed by Agentry. A run is given an access token alone, never the
refresh token or a client secret.

### Making one

The vault's routes under `/api/v1/x/vault/` are a signed-in session's
alone. No token starts, finishes, lists or removes a connection.

| Route | Does |
|---|---|
| `POST /me/connections` | starts a consent from `{"ref", "server", "return"}` and answers the vendor's address to open in the browser |
| `GET /me/connections/callback` | the vendor's answer; it is taken only into the browser signed in as the account that started the consent, within ten minutes |
| `GET /me/consents/{id}` | what became of a consent: `started`, `exchanging`, `connected` or `failed` |
| `GET /me/connections` | the account's connections by release and server, with when each was made, refreshed and last used, and `broken` when its vendor no longer honours it |
| `DELETE /me/connections/{id}` | Disconnect: the connection goes at once, and its revocation at the vendor is attempted and audited |

A consent at a vendor whose token or revocation endpoint is not on the
deployment's vendor list (`AGENTRY_VAULT_VENDOR_HOSTS`, when it names one)
is refused with `409 vendor-not-allowed`, naming the server and the host.
Such a release runs on your own machine.

### At create

A run of a release whose servers sign in by OAuth is created only when the
caller keeps a working connection to each one for that release: the same
ref and archive digest, never another version's or another account's. A
connection whose vendor refused its last refresh counts as missing. The
run records the servers' keys (`connections`), never a token.

### At the hand-off

The dispatcher, in the worker role, locks the run while it is claimed on
its host and, in the same transaction, before the run's secrets, does this
for each connection:

- locks the connection and opens its refresh token, and any client secret,
  under the account's key;
- refreshes it at the vendor, through the egress guard (and, where the worker has an egress proxy,
  through it);
- keeps the new refresh token, sealed, when the vendor rotates it;
- sets the connection's last refresh and last use;
- writes one `vault.connection_used` audit event, with the server, the
  issuer, the run and the host.

Then the access token goes into the job, with its expiry, the issuer and the
scopes. The host writes it to an owner-only `connections.json` in the job's
directory and runs the CLI with `--connections-file`. The CLI then hands each
server its token as it does on your machine, opens no connection store,
and refreshes nothing. The file is deleted when the CLI exits, and the
tokens are masked in every line the host keeps, as secrets are.

The run fails before any host sees it, with its hold refunded and its error
naming the server, when a connection:

- was removed since the create;
- is refused by its vendor at the refresh, or was made with your own OAuth
  client and that client was removed or replaced since: the connection is
  marked broken (`vault.connection_broken`), even though the run fails, and
  the next run asks you to connect again;
- has a vendor that could not be reached: the connection is kept as it was;
- is at a vendor off the deployment's list.

Whatever a hand-off learned is kept even when it fails the run. A refresh
token a vendor already rotated for another server is not lost.

### During the run, and after

Nothing is refreshed during a run, and the token's life is the vendor's
to choose. A session that outlives it keeps running, and that server's
calls fail with a sentence that names the run's connection and says a new
run is given a fresh token. The receipt's
`capabilities_enforced.mcpServers.connections` names each server, its
issuer and its scopes, and says the run was given an access token alone.

The vault deletes a connection no run has used for 90 days and attempts its
revocation, unless another connection of the account shares the grant. It deletes every connection with the account, and Disconnect
deletes one at once.

### What this does not protect

- **The access token is plaintext for the run's life.** It is in the job,
  in the host's file and in the server's container, and a server given it
  can use it until it expires. A connection's scopes are what the release
  declared and you approved, not less.
- **The worker can open any account's connection.** Each is sealed under a
  key derived for its account, but the worker's role may decrypt under the
  connections key, so its policy limits the operation, not the account.
- **Behind the egress proxy, the address check is not pinned.** The worker
  checks that a vendor's name resolves to public addresses before it asks
  the proxy, and the proxy resolves the name again. The proxy's exact list
  of hosts is what bounds where the request goes.

## A knowledge build

A run of the kind `knowledge_build` runs the CLI's built-in Knowledge
Creator over documents, a brief, or both to make or extend a [knowledge
pack](knowledge.md) in the registry's store, against the platform's model,
for credits. It is created by the same `POST /api/v1/x/runs/` with `kind:
knowledge_build`, the documents as `inputs`, a `brief` (what the pack should
cover and for whom: text of at most 8 KiB after trimming, with no control
characters but line breaks and tabs, kept in the pack as
`sources/brief.md`), optional `repos` and `urls` (sources, below), at least
one of `inputs`, `brief`, `repos` or `urls`, an optional `web` (Search the
web, below), and exactly one of `name` (a new pack of that name; an empty
pack of that name, one a refused build left, is reused), `pack` (the id of
one of the caller's packs) or `continue` (a finished build of the caller's,
whose documents, sources, brief and web choice are copied for the new one,
so it takes no `inputs`, `repos`, `urls`, `brief` or `web` itself). It names
no `ref`, `task` or `intake`. With `org` (an organization's handle) the
build makes or extends that organization's shared pack: only its admins may,
a caller who is not a member gets `404`, one who is not an admin `403`, and
an organization in its decommission hold `409 org-decommissioning`, since
its shared knowledge is read-only then. Membership is read again at the
hand-off and at the output download, as for a run that attaches a shared
pack (above). A token needs `knowledge:read` and `knowledge:write` beside
`run:write`, and downloading a build's output needs `knowledge:read` beside
`run:read`, since the output holds the pack.

A build holds `AGENTRY_RUNS_BUILD_CREDITS` (201) on the payer's row under
its own ledger reasons (`knowledge_build_hold`, then `knowledge_build` and
`knowledge_build_release`, or `knowledge_build_refund`), with caps of its
own: `AGENTRY_RUNS_BUILD_SECONDS_STANDARD` (900 s) and
`AGENTRY_RUNS_BUILD_SECONDS_{PRO,BUSINESS,ENTERPRISE}` (3,600 s),
`AGENTRY_RUNS_BUILD_MAX_TURNS` (300), and as tokens what the hold less the
scan's credit buys at the input rate: 10,000,000 by default. It counts
against one active run per account. It runs only on sandbox hosts Agentry
pushes to: the pack's tree is staged for the host beside the documents, the
host runs `agentry knowledge add` (or `create`) over it and stops the build
when its narrated tokens, priced at the two rates, pass the hold less one
credit. That credit is the pack's scan: when the build finishes, the
registry opens its output for its runner, puts the pack's new tree into the
store if the pack still holds the tree the build was handed — resealed under
the pack's own key, counted against the allocation, and scanned as any
upload is — and settles the tokens plus 1 credit for the scan, never past
the hold. The run's `build` record says what happened: the pack's digest,
pages and bytes when it was `applied`, or a `note` — `nothing` (the build
made no pack), `changed` (the pack took another tree while it ran),
`allocation`, or `deleted`, each settling the tokens spent, or `invalid`
(the output held no valid pack), refunded in full.

**Search the web.** `web: true` lets the Creator search, `false` forbids it,
and with no `web` a new pack with no documents, repositories or addresses
searches and anything else does not; the status route's `knowledgeBuild.web`
states the terms and the words a client shows beside the choice. A build
that searches runs `agentry knowledge … --hosted --web` on the host with a
credential minted for that build alone, as [a hosted
draft](#a-hosted-draft)'s is: its searches go to the registry's search route
and every result and page it reads to the [model-input
routes](model-input.md) before its model reads it, and its `web_read` opens
only an address one of its own searches returned. The registry counts each
call against the build's caps, `AGENTRY_RUNS_BUILD_SEARCHES` (30) searches
and `AGENTRY_RUNS_BUILD_PAGES` (60) pages, and refuses what passes them
(`403`). Each search the provider answered settles at
`AGENTRY_RUNS_DRAFT_SEARCH_CREDITS` (1) inside the build's hold, never past
it. A build without the web is handed no credential. The run's `build.web`
record counts the searches, the pages let through, AI Review's reads and
what it withheld. A page the Creator wrote from the web cites `[src:
web:<url>]` and keeps none of the page's text.

**Pages drawn by scripts.** A build that searches the web is a browser job:
it takes two of a sandbox host's slots and goes only to a host whose health
says `acceptsBrowser`, as [a run with a browser](#a-run-with-a-browser)
does, and its CLI is told to render. Its `web_read` then reads a page whose
text comes from scripts as a headless browser draws it, held to the same
addresses and the same AI Review as a plain read
([pages drawn by scripts](runner.md#knowledge-packs)); each render
counts as one of the build's page reads. The model never drives the
browser. A build is never given the open web that
`AGENTRY_RUNS_BROWSER_PUBLIC_WEB` allows a release, and a build that does
not search never renders.

**A repository or a web address.** With CLI v0.6.147 or later on the sandbox
host, `repos` (at most 10) are git repositories by their https address, with
`@BRANCH`, `@TAG` or `@COMMIT` after it for a ref other than the default
branch, and `urls` (at most 20) are files at web addresses; each is one line
of at most 2 KiB. The create reads them as the CLI will, and refuses one it
would refuse (`422 validation`). On the host the CLI fetches each through a
proxy that reaches public addresses only, as `agentry knowledge … --repo …
--url …` does on a person's computer ([a repository or a web
address](runner.md#knowledge-packs)), within the hosted caps of 10,000 files
and 256 MiB for a repository and 10 MiB for a file, and the Creator reads
what was fetched as documents. A key the person saved for a source's host
under Settings → Encrypted storage is matched at create and handed to the
host as that source's access token, used by the fetch step for that host
alone; the build carries no other source credential. The status route's
`knowledgeBuild.sources` says whether sources are taken (`enabled`) and
`maxRepos` and `maxUrls`. A build's documents and sources are not read by AI
Review before the Creator reads them; the pack it makes is scanned before it
is final.

Refused before a pack is made or anything is held: a token without the
scopes (`403`), a balance that cannot hold the build (`402`), a pack that is
not the caller's (`404 knowledge-not-found`), a name a pack with a tree has
(`409 knowledge-name-taken`), a pack being scanned (`409 knowledge-scanning`)
or whose stored tree could not be read (`409 knowledge-failed`), documents
that with what the pack holds pass its 10 MB (`413 knowledge-too-large`) or
the allocation (`413 knowledge-allocation`), and a deployment with no sandbox
hosts or no knowledge store (`503 knowledge-build-unavailable`). The Creator
is part of the CLI the host runs, so a build runs without a registry scan of
a package; the pack it makes is scanned before it is final.

## A hosted draft

A run of the kind `draft` runs the CLI's built-in Drafter, which turns a
description of a task into a draft of a QuickAgent (the CLI's `agentry
draft`), on a sandbox host against the platform's
model, for credits. It is created by the same `POST /api/v1/x/runs/` with
`kind: draft`, a `description` (at most 24 KiB of text) and up to ten
`hints` (the services or sites it works with, whether it runs on its own or
in a conversation, an example of the output wanted; one line of at most 500
bytes each, blank ones dropped), and optionally `knowledge`, the ids of
packs the Drafter reads first (below). It names no `ref`, and takes no
`task`, `intake` or `inputs`: each is `422`. A token needs `run:write`, and
`knowledge:read` beside it to name packs. The description is the run's
`task`; the hints are in its `draft` record.

**Knowledge in a draft.** The packs are checked as
a run's are ([knowledge attached to a run](#knowledge-attached-to-a-run)):
the caller's own `ready` packs, or their organization's while they are an
active member, at most the run's number of packs. A draft never scans a pack
again, so each must carry a scan record that stands in: Agentry's report
with every stage finished and AI Review configured and failing on none of
its chunks, else `409 knowledge-scan-incomplete` ("Upload the pack again to
have it scanned anew, or draft without it"). The packs, each counted with
its scan record, are at most 10 MB in all (`413 knowledge-too-large`). The
host passes them to `agentry draft --hosted --knowledge`, which withholds
from the Drafter what their scans flagged and names it in the draft's
notes; the draft never ships a pack.

A draft holds `AGENTRY_RUNS_DRAFT_CREDITS` (40) on every tier, and that hold
is the most it costs the account: its model use, its searches at their
price (`AGENTRY_RUNS_DRAFT_SEARCHES`, 10, at
`AGENTRY_RUNS_DRAFT_SEARCH_CREDITS`, 1 each) and AI Review's 1 credit all
settle inside it, under its own ledger reasons (`draft_hold`, then `draft`
and `draft_release`, or `draft_refund`). Its caps are
`AGENTRY_RUNS_DRAFT_SECONDS` (1,800 s), `AGENTRY_RUNS_DRAFT_MAX_TURNS` (300)
and `AGENTRY_RUNS_DRAFT_MAX_TOKENS` (5,000,000). Unlike a build's, the token
cap is not what the hold buys: a draft may use more than it is charged for,
and what it uses past its hold is the platform's cost.
The status route's `draft.tokenCredits` (39, the
hold less AI Review's credit) is the most its model use may cost the
account. It pays under
the same payer rule as a run and counts against one active run per account.
A balance that cannot hold it is `402` with nothing held, and a deployment
with no sandbox hosts is `503 draft-unavailable`.

It runs only on sandbox hosts Agentry pushes to. When a host takes the
draft, the registry mints it a credential for this one draft, keeps only its
digest, and hands it to the host with the job. The host runs `agentry draft
--hosted --output-format json` with the credential in the CLI's
environment beside the platform model's key, as for any run, and no Jev or
search key, and stops the draft when its
narrated tokens, priced at the two rates, pass its token cap's price at the
output rate (200 credits by default, the record's `stopCredits`). That stop
takes nothing from the account; it bounds what the platform absorbs. The
Drafter's web tools send every search result, page and registry answer to
the registry's [model-input routes](model-input.md) with that credential
before the model reads it, and its searches to the registry's search route.
The registry counts each call against the draft's own caps — its searches,
`AGENTRY_RUNS_DRAFT_PAGES` (60) pages, 60 registry answers — and refuses
what passes them (`403`). The credential answers only while its draft is
claimed or running and not asked to stop; every hand-back to the queue and
every close clears it. The CLI writes it into the run's gateway secrets
file for the tools container, where the web tools run; it never enters the
agent's container.

A draft that ran settles its model use (at most its `tokenCredits`), the
searches the provider answered at their price, and 1 credit for AI Review,
however many texts it read, never past the hold. Its record's
`pricedCredits` is what all of that came to before the hold capped it, so
`pricedCredits` less `settledCredits` is what the platform absorbed. A draft
that did not run is refunded in full: one whose description AI Review did
not pass (the CLI's exit 11 at stage `description`, before anything is
searched or read) and one the platform failed. The run's `draft` record
keeps what the calls spent: the searches, the texts scanned and withheld,
the judge's requests (AI Review is 1 credit however many), and the parts of
the settlement. Its output is the sealed `output.tar`, for its runner alone,
holding `draft.json`, the rendered `package/`, the reports and the receipts.

The Drafter is part of the CLI the host runs, like the Knowledge Creator:
a draft runs without a registry scan of a package. What it drafts is not
published by it: a submission of the draft is scanned like any other.

Every draft's record also keeps what its host sealed, and never the
content: `package`, the path, SHA-256 and size of each file under
`package/`, and `proof`, the draft's proof (below). Both come from the
host's summary alone, and only for a package that was sealed whole.

### A hosted revision

A revision is a draft of the next version of a QuickAgent that is already
published (Edit with AI, In Agentry). It is created by the same `POST
/api/v1/x/runs/` with `kind: draft` and `revises`, the QuickAgent's current
published release as `ns/name@version`, and the person's two texts in
place of a description and hints: `instructions`, what to change, and
`problems`, what is wrong with the current version. Each is text of at most
4,000 bytes after trimming, with no control characters except line breaks
and tabs, and at least one must be given. A revision with a `description`,
`hints` or `knowledge` gets `422`, and so does a plain draft with
`instructions` or `problems`.

It is refused, in order:

- `404 not-found` for a release the caller may not revise: a QuickAgent
  they can neither maintain nor publish to, a version that is not its
  current published release, and a missing name, which all get the same
  answer. The core decides the roles, and publishing is enough because the
  desktop's sign-in token publishes but never maintains.
- `403 revise-tier` ("Pro and above") when the payer is on Standard. It is
  judged on the payer's tier, as a knowledge build is, with the `account`,
  its `tier` and `requires` in the problem. A signed-in caller's
  `caller.revise.allowed` in `status` says the same in advance. On
  Standard, a revision runs on the person's own computer with their own
  keys (Agentry Desktop), which this route never sees.

A revision is otherwise a draft. It has the same hold, caps, credential,
admission and settlement, its task reads `Revise ns/name@version.`, and its
record keeps `revises` (the ref and the digest of the release's archive, as
resolved at create) and the two texts. An erasure removes the texts with
the hints. Whatever the release's visibility, its claim mints a release
grant, and the host runs `agentry draft --hosted --revise-ref REF
--revise-registry …/api/v1/x/runs/rel` with the two texts as files. The
release prefix serves the CLI that one release, at the pinned digest, only
while the draft is live. The CLI's AI Review reads the two texts as it
reads a description, and the release's manifest and instruction file as
`input_file` chunks, before the Drafter does. The admission counts those
release scans under a cap of their own, `releaseScans`, at most 24. A
release too large for them stops at that scan and is refunded as a draft
that did not run.

**What publishing it proves.** A draft's proof (`pkg/draftproof`) is two
digests. One is of the manifest, parsed and canonicalised, leaving out what
the Builder sets itself or cannot hold. The other is of the instruction
file's text with LF line breaks and exactly one final newline. The host
computes the proof over `package/` before sealing, and the registry
computes it over the files it receives, so only digests cross. An upload
may name the run it came from in `draftRun`, which Edit with AI's *Publish
this version* sends. That is a claim. At the version's publish scan the
registry asks the deployment whether the submitter ran that draft, whether
the draft succeeded with a sealed package, whether it revised the release
S9 compares against at that release's archive digest, and whether it
recorded the same proof. Only a yes gives the version the source
`drafter-revision` and S9's benefit of the doubt ([trust.md,
S9](trust.md#s9)). Anything else gets the usual S9: an unknown or failed
run, another account's draft, a plain draft, a revision changed in the
Builder, or a registry without this extension. The answer reads the
draft's record alone and never a tier, a balance or the draft's body.

## A hosted Voice Writer run

A run of the kind `voice_build` runs the CLI's built-in Voice Writer
(`agentry/voice-writer`) on a sandbox host against the platform's model,
to write the caller's [Writing Voice](voice.md). It is created by the same
`POST /api/v1/x/runs/` with `kind: voice_build` and an `op`:

- `create`: samples of the person's writing as `inputs` (up to twenty
  files from the input route) and an optional `brief`, how they want to
  sound;
- `improve`: more samples and an optional `brief`, over the current voice;
- `edit`, an AI Edit: a `note` saying what should change, required, and
  optional samples as `inputs` (up to twenty files, under the same caps as
  a `create`'s) that show the change.

Each of the three also takes `urls` (at most 20, each one https line of at
most 2 KiB), web addresses of pages of the person's writing, beside the
samples or instead of them (below). A brief or a note is text of at most 4
KiB. The run takes no `ref`, `task`, `intake`, `description`, `hints`,
`name`, `pack`, `continue`, `org`, `knowledge` or `voice`: each is `422`. A
token needs `voice:read` and `voice:write` beside `run:write`, and
downloading the run's output needs `voice:read` beside `run:read`. An
Improve or an AI Edit of a person with no voice is `409 voice-not-found`.

**Price.** Each of the three costs **20 credits flat**
(`AGENTRY_RUNS_VOICE_CREDITS`), AI Review of what it writes included. The
whole price is held under `voice_build_hold`, then settled whole under
`voice_build` when the run's `VOICE.md` became the person's pending
version, or refunded in full under `voice_build_refund` when no voice came
out, the store refused it, the voice it worked on was deleted before it
started, or the store was off. It is not metered: the host stops it at the
tokens its credits buy at the input rate. It pays under the same payer
rule as a run and counts against one active run per account.

**Standard runs it once a billing cycle.** A payer on Standard starts one
Voice Writer run in each of their anchored billing cycles, whichever of
the three it is; Pro, Promo Pro, Business and Enterprise start any number.
The count is of the cycle's holds that no refund closed, so a run in
flight counts and a refunded one frees the cycle. A second is
`403 voice-build-limit`, with `used`, `max`, `nextAt` (when the cycle
turns) and `requires`, before any input or credit is touched. A signed-in
caller's `caller.voice` (`allowed`, `limited`, `used`, `max`, `nextAt`,
`holdCredits`) says so before a run exists.

**How it runs.** At the hand-off an Improve or an AI Edit is handed the
person's pending version if there is one, else the live one, so an AI Edit
can repair a flagged version; the run's `voiceBuild.from` names its
digest. The host runs `agentry voice create|improve|edit --write …
--current … --max-text-bytes …` over the staged samples, with their decoded
text capped at `AGENTRY_RUNS_VOICE_TEXT_BYTES` (1 MB: past it the Voice
Writer reads the first 1 MB and is told so), and keeps no voice on the
host. On collect the registry opens the sealed output with the runner's
key and proposes the `VOICE.md` to the core's store as the pending version
(source `build`, or `ai-edit` for an AI Edit), where only AI Review makes
it live ([The review](voice.md#the-review)). The run's `voiceBuild` record
says what happened: `op`, `maxTextBytes`, `from`, and `applied` with the
voice's `digest` and `bytes`, or a `note`: `nothing` (no voice came out),
`invalid` (the output held no voice the store takes), `gone` (the voice
it worked on was deleted) or `unavailable` (the store was off).

**Web addresses.** With CLI v0.6.147 or later on the sandbox host, a run
given `urls` is handed a credential minted for it alone, which the registry admits only for AI Review's reads of pages, at
most `AGENTRY_RUNS_VOICE_PAGES` (100) of them, and only while the run is
claimed or running; a run given none holds no credential, and the
credential is cleared when the run closes. On the host the CLI fetches each
address through a proxy to its host, has AI Review read the page's text
through the registry's [model-input routes](model-input.md) with that
credential, and withholds a page AI Review flags or cannot scan, naming it.
A run given addresses is a browser job of two slots, as a knowledge build
that searches is, so a page drawn by scripts is read by the Voice Writer's
`web_read`, which opens only the addresses given and renders the page in a
headless browser, AI Review reading the rendered text first; each render is
one page read against the cap ([samples from web
addresses](runner.md#a-writing-voice)). That review is inside the run's flat
20 credits. The run's `voiceBuild` record counts the pages read, what AI
Review read and what it withheld.

Its caps are `AGENTRY_RUNS_VOICE_SECONDS` (1,800 s) and
`AGENTRY_RUNS_VOICE_MAX_TURNS` (300). `voiceBuild` in `GET
/api/v1/x/runs/status` states its terms to anyone: `enabled`, `credits`,
`caps`, `maxInputs`, `maxTextBytes`, `maxBriefBytes`, `urls` (`enabled`,
`max` 20 and `maxPages`), `standardPerCycle`,
`aiReviewCredits` (what the review of a voice saved by hand costs, 1) and
`attach`. A deployment with no sandbox hosts or no voice store answers
`503 voice-build-unavailable`. The Voice Writer is part of the CLI the host
runs, so the run needs no registry scan of a package; what it writes is
reviewed before it is live.

## A hosted session

A **hosted session** is a hosted run of a release's interactive mode: the
runner talks to the agent while it runs on a sandbox host, as they would in
a [terminal session](runner.md#run-modes). It is created like a run, with
`"mode": "interactive"`, and runs exactly as a pushed run does: the same
release verification, the same compiled plan bar the harness's own
arguments and the session block, the same sandbox under `runsc`, egress
proxy and gateway, and a declared secret reaches the tools container alone.
A message cannot widen what the release declares. The CLI's policy decides
every permission request, as it does on a person's own machine: a tool the
gateway serves is granted and anything else denied, and no request reaches
the person. The host drives the CLI
through its [session protocol](runner.md#driving-a-session-from-a-program).

On the product a session is started from the site's guided run setup
(**Talk to it**) and held on the run's page as a chat, or from the desktop
app's run panel (**Talk to it In Agentry**), whose chat is the one a local
session uses. A script drives it through the routes below.

**Who may start one.** A payer on Pro, Business or Enterprise; on Standard
the create is `403 session-tier`. The tier is the payer's, so a Standard
member of an organization starts one on the organization's tier. A session
already running is not stopped by a later change of tier. A session runs only
where the deployment pushes runs to sandbox hosts, sessions are turned on,
and a host is taking runs.

**Following it.** `GET /api/v1/x/runs/{id}/session` is server-sent events:

- `state`: the run's content-free state (`status`, `startedAt`,
  `finishedAt`, `outcome`, `error`) and its session record, whenever
  either changes;
- `frame`: one display event, its `id` the frame's sequence number from 1.
  The kinds are `user_turn` (the CLI's own notices marked `synthetic`),
  `assistant_text` (a streamed chunk), `assistant_turn` (the whole reply),
  `tool_call` and `permission_denied` (by the tool's name), `input_added`
  (by the file's name), `session_end` (with the reason) and `error`,
  which carries a fixed `class` and never text the harness wrote. The
  host's `usage` frames, the session's token counts, are taken in order
  and not sent ([in credits, never in tokens](#in-credits-never-in-tokens));
- `dropped`: the host's memory guard (16 MiB of frames for one session) let
  go of frames before `before`; they are in the transcript only;
- a comment every 20 seconds, which keeps a quiet stream open through
  proxies;
- `done` once the session is over; `timeout` after thirty minutes, from
  which the client reconnects with `Last-Event-ID` or `?after=` and the host
  replays what it still holds; `error` (`{"class":"key"}` or
  `{"class":"frame"}`) when the stream cannot show this session's frames,
  which ends that stream but not the session.

**Talking to it.** `POST …/session/turns` takes `{"text": …}`: one message
of at most 16 KiB, with no control character but a newline or a tab.
`POST …/session/files` takes `{"input": …}`, one of the caller's unclaimed
uploads from `POST /api/v1/x/runs/inputs`, named by one file name; it is held to the
run's input caps together with the run's other inputs and the files already
added, staged sealed under a key the turn carries and handed to the host
as a five-minute presigned URL ([at rest](#a-runs-data-at-rest)), and
deleted from the registry once the host has it. The agent finds it under `/inputs`. The
CLI tells the agent about the file in a notice: a turn of its own when the
session is idle, or with the next message otherwise. `POST …/session/end`
takes `{"finish": true}` (ask for the final result, then end) or `false`
(end now, without one). Each is answered `202` once the host has it, or:

| Answer | Why |
|---|---|
| `409 session-starting` | the host has not started the session yet; a stop before then is a cancel |
| `409 session-busy` | the agent is still answering the last message |
| `409 file-exists` | a file of that name was already added |
| `409 session-ended` | the session is over |
| `413 too-large` | the file would pass the run's input caps |
| `422 validation` | a text the host would not take, or an input that is not one of the caller's uploads or not one file name |
| `502 host-unreachable` | the sandbox host did not answer; send it again |

**Its bounds.** There is no turn, token or tool-call cap. A session closes
after **five minutes** with no message, reply, tool call or streamed text
(a release's `interactive.idleTimeoutSeconds` may ask for less, never
more). Its only wall is the life of the presigned URL its output is posted
through: seven days, less the host's ten minutes for teardown and a minute
for the hand-off. It ends on
finish, stop, the idle close, that wall, or a minute its payer cannot pay.

**What it costs.** A session holds nothing. Its **server time** is a second
price beside its tokens: the first **ten minutes** of running are free, and
each minute after costs **50 credits**, pulled from the payer's balance as
the minute starts, once per minute however many registry replicas see it,
each a `session_time` line in the ledger and a `charge` event on the run.
A minute the balance cannot cover stops the session without a final
result, and it closes as `budget` with the error `out of credits`. Its
**tokens** settle once, when it closes, at the two rates above, taking at
most what the balance holds and never below zero; any rest is recorded as
`tokensUnpaid` and is the platform's cost. A session starts only on a
balance of at least **50 credits**, the price of its first paid minute
(`402 credits-exhausted` otherwise). An output the platform could not
deliver keeps the minutes, which paid for a host that ran, and settles no
tokens. An unmetered organization's minutes are counted at 0, with a
`charge` event and no ledger line.

The run carries a content-free `session` record: the terms it was created
on (`freeMinutes`, `creditsPerMinute`, so a change of configuration never
reprices a running session), `paidThrough` (the last minute settled,
counting the free ones), `timeCredits`, `tokenCredits`, `tokensUnpaid`,
`outOfCredits`, `filesAdded`, `bytesAdded` and `idleSeconds`.
`settledCredits` is the time and the tokens together.

**Who may watch or type into it.** Its runner alone. Everyone else gets
`404`, as for a run that does not exist: another account, a fellow member
of the organization that pays for it, platform staff, a token without both
`run:read` and `run:write`, and anyone on a run that is not a session. A
session that attached an organization's shared knowledge answers its
runner only while they are still a member. Once it has finished, the
run's record and output are read as any run's are.

**What is kept.** The clients show this sentence beside the chat:

> Transport encrypted by the user key, messages not stored; the transcript
> comes back only in your sealed output.

**Agentry holds each person's key**, sealed, so that it can open their
output for them. The sentence therefore does not claim that the platform
cannot read a session. In full, it means:

- Each frame is sealed on the sandbox host to the runner's own encryption
  certificate, the one a pushed run's `output.tar` is sealed to, with the
  run, its sequence number and whether it is the last bound in.
  The registry opens it with the runner's key in memory, inside the
  runner's own request, and writes it to that response alone. A frame for
  another run, reordered or replayed, does not open.
- The host keeps the sealed frames in memory for the session's life and
  drops them once it has closed, when its last frame is read or at most 25
  seconds after. The registry writes no turn, reply or frame
  to a table, a run event, an object or a log line; the run's events are
  its statuses, its minute charges and its end. The one copy of the
  conversation kept is `transcript.md` in the receipts of the sealed output.
- A message is not sealed. It travels to the host over the runner's sign-in
  and Agentry's mutually authenticated channel, as a run's task and files
  do, and is stored nowhere but that transcript.

The sealing means a frame opens only inside its runner's own request; that
nothing is written on the way is how the registry, the site and the edge are
built, and the registry's tests check it. Neither keeps a session's
conversation from Agentry, which can open it as it opens an output.

## The execution plane

Agentry pushes each run to a **sandbox host**: a machine that runs
`secureagentry-runhost`, a small service beside a docker daemon that takes
typed jobs over mutually authenticated TLS and runs the installed `agentry`
CLI for each one, as a subprocess with typed arguments and a minimal
environment. The registry is the host's only client. The host reaches
nothing of Agentry's but its public origin: runhost to enrol, and the CLI to
sign in and to resolve and install each job's release.

### The push path

The push path runs when the server has both [Agentry's
CA](#agentrys-ca-and-enrolment) and the runs store, a pair of buckets of its
own (`AGENTRY_RUNS_STORE_*`). A runs store without the CA stops the server
at start-up; with no store, nothing is pushed. Every
`AGENTRY_RUNS_DISPATCH_EVERY` (5 s) the dispatcher, in the worker role:

1. calls each enrolled host that is not retired on its health call, and
   believes the answer only for that host's name, through the CA's pinned
   `hosts` intermediate;
2. renews a host's certificate that ends within
   `AGENTRY_RUNS_HOST_RENEW_BEFORE` (`240h`), and pushes the hosts'
   settings to a host that holds other ones (both below);
3. polls each run in flight, and passes a cancel on;
4. collects each finished run: it confirms the output from the object's
   size and header, never its body, keeps the receipt from the host's
   summary, settles the credits as for any run (never above the hold), and
   deletes what was staged for the run;
5. hands the oldest queued run to a host with a free slot.

The hand-off copies the run's task and inputs into the input bucket, under
the run's id, each sealed under a fresh key that only the job carries
([at rest](#a-runs-data-at-rest)), and the job carries a presigned GET for each, valid for twenty
minutes, and one presigned POST for the output, whose policy fixes the
object's key and caps its size and which is valid for the run's time cap
plus thirty minutes. The job also carries the runner's encryption
certificate, a private release's grant, and the values of the secrets a run
declares ([at the hand-off](#at-the-hand-off)). It carries no command, no
host path and no image. So a host holds no bucket credential: what it may
fetch, and the one place it may write, are the job's URLs.

A host that is full or failing leaves the run queued, and what was staged
for it is deleted. A host that refuses the job as malformed closes the run as
`error`, refunded. A run whose output the platform could not seal, upload or
confirm closes as `error` with nothing charged, whatever the CLI did.

### On the host

runhost answers on one port (`:8443` by default), over TLS 1.3 only, and
only to Agentry's control client: a certificate for client authentication
named `agentry-control` that chains to the root through exactly the `hosts`
intermediate the host pinned when it enrolled. The server makes that
certificate in its memory, for thirty days, and never stores it. The calls
are a job's start, read and cancel; a hosted session's turns and frames; the
host's health; the two halves of a certificate renewal; and the settings
push.

A job is staged under the host's home at `0700`, and the host renders one
policy per job from the CLI's own defaults: the platform's model, with its
endpoint as the egress proxy's only allowed host and its key named by an
environment variable and never written; the run's caps as the budgets; an
`envFile` secret source naming the job's own `secrets.env`, which holds the
values the job carried and is deleted with the job; and
`docker.runtime: runsc`. A cancel is SIGINT, then SIGKILL. A host runs
`AGENTRY_RUNHOST_CAPACITY` jobs at once, one by default.

What this arrangement gives a run is the isolation the
[Runner reference](runner.md) describes, plus the runtime: its containers are
created under gVisor's `runsc`, and the receipt names which were and which
were not ([the `docker.runtime` knob](runner.md#the-oci-runtime-dockerruntime)).
A sandbox host's runhost sets two more of the policy's runtime settings:
`AGENTRY_RUNHOST_RESOLVERS` becomes `docker.resolvers`, the host's own name
servers, through which the llm-proxy, the MCP server install proxy, the
relays and the Drafter's web tools resolve under `runsc`; and
`AGENTRY_RUNHOST_GATEWAY_RUNTIME` becomes `docker.gatewayRuntime`, a second
registration of `runsc` with `--host-uds=open` (`runsc-uds` on Agentry's
hosts), under which the MCP gateway reaches its run's docker filter. runhost
refuses to start when the daemon lacks either runtime, or when the gateway's
is not `runsc`'s own binary with that flag. With both set, no container of a
hosted run is on the daemon's default runtime. It is
not a machine per run. A daemon shared with anything else is a kernel shared
with the run's sandbox, and that is a property of the deployment, not of the
receipt.

### The host's settings

A host can start with nothing secret but its enrolment token. Until the
registry pushes its settings it reports itself unconfigured and takes no
job. The server holds them as `AGENTRY_RUNS_HOST_REGISTRY_TOKEN` (a registry
token with `agent:read`, which the CLI installs releases with),
`_MODEL`, `_MODEL_BASE_URL` and `_MODEL_API_KEY`, all set or none, with
`AGENTRY_RUNS_HOST_MODEL_PROVIDER` (`openai` when unset), and optionally
`AGENTRY_RUNS_HOST_HYBRID_API_KEY`, the platform's Hybrid Analysis key,
which is refused when it is set alone. On each pass they go to every host
whose held settings differ. The host proves the token with an
`agentry login` before it changes anything, keeps the settings `0600` beside
its key, and gives them to the next job, never to one in flight. The model
key reaches the CLI only under the provider's own variable name, and the
Hybrid Analysis key only as `HYBRID_API_KEY`; both are removed from every
line that leaves the host. Each push is audited as
`runs.host_settings_pushed` with a digest of the values, never a value. A key
changed in the server's environment reaches every host on the next pass,
with no restart of the host. A host can instead be configured from its own environment
(`AGENTRY_RUNHOST_REGISTRY_TOKEN`, `_MODEL_*`), and the first push replaces
that.

### Agentry's CA and enrolment

Agentry runs a certificate authority of its own. Its **root** is offline:
the operator makes it with `secureagentry-ca init` on a machine of their
own, keeps its key there with their own backup, and gives it to no server.
The root signs two intermediates, each valid for five years: **`hosts`**,
which certifies each sandbox host's 30-day TLS server certificate,
Agentry's control client and the server certificate of one of Agentry's own
cluster services, such as OpenBao's (`secureagentry-ca issue-server`), and
**`users`**, which certifies each person's
one-year X25519 encryption certificate (and each organization's, for its
shared knowledge packs). The server holds both intermediates' keys sealed
with AES-256-GCM under `AGENTRY_RUNS_CA_MASTER_KEY`, a key of the CA's own,
beside `AGENTRY_RUNS_CA_BUNDLE` (the root's certificate and the sealed
intermediates). It needs both or neither. A leaked or expiring
intermediate is signed again from the root with `secureagentry-ca reissue`.

Where the vault is configured, as on Agentry's own deployment, every
holder's private key is sealed by the vault, not by the CA's master key:
OpenBao's Transit key `hosted-keys`, derived, with `user:<account id>` or
`org:<organization id>` as the context and the certificate's serial bound in
as associated data. Neither the CA's master key nor the database, alone or
together, opens one, and every open is a Transit decrypt that OpenBao's
audit records with the role that asked. Both the api and the worker may open
a key under it ([OpenBao](self-hosting.md#what-openbao-must-carry)). A key
sealed before the vault did is moved by a seal pass, `userkeys.seal`, which
runs every minute in the worker until none is left. A deployment without the
vault seals the keys under the CA's master key instead, and then the master
key with the database does open them.

A host enrols itself, once:

1. Platform staff mint a one-use token for the host's name and the address
   Agentry will reach it at, from a signed-in session: `agye_`, valid for
   24 hours, stored as its digest, audited as `runs.host_enrolment_minted`.
2. The host makes its own key, which never leaves it, and posts a
   certificate request with the token to `POST
   /api/v1/x/runs/hosts/enrol`. `secureagentry-runhost enrol` reads the
   token on stdin, never from its command line.
3. It gets a 30-day certificate for server authentication for the
   token's host name, with the `hosts` chain and the `users` intermediate.
   A request that names anything else, or carries an IP address, an email
   address or a URI, is `422` and leaves the token unspent. The token is
   spent in the transaction that records the host (`runs.host_enrolled`). A
   spent, revoked, expired or unknown token is `401`.

Renewal is pushed. Within the renewal window the dispatcher asks the host
for a certificate request for a fresh key, and installs the new certificate
over the same channel (`runs.host_renewed`). A renewal never changes the
pin: a host refuses a chain through another `hosts` intermediate or another
root, so re-issuing `hosts` after a leak means enrolling every host again.
Staff can revoke a token not yet used, and retire a host, except the last
one taking runs (`409 last-host`). A host the fleet made is drained: it is
handed nothing new, its runs finish on it, and the fleet then retires and
destroys it. A host made by hand is retired at once: from the next pass
Agentry calls it no more, and a run it held is closed and refunded once the
stale window passes. A retired name is never enrolled again, so a rebuilt
machine comes back under a new name.

### The output, encrypted to the person who ran it

A pushed run has one output, `output.tar`: the tar of the run's
`result.json`, `reports/`, `receipts/` and `outputs/`, regular files only.
The host encrypts it before it leaves the host, with HPKE (X25519,
HKDF-SHA256, AES-256-GCM) to the runner's encryption certificate, once it
has checked that certificate's chain to the `users` intermediate, and posts
it through the job's presigned POST. Each 64 KiB frame is bound to the
header, to its place and to whether it is the last, and the encryption is
bound to the run, so an object sealed for one run does not open as another
run's. No plaintext output rests in a bucket. The dispatcher refuses an
object that is missing, too large, not a sealed output, sealed for another
run, or sealed to a certificate other than the one it handed out; a refused
object is deleted, and the run closes as `error`, refunded.

The certificate is the runner's own, even when an organization's pool pays,
and it is made the first time they start a hosted run. Nobody sees or
handles it: Agentry keeps its private key sealed by the vault's
`hosted-keys` and opens it only inside the registry, with a vault call
recorded in OpenBao's audit, to decrypt that person's own download as it
streams. The download answers the runner alone; platform staff and every
other account get `404`. The registry opens two built-ins' outputs on the runner's
behalf: a knowledge build's, to put the pack back in the knowledge store,
and a Voice Writer run's, to read its `VOICE.md`.

The keys that open your knowledge packs, your Writing Voice and your runs'
results are sealed by a key that never leaves our vault. Each time one is
opened it is a vault call, recorded in its audit log and allowed only to
the parts of Agentry that need it. Agentry runs that vault, so this is not
end-to-end encryption. It keeps plaintext from resting in a bucket, an
object from standing in another run's place, and a download from reaching
another account.

**What erasure does.** Deleting a sealed key destroys it, and every output
encrypted to it can no longer be opened from the live database. The key
remains in the database's backups until they age out (on Agentry's
deployment, two days of point-in-time history and thirty nightly copies),
and a restore of one would open those outputs again for as long as the
outputs themselves are kept: with the vault's key, or, for a backup taken
before the vault sealed the keys, with the CA's master key. A person's keys
are destroyed when their account is erased or their data is cleared, and an
organization's when it is erased. The runs sweep is the backstop for a
destruction that did not complete. It also removes an expired key last used
longer ago than the runs' retention, unless a knowledge pack's key is
wrapped to it. A finished run of an erased account is deleted within a
minute ([retention](#retention)).

### No log

A pushed run keeps no log. The host discards the CLI's stderr, and the run's
events are its status changes (and a hosted session's charges). The host
reports a summary: the status, the exit class and code, the usage, the wall
time, the output's size, and as the receipt the runner's parts of the CLI's
envelope, never its result or its error text. It keeps that summary for a
day, in memory. runhost's own service log records each job's id, release,
status and the step a failure stopped in, and nothing the run wrote. A
presigned URL is a credential, and the host never logs one. A hosted
session's chat frames are sealed one by one to the runner and held in the
host's memory, within a bounded buffer, for the session's life; they are
dropped once the session has ended and its reader has the last one
([a hosted session](#a-hosted-session)).

### What the person sees

That the run was done; whether it passed; the credits it held and settled;
its receipt; and its output, decrypted for them on download (the site reads
it in their browser). Nothing of the encryption is asked of them or shown to
them.

### Where it runs

A deployment chooses where its runs happen. The sandbox hosts and the runs
buckets sit in the region and network the operator gives them, and the hosts'
model is the one [the host's settings](#the-hosts-settings) name. A run and
its output are deleted after the [retention](#retention) period, and every
output is encrypted to the person who ran it. A region per organization is
not offered. The hosts belong in a network of their own that shares no route
with the registry's: [a sandbox host of your
own](self-hosting.md#sandbox-hosts-for-hosted-runs) lists the rules.
[Where hosted runs run](https://docs.secureagentry.net/agentry/hosted-runs/#where-hosted-runs-run)
says where SecureAgentry's own runs sit.

## Retention

A run and its artefacts are deleted thirty days after the run was created
(`AGENTRY_RUNS_RETENTION`, `720h`), and, once the run has finished, within a
minute of the account being erased (the runs sweep deletes a closed run of an
erased account). Uploaded inputs that no run claims are swept after a day. Runs, uploads and
schedules written before their data was sealed at rest are sealed in place
by the worker's seal passes (`runs.seal`, `schedules.seal`, a batch a
minute), not left to expire; what a pass replaces is deleted. Download
anything you want to keep before then; nothing is archived elsewhere. A
pushed run's output also stops opening once the key it was encrypted to is
destroyed ([what erasure does](#the-output-encrypted-to-the-person-who-ran-it)).

## The deployment's configuration

| Variable | Default | What |
|---|---|---|
| `AGENTRY_RUNS_CAPS_STANDARD` | `300,20,500000` | the Standard tier's seconds, turns, tokens |
| `AGENTRY_RUNS_CAPS_PRO` | `900,60,5000000` | the Pro tier's seconds, turns, tokens |
| `AGENTRY_RUNS_CAPS_BUSINESS` | Pro's | the Business tier's seconds, turns, tokens |
| `AGENTRY_RUNS_CAPS_ENTERPRISE` | Pro's | the Enterprise tier's seconds, turns, tokens |
| `AGENTRY_RUNS_INPUT_TOKENS_PER_CREDIT` | `50000` | the input tokens a credit buys |
| `AGENTRY_RUNS_OUTPUT_TOKENS_PER_CREDIT` | `25000` | the output tokens a credit buys; a run's hold is its token cap at this rate |
| `AGENTRY_RUNS_BUILD_CREDITS` | `201` | what a knowledge build holds and the most it costs, its scan's 1 credit included; the rest buys its token cap at the input rate |
| `AGENTRY_RUNS_BUILD_SECONDS_STANDARD` | `900` | a knowledge build's wall time on Standard |
| `AGENTRY_RUNS_BUILD_SECONDS_{PRO,BUSINESS,ENTERPRISE}` | `3600` | a knowledge build's wall time on the tiers above |
| `AGENTRY_RUNS_BUILD_MAX_TURNS` | `300` | a knowledge build's turn cap |
| `AGENTRY_RUNS_BUILD_SEARCHES` | `30` | the web searches the registry brokers for one knowledge build |
| `AGENTRY_RUNS_BUILD_PAGES` | `60` | the pages AI Review reads for one knowledge build |
| `AGENTRY_RUNS_DRAFT_CREDITS` | `40` | what a hosted draft holds, and the most it costs the account |
| `AGENTRY_RUNS_DRAFT_MAX_TOKENS` | `5000000` | a hosted draft's token cap; the host stops it at this cap's price at the output rate, and what it uses past its hold is the platform's |
| `AGENTRY_RUNS_DRAFT_SEARCHES` | `10` | the web searches the registry brokers for one draft |
| `AGENTRY_RUNS_DRAFT_SEARCH_CREDITS` | `1` | what one search costs a draft |
| `AGENTRY_RUNS_DRAFT_PAGES` | `60` | the pages AI Review reads for one draft |
| `AGENTRY_RUNS_DRAFT_SECONDS` | `1800` | a draft's wall time, on every tier |
| `AGENTRY_RUNS_DRAFT_MAX_TURNS` | `300` | a draft's turn cap |
| `AGENTRY_RUNS_VOICE_CREDITS` | `20` | what a Voice Writer run costs, flat, AI Review included |
| `AGENTRY_RUNS_VOICE_TEXT_BYTES` | `1048576` | the cap on a Voice Writer run's samples' decoded text |
| `AGENTRY_RUNS_VOICE_SECONDS` | `1800` | a Voice Writer run's wall time, on every tier |
| `AGENTRY_RUNS_VOICE_MAX_TURNS` | `300` | a Voice Writer run's turn cap |
| `AGENTRY_RUNS_VOICE_PAGES` | `100` | AI Review's page reads for one Voice Writer run given web addresses: each page before the run, a long page in several pieces, and each page drawn by scripts that its `web_read` renders |
| `AGENTRY_RUNS_QUEUE_MAX` | `1h` | how long a run may wait for a host before it is cancelled and refunded; at most `12h`, half the day a secret held for one run waits for it |
| `AGENTRY_RUNS_STALE` | `10m` | how long a run's sandbox host may be silent before the run is closed as `error` and refunded |
| `AGENTRY_RUNS_TASK_MAX_BYTES` | `65536` | the task text's cap |
| `AGENTRY_RUNS_INPUT_MAX_FILES` | `20` | input files per run |
| `AGENTRY_RUNS_INPUT_MAX_BYTES` | `10485760` | one input file's cap |
| `AGENTRY_RUNS_OUTPUT_MAX_BYTES` | `52428800` | all of a run's artefacts together |
| `AGENTRY_RUNS_UNCLAIMED_INPUTS_MAX` | `100` | the uploads no run has claimed that one account may hold |
| `AGENTRY_RUNS_UNCLAIMED_INPUT_BYTES_MAX` | `268435456` | the bytes of those uploads; past either, an upload is `413 unclaimed-inputs` |
| `AGENTRY_RUNS_RETENTION` | `720h` | how long a run and its artefacts are kept |
| `AGENTRY_RUNS_CA_MASTER_KEY` | none | the 32-byte key the CA's intermediates and every holder's private key are sealed under (`master.key` from `secureagentry-ca init`); with the bundle, both or neither |
| `AGENTRY_RUNS_CA_BUNDLE` | none | the root's certificate and the two intermediates, their keys sealed (`bundle.b64`) |
| `AGENTRY_RUNS_STORE_ENDPOINT` | none | the runs store's S3 endpoint; set, the push path runs, and it needs the CA |
| `AGENTRY_RUNS_STORE_ACCESS_KEY`, `AGENTRY_RUNS_STORE_SECRET_KEY` | none | the runs store's keys, required with an endpoint |
| `AGENTRY_RUNS_STORE_REGION` | `us-east-1` | its region |
| `AGENTRY_RUNS_STORE_INPUT_BUCKET` | `runs-input` | where a run's task and inputs are staged, sealed, at the hand-off |
| `AGENTRY_RUNS_STORE_OUTPUT_BUCKET` | `runs-output` | where a host posts the sealed output; must differ from the input bucket |
| `AGENTRY_RUNS_STORE_PATH_STYLE` | `true` | path-style bucket addressing |
| `AGENTRY_RUNS_STORE_CREATE_BUCKETS` | `false` | make the two buckets at start-up when they are missing, for a development store; any other deployment makes its buckets itself |
| `AGENTRY_RUNS_DISPATCH_EVERY` | `5s` | how often the dispatcher calls the hosts, hands out queued runs and collects finished ones |
| `AGENTRY_RUNS_HOST_RENEW_BEFORE` | `240h` | how long before a host's certificate ends Agentry pushes it a new one |
| `AGENTRY_RUNS_HOST_REGISTRY_TOKEN`, `AGENTRY_RUNS_HOST_MODEL`, `AGENTRY_RUNS_HOST_MODEL_BASE_URL`, `AGENTRY_RUNS_HOST_MODEL_API_KEY` | none | the settings pushed to every host ([the host's settings](#the-hosts-settings)), all or none; none pushes nothing |
| `AGENTRY_RUNS_HOST_MODEL_PROVIDER` | `openai` | the model's provider, pushed with those settings |
| `AGENTRY_RUNS_HOST_HYBRID_API_KEY` | none | the platform's Hybrid Analysis key, pushed with those settings and refused without them |
| `AGENTRY_RUNS_SESSIONS` | off | whether this deployment runs [hosted sessions](#a-hosted-session); they also need sandbox hosts |
| `AGENTRY_RUNS_SESSION_FREE_MINUTES` | `10` | a session's free minutes of server time |
| `AGENTRY_RUNS_SESSION_MINUTE_CREDITS` | `50` | what each minute after the free ones costs; must be positive |
| `AGENTRY_RUNS_SESSION_MIN_CREDITS` | `50` | the balance a metered payer needs to start a session |

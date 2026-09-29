# Hosted runs

A hosted run is `agentry run` on the platform's machine instead of yours.
An account asks the registry to run a published release, the registry queues
it and holds credits for it, a worker on a sandbox host runs the CLI against
it, and the account watches the log and reads the outcome, the receipt and
the outputs. The release, the compiled plan, the gateway and the receipts are
the ones the [Runner reference](runner.md) describes; what differs is who
owns the docker daemon, what bounds the run, and that it costs credits.

Hosted runs are not part of this repository's server. They are an extension a
deployment mounts (`internal/runs` in the closed enterprise build): the routes
sit under `/api/v1/x/runs/` and `GET /api/v1/meta` lists the extension where
one is loaded. A registry built from this repository has none, and a token
carrying only `run:read` and `run:write` is refused there exactly as a token
without the right scope is anywhere else
([API conventions](api-conventions.md#personal-access-tokens-and-their-scopes)).
The secrets a run declares are kept by a second extension, the vault
(`/api/v1/x/vault/`), which returns no value on any route. `secret:write` is
the scope it is to admit a token by to set and delete the account's secrets
(agentry-enterprise#251); listing them stays a signed-in session's.
[A run's secrets](#a-runs-secrets) says how a run gets them.

`GET /api/v1/x/runs/status` answers anyone: whether this deployment can take
runs at all (it needs a database, a credit ledger and an object store), how
many workers were seen within the stale window, and how many runs are queued.
It also answers the price list, to anyone, since it is the deployment's
configuration and not a secret: `inputTokensPerCredit` and
`outputTokensPerCredit`, every tier's caps and hold under `tiers` (each with
the `build` caps and hold of a [knowledge build](#a-knowledge-build)), and
`knowledgeBuild` — whether a build can run here, what it holds, and the
pack scan's credit — and `draft`, the terms of a [hosted
draft](#a-hosted-draft). A signed-in caller also gets `caller` — the tier a
run of theirs is held at, `account` (whose row it is held on: their own, or
the organization whose pool pays for their runs), that tier's caps, the
credits a run holds, the two rates, the tier's `build` and the `draft` hold —
so a client can state the cost, and whose credits it is, before any run
exists.

## Who may do what

Three credentials reach these routes and never overlap.

An **account** acts through a browser session or a personal access token
carrying `run:read` (list, read, events, outputs) or `run:write` (create,
input upload, cancel), and reaches only its own runs. Another account's run,
and another account's artefact, is `404` — a fellow member of the
organization whose pool paid for the run included: the pool is shared, the
run is not.

| Route | Credential |
|---|---|
| `GET /api/v1/x/runs/status` | anyone; `caller` is added for a signed-in one |
| `POST /api/v1/x/runs/` | session or PAT with `run:write` |
| `GET /api/v1/x/runs/` | session or PAT with `run:read` — the newest fifty |
| `POST /api/v1/x/runs/inputs?name=` | session or PAT with `run:write` |
| `GET /api/v1/x/runs/{id}` | session or PAT with `run:read` (platform staff read any) |
| `GET /api/v1/x/runs/{id}/events` | session or PAT with `run:read` |
| `GET /api/v1/x/runs/{id}/outputs/{name}` | session or PAT with `run:read` |
| `POST /api/v1/x/runs/{id}/cancel` | session or PAT with `run:write` |
| `POST /api/v1/x/runs/claim` | worker token |
| `POST /api/v1/x/runs/{id}/events` | worker token, the run's holder |
| `POST /api/v1/x/runs/{id}/artefacts/{name}` | worker token, the run's holder |
| `GET /api/v1/x/runs/{id}/inputs/{name}` | worker token, the run's holder |
| `POST /api/v1/x/runs/{id}/finish` | worker token, the run's holder |
| `GET`/`POST /api/v1/x/runs/staff/workers` | platform staff, session only |
| `POST /api/v1/x/runs/staff/workers/{worker}/revoke` | platform staff, session only |

The **worker token** is the execution plane's credential: `agyw_` and 32
random bytes, minted by platform staff from a session (a staff PAT is `403`,
as with the core's own platform actions), stored as a SHA-256 digest, and
audited as `runs.worker_registered` and `runs.worker_revoked`. It travels in
its own header, **`X-Agentry-Worker-Token`**, never as an `Authorization`
bearer — the core's principal middleware refuses any bearer that is not a
PAT before an extension sees the request, and a worker's credential and a
person's must not overlap.

What that token can do is the five worker routes above: claim the oldest
queued run, and — for the runs that worker holds and no others — report event
batches and the `running` status, upload artefacts, fetch the run's inputs,
and finish the run with the runner's envelope. It reads nothing of an
account's — no run it does not hold, no list, no artefact of another run —
and it is not a principal, so on an account or staff route it is `401`. A
session or a PAT on a worker route is `403`, with or without a worker token
beside it. Revoking a worker stops it at its next claim — the token is
unknown from then on — and the runs it was holding stop being reported, so
the sweep closes them as `error` and refunds them once the stale window
passes.

## Creating a run

`POST /api/v1/x/runs/` takes a `ref` (`ns/name@version`, or `ns/name` for
the latest published release), the `task` text the harness receives, the
release's `intake` answers as a JSON object, and up to twenty `inputs` — ids
from `POST /api/v1/x/runs/inputs?name=<relative name>`, which stores one file
each and sweeps unclaimed uploads after a day. It may also name up to five
knowledge packs by id in `knowledge`, for the run to search
([below](#knowledge-attached-to-a-run)). The response is the run:
its resolved ref and archive digest, its caps, the credits held and `payer`
— the handle whose row holds them — its queue position, and `expiresAt`.

The ref must name a release the caller may read, as the registry's own agent
read decides it: a public release is anyone's; a private one needs `read` on
the agent — the namespace's owner, an admin or member of the organization
whose namespace it is, or a grant on the agent — and, on a personal access
token, the `agent:read` scope beside `run:write`. The agents of an
organization that is suspended are absent to everyone, public or not.

The mode is `autonomous`. An interactive session is a conversation with a
terminal on the other end; the hosted run has none.

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

A run is created with the caps of the payer's tier, and the worker gives
them to the CLI as its `--timeout` and `--max-turns`.

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
They replaced a single tokens-per-credit rate; a deployment that still sets
`AGENTRY_RUNS_TOKENS_PER_CREDIT` is stopped at start-up with a message naming
the two, as is one that sets a zero rate, an empty cap or a zero timeout,
rather than running with a price it did not mean. `GET /api/v1/x/runs/status`
reports the live values.

## Credits: a hold, then a settlement or a refund

Nothing is debited before a run. Creating one **holds**
`ceil(maxTokens ÷ outputTokensPerCredit)` credits on the payer's row — the
tier's token cap priced at the output rate, the dearer one, which bounds any
mix of input and output within the cap: 20 for Standard and 200 for Pro,
Business and Enterprise — in the same transaction as the run's row. A create the
payer's balance cannot cover is `402 credits-exhausted` carrying `account`,
`balance`, `hold`, `resetsAt` and `tier`, and no run is written.

When the worker finishes the run, the runner's exit class becomes the
outcome, and the outcome decides what the hold becomes.

| Outcome | The runner's exit class | The hold |
|---|---|---|
| `succeeded` | `ok` | settled from the tokens |
| `failed` | `harness` (14), `outputSchema` (17) | settled from the tokens |
| `timeout` | `timeout` (15) | settled from the tokens |
| `budget` | `budget` (16) | settled from the tokens |
| `interrupted` | an envelope whose error is `interrupted`, and any run the account cancelled that ran and did not succeed | settled from the tokens when something ran; refunded when the envelope reports no tokens and no turns |
| `refused` | `verify` (10), `policy` (11), `compile` (12) | refunded in full |
| `error` | `cli` (1), `usage` (2), `gateway` (13), and any exit class the mapping does not know | refunded in full |

A run cancelled while still queued is `cancelled`, not an outcome, and its
hold is refunded in full. So is a run nobody claimed within the queue timeout;
a run whose worker fell silent is closed as `error` and refunded.

A run that **ran** settles `max(1, ceil(input ÷ inputTokensPerCredit + output
÷ outputTokensPerCredit))`, never more than the hold, with the rest of the
hold released. `input` and `output` are the receipt's `usage.inputTokens` and
`usage.outputTokens`; tokens its `usage.totalTokens` counts beyond them —
all of them, when a harness reported no split — are priced at the output
rate. Input counts tokens processed, cached prefixes included, so the price
leans the platform's way rather than the account's. The minimum of one credit
means a run that started and produced nothing still costs one. The ledger records the
hold (`run_hold`), then either the whole hold released (`run_release`) and
the cost charged (`run`), or the whole hold refunded (`run_refund`) — each
line unique on its reason and the run's id, so a finish reported twice
changes nothing.

## What a run is refused for

| What | Answer |
|---|---|
| The release does not declare the autonomous mode | `409 mode-not-declared` |
| The release, or an MCP server it declares, declares a secret the caller has not set | `409 secret-missing`, with `missing` (the names not set) and `secrets` (every declared name); set them, then create the run again ([below](#a-runs-secrets)) |
| The release declares a secret and the deployment keeps none, or pushes to no sandbox host | `409 secrets-declared`, with `secrets` — such a release runs on your own machine, where its keys are yours |
| The release declares more than 32 secrets, where the deployment keeps secrets | `422 validation` |
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

The same `413 too-large` guards the worker's side: a run keeps at most 50 MB
of artefacts, and an output over what is left is reported on the run rather
than dropped quietly.

One refusal happens after the run is created, because only the CLI can find
it: a release whose attestation verifies under no key the worker has pinned
is refused at verify (exit 10). The run is created, held, claimed, and comes
back `refused` with the whole hold refunded, and the receipt's error says no
pinned key verifies the signature. A key rotation on the registry does not
leave it that way: the registry advertises its retired keys and, at its next
start, queues a sweep that countersigns every attestation the new key has not
signed (see [Trust and security](trust.md)), so a release published before
the current key verifies for a fresh worker once the sweep has run. What does
cause it is a worker whose pinned set predates a rotation — its preflight
login reports the changed key ids; re-pin its home deliberately.

## Watching a run, and cancelling it

`GET /api/v1/x/runs/{id}/events` is server-sent events over the run's
append-only rows. Each event carries `id` (the row's sequence number),
`event` — `log`, `status`, `usage` or `error` — and the row as JSON `data`.
The stream starts after `Last-Event-ID` or `?after=`, so a client that
reconnects loses nothing; it ends with the run's terminal `status` row
followed by `done`, or with `timeout` after ten minutes, from which the
client reconnects at its last id. No transaction is held open for a reader.

The log lines are the CLI's stderr as the worker batched it. The `usage`
event is the receipt's usage, forwarded once when the run ends.

`POST /api/v1/x/runs/{id}/cancel` cancels a queued run at once and refunds
its hold. On a claimed or running one it records the request; the worker sees
it on its next claim, interrupts the CLI, and the finish settles what ran.

## The receipt, the usage and the outputs

A finished run carries the runner's envelope minus its result text, kept
verbatim as `receipt`, beside `usage` (turns, input and output tokens, wall
milliseconds), `outcome`, `exitClass`, `settledCredits` and the `outputs` by
name. `GET /api/v1/x/runs/{id}/outputs/{name}` serves one artefact's bytes as
the worker uploaded them, with the account's grant. No artefact is served by a
public URL, and the worker uploads through the registry's object store rather
than from the sandbox host.

A client showing a run shows the receipt's `capabilities_enforced` as it is —
item for item, sentence for sentence, never summarised or scored. Those
sentences name the mechanism behind each contract line, including
`capabilities_enforced.runtime`, the OCI runtime the QuickAgent's containers
were created with ([the `docker.runtime` knob](runner.md#the-oci-runtime-dockerruntime)).
Summarising them would replace what the run enforced with someone's reading
of it.

Three surfaces read the same run. The API above is one; the site's run page
is another, reached from **Run in Agentry** on a QuickAgent's page, with the
queue, the live log, the credits held and settled, and the outputs to
download; the desktop app's run panel is the third. The site's
[Running on Agentry](https://docs.secureagentry.net/agentry/hosted-runs/)
walks through what a person sees.

## What actually bounds a run

The payer's tier's wall time and turn count are the CLI's own budgets,
enforced inside the run as they are on your own machine (exit 15 and 16).

**The token cap is live.** The CLI narrates its usage as the run goes
(`usage: input=… output=… total=… turns=…` on stderr), and the execution
plane interrupts the run as a cancel does when the narrated total first
passes the tier's token cap; the run finishes `interrupted` and settles on
what it spent. It can pass the cap by at most the tokens of the report that
crossed it, and it cannot cost more than the hold, because the settlement is
capped there. `--max-cost` is not derived — an OpenAI-compatible endpoint of
the deployment's choosing reports no cost.

Two sweeps run every minute. A run nobody claims within the queue timeout
(`AGENTRY_RUNS_QUEUE_MAX`, 1 h) is cancelled and refunded. A claimed run
whose worker has been silent past the stale window
(`AGENTRY_RUNS_STALE`, 10 min) is closed as `error` and refunded.

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

Attached knowledge runs only on sandbox hosts Agentry pushes to; the pull
worker never claims such a run. At the hand-off the dispatcher reads each
pack's tree through the core's store, which decrypts it there, so the pack's
data key never leaves the core. It stages the tree for the host beside the
run's inputs, with the same posture inputs have, and the host passes each
pack to the CLI as a `--knowledge` directory. The CLI mounts it read-only at
`/knowledge/<name>` on the tools container and names it in the receipt by
digest, as for a local run ([Running them](runner.md#knowledge-packs)). The
staged trees are deleted with the job's inputs on every path: the collect,
a requeue, a cancel and the sweep.

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

## A run's secrets

A release can declare secrets: its own, in `capabilities.secrets`, and each
declared MCP server's, in that server's `secrets`. On your own machine the
CLI resolves them from your profile or the policy's secret source
([Running them](runner.md)). A hosted run gets them from the account's
secrets in the vault, the extension named above. Where no vault is
configured, such a release is refused with `409 secrets-declared` and runs
on your own machine.

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
release's names and its MCP servers' are one namespace. A name that is not
set is `409 secret-missing`, with `missing` naming each and `secrets`
naming all, and nothing is held or queued. More than 32 declared names is
`422 validation`. With every name set, the run records the names
(`secrets`, names only) and is queued.

A secret that is not kept counts only for the credential that set it: the
same session, or the same token. To any other caller it is missing, so
that start asks for it again. Run create takes a PAT with `run:write`, so a
token holder can learn which of a release's declared names the account has
set. It never learns a value.

### At the hand-off

A run with secrets goes only to a sandbox host Agentry pushes to; the pull
worker never claims one. The dispatcher, in the worker role, locks the run
while it is claimed on its host. Then, in one transaction committed just
before the job is sent, it:

- decrypts each declared name's secret, under the key of the account that
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
job's directory. The policy it renders names that file as the CLI's
`envFile` secret source, so a declared secret never resolves from the
host's own environment. The CLI then does what it does on your machine
([What a run enforces](runner.md#what-a-run-enforces)). It gives each value
to the MCP gateway's container and to the tools container or the declared
server's container, and never to the agent's. The file is deleted as soon
as the CLI exits, and so is the gateway's copy if a killed CLI left one.

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
holds every value it injects. A sandbox host whose CLI predates
agentry-cli#376 still writes `none declared` when only a declared server
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

## A knowledge build

A run of the kind `knowledge_build` runs the CLI's built-in Knowledge Creator
over documents to make or extend a [knowledge pack](knowledge.md) in the
registry's store, against the platform's model, for credits. It is created
by the same `POST /api/v1/x/runs/` with `kind: knowledge_build`, the
documents as `inputs`, and exactly one of `name` (a new pack of that name;
an empty pack of that name, one a refused build left, is reused), `pack` (the
id of one of the caller's packs) or `continue` (a finished build of the
caller's, whose documents are copied for the new one). It names no `ref`,
`task` or `intake`. With `org` (an organization's handle) the build makes
or extends that organization's shared pack: only its admins may, a caller
who is not a member gets `404`, one who is not an admin `403`, and an
organization in its decommission hold `409 org-decommissioning`, since its
shared knowledge is read-only then. Membership is read again at the
hand-off and at the output download, as for a run that attaches a shared
pack (above). A token needs `knowledge:read` and `knowledge:write`
beside `run:write`, and downloading a build's output needs `knowledge:read`
beside `run:read`, since the output holds the pack.

A build holds `AGENTRY_RUNS_BUILD_CREDITS` (100) on the payer's row under
its own ledger reasons (`knowledge_build_hold`, then `knowledge_build` and
`knowledge_build_release`, or `knowledge_build_refund`), with caps of its
own: `AGENTRY_RUNS_BUILD_SECONDS_STANDARD` (900 s) and
`AGENTRY_RUNS_BUILD_SECONDS_{PRO,BUSINESS,ENTERPRISE}` (3,600 s),
`AGENTRY_RUNS_BUILD_MAX_TURNS` (300), and as tokens what the hold buys at the
input rate. It counts against one active run per account. It runs only on
sandbox hosts Agentry pushes to: the pack's tree is staged for the host
beside the documents, the host runs `agentry knowledge add` (or `create`)
over it and stops the build when its narrated tokens, priced at the two
rates, pass the hold less one credit. That credit is the pack's scan: when
the build finishes, the registry opens its output for its runner, puts the
pack's new tree into the store if the pack still holds the tree the build was
handed — resealed under the pack's own key, counted against the allocation,
and scanned as any upload is — and settles the tokens plus 1 credit for the
scan, never past the hold. The run's `build` record says what happened: the
pack's digest, pages and bytes when it was `applied`, or a `note` —
`nothing` (the build made no pack), `changed` (the pack took another tree
while it ran), `allocation`, or `deleted`, each settling the tokens spent,
or `invalid` (the output held no valid pack), refunded in full.

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
bytes each, blank ones dropped). It names no `ref`, and takes no `task`,
`intake`, `inputs` or `knowledge`: each is `422`. A token needs `run:write`
only. The description is the run's `task`; the hints are in its `draft`
record.

A draft holds the same on every tier: its model tokens' credits
(`AGENTRY_RUNS_DRAFT_TOKEN_CREDITS`, 30), its searches at their price
(`AGENTRY_RUNS_DRAFT_SEARCHES`, 10, at `AGENTRY_RUNS_DRAFT_SEARCH_CREDITS`, 1
each) and AI Review's 1 credit — 41 by default, under its own ledger reasons
(`draft_hold`, then `draft` and `draft_release`, or `draft_refund`). Its caps
are `AGENTRY_RUNS_DRAFT_SECONDS` (900 s), `AGENTRY_RUNS_DRAFT_MAX_TURNS` (100)
and as tokens what its token credits buy at the input rate. It pays under
the same payer rule as a run and counts against one active run per account.
A balance that cannot hold it is `402` with nothing held, and a deployment
with no sandbox hosts is `503 draft-unavailable`.

It runs only on sandbox hosts Agentry pushes to. When a host takes the
draft, the registry mints it a credential for this one draft, keeps only its
digest, and hands it to the host with the job. The host runs `agentry draft
--hosted --output-format json` with the credential in the CLI's
environment beside the platform model's key, as for any run, and no Jev or
search key, and stops the draft when its
narrated tokens, priced at the two rates, pass its token credits. The
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

A draft that ran settles its tokens (at most its token credits), the
searches the provider answered at their price, and 1 credit for AI Review,
however many texts it read, never past the hold. A draft that did not run is
refunded in full: one whose description AI Review did not pass (the CLI's
exit 11 at stage `description`, before anything is searched or read) and
one the platform failed. The run's `draft` record keeps what the calls
spent: the searches, the texts scanned and withheld, the judge's requests
and input tokens (for the record: AI Review is 1 credit), and the parts of
the settlement. Its output is the sealed `output.tar`, for its runner alone,
holding `draft.json`, the rendered `package/`, the reports and the receipts.

The Drafter is part of the CLI the host runs, like the Knowledge Creator:
a draft runs without a registry scan of a package. What it drafts is not
published by it: a submission of the draft is scanned like any other.

## The execution plane

The worker is a puller beside a docker daemon on a sandbox host, and reaches
the registry only outbound: it claims every couple of seconds with its worker
token, stages the run under its own home at `0700`, renders one policy per run
from the CLI's own defaults — the platform's model with its endpoint as the
egress proxy's only allowed host and its key named by an environment variable
and never written, the run's caps as the budgets, `secretSource: env` with no
names (a sandbox host's runhost names the job's own `secrets.env` as an
`envFile` source instead, [above](#at-the-hand-off)), and
`docker.runtime: runsc` — and runs the installed `agentry` CLI as
a subprocess with typed arguments and a minimal environment. The worker token
never reaches the CLI; the CLI gets the worker's own registry token, which
carries `agent:read` and `user:profile` and nothing more.

The claim is atomic (`FOR UPDATE SKIP LOCKED` on the oldest queued row within
the worker's declared capacity), so two workers polling together never both
take the same run.

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

## Retention

A run and its artefacts are deleted thirty days after the run was created
(`AGENTRY_RUNS_RETENTION`, `720h`), and, once the run has finished, within a
minute of the account being erased (the runs sweep deletes a closed run of an
erased account). Uploaded inputs that no run claims are swept after a day. Download
anything you want to keep before then; nothing is archived elsewhere.

## The deployment's configuration

| Variable | Default | What |
|---|---|---|
| `AGENTRY_RUNS_CAPS_STANDARD` | `300,20,500000` | the Standard tier's seconds, turns, tokens |
| `AGENTRY_RUNS_CAPS_PRO` | `900,60,5000000` | the Pro tier's seconds, turns, tokens |
| `AGENTRY_RUNS_CAPS_BUSINESS` | Pro's | the Business tier's seconds, turns, tokens |
| `AGENTRY_RUNS_CAPS_ENTERPRISE` | Pro's | the Enterprise tier's seconds, turns, tokens |
| `AGENTRY_RUNS_INPUT_TOKENS_PER_CREDIT` | `50000` | the input tokens a credit buys |
| `AGENTRY_RUNS_OUTPUT_TOKENS_PER_CREDIT` | `25000` | the output tokens a credit buys; a run's hold is its token cap at this rate |
| `AGENTRY_RUNS_BUILD_CREDITS` | `100` | what a knowledge build holds, its scan's 1 credit included |
| `AGENTRY_RUNS_BUILD_SECONDS_STANDARD` | `900` | a knowledge build's wall time on Standard |
| `AGENTRY_RUNS_BUILD_SECONDS_{PRO,BUSINESS,ENTERPRISE}` | `3600` | a knowledge build's wall time on the tiers above |
| `AGENTRY_RUNS_BUILD_MAX_TURNS` | `300` | a knowledge build's turn cap |
| `AGENTRY_RUNS_DRAFT_TOKEN_CREDITS` | `30` | what a hosted draft's model tokens may cost; the host stops it there |
| `AGENTRY_RUNS_DRAFT_SEARCHES` | `10` | the web searches the registry brokers for one draft |
| `AGENTRY_RUNS_DRAFT_SEARCH_CREDITS` | `1` | what one search costs a draft |
| `AGENTRY_RUNS_DRAFT_PAGES` | `60` | the pages AI Review reads for one draft |
| `AGENTRY_RUNS_DRAFT_SECONDS` | `900` | a draft's wall time, on every tier |
| `AGENTRY_RUNS_DRAFT_MAX_TURNS` | `100` | a draft's turn cap |
| `AGENTRY_RUNS_QUEUE_MAX` | `1h` | how long a run may wait for a worker before it is cancelled and refunded; at most `12h`, half the day a secret held for one run waits for it |
| `AGENTRY_RUNS_STALE` | `10m` | how long a claimed run's worker may be silent before the run is closed as `error` and refunded |
| `AGENTRY_RUNS_TASK_MAX_BYTES` | `65536` | the task text's cap |
| `AGENTRY_RUNS_INPUT_MAX_FILES` | `20` | input files per run |
| `AGENTRY_RUNS_INPUT_MAX_BYTES` | `10485760` | one input file's cap |
| `AGENTRY_RUNS_OUTPUT_MAX_BYTES` | `52428800` | all of a run's artefacts together |
| `AGENTRY_RUNS_RETENTION` | `720h` | how long a run and its artefacts are kept |

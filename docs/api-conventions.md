# API conventions

Rules that hold across the whole REST surface (PLAN §9.1), plus the
per-endpoint semantics that are easy to get wrong. The authoritative
contract is `schemas/openapi.yaml`; this document explains the parts a
schema cannot express.

Base path is `/api/v1`. Three surfaces sit deliberately outside it: `/scim/v2`
(the SCIM 2.0 spec fixes that path), `/sso/{org}` (a browser destination
people paste into address bars and IdP consoles, not a JSON operation), and
`/internal/directory/trusted-device` (the directory's own trust check on the
private network, gated by a shared secret and never routed by an edge; see
`docs/self-hosting.md`, agentry#670). The last is not part of the public API
and answers bare status codes.

## Versioning

`/api/v1` is additive: a CI gate (`oasdiff`) refuses a pull request that
removes or narrows anything in the contract. It was broken deliberately
once, before the beta and with no external consumers — spec 0.2.0 → 0.3.0
replaced the `kind` classification with `modes` (`?kind=` → `?mode=`, the
`kind` facet → `mode`; DEV-088) — and has been additive again since. A
version's `manifestSchemaVersion` says which manifest major its snapshot
follows, so a client reading a v1 snapshot applies the v1 mapping
(`skill`, `prompt-agent` → `[autonomous]`).

## Errors are problem+json

Every error response is `application/problem+json` (RFC 9457) with `type`,
`title` and `status`; most also carry a `detail`. Read `detail` for the
human-facing reason; do not parse `title`. A `422` carries field-level
validation errors; a `409` means the request conflicts with current state
and the `detail` says how.

Three problems exist only where a deployment runs an admission extension
(the hosted product's subscription tiers); a core registry never answers
them. `402 credits-exhausted` refuses a submission after every core check
has passed and before anything is stored, and carries `balance`,
`resetsAt` and `account` beside the standard members so a client can say
when to retry and whose balance is short — the submitter's own, or the
organization's when they are a member of one that pays for their work.
`402 subscription-inactive` refuses a submission whose payer is an
organization awaiting payment or lapsed, and names it in `account` too.
`503 admission-unavailable` means the check could not be reached; nothing
was recorded. `422 private-agent-cap` refuses one more private agent in a
namespace at its cap, on create and on a `PATCH` that turns an agent
private; nothing already private is touched.

The organization problems (plan organization-subscriptions), each with
its own slug so a client can offer the right next step. Answered by every
registry: `409 last-admin` refuses the demotion or removal of an
organization's last admin, by an admin or by the organization's IdP over
SCIM, their leaving, and the erasure of their account (`POST
/user/delete`) — promote another member first; only a decommission
removes the last one. `403 email-unverified` refuses `POST /orgs` and the
domain lookup from an account whose address is not verified. `409
org-pending` refuses `POST /orgs` while an organization the account
created is still awaiting payment (only where an admission extension
runs; a core registry activates an organization as it is created).
`403 seat-allowance` refuses an invitation or an approval past the
organization's seats, carrying `used`, `invited`, `pending` and `max`; a
registry with no billing extension has no seat cap and never answers it.
`403 feature-not-included` refuses an act the organization's subscription
does not include at all, which is not the same as its allowance being
reached; since agentry#820 it also refuses `POST /user/ssh-keys` where the
person's own subscription does not include adding SSH keys (a key already
held keeps working, listed and removable; a registry with no billing
extension includes it). `409 already-a-member` refuses an invitation, an approval or
`POST /orgs` for someone who is an active member of another
organization: a person belongs to one at a time, and leaves it (`DELETE
/orgs/{org}/members/{own handle}`) before joining or founding another.
`409 staff-org-domain` refuses the deployment's staff organization
(`AGENTRY_STAFF_ORG`) an address outside its domain (`AGENTRY_STAFF_DOMAIN`),
at every door: an invitation, its accept, an approval, SCIM provisioning and
founding it; its members are platform staff (agentry#556).
`409 domain-claimed` refuses `POST /orgs` from an address whose domain
already belongs to an organization — recorded at that organization's
creation, or verified by it over DNS — and a DNS verification of a domain
another organization holds; it carries `domain` and `org`, the holder,
whose administrators can add the person (`GET /user/domain-org` says the
same, and `POST /user/domain-org/request-access` asks them, once a day —
`429 rate-limited` afterwards). `409 org-decommissioning` refuses every
change to an organization in its decommission hold, and to anything under
it, carrying `org` and `decommissionAt`; reads, the audit log and its
export go on until then, and a member may still leave. A suspended organization, and everything under
it, answers `404` to everyone until platform staff reinstate it.

Unscanned private agents (plan organization-subscriptions §4) have three
refusals of their own, all `409`. `pipeline-skip-public` and
`pipeline-skip-personal` refuse `pipelineSkip: true` on `PATCH
/agents/{ns}/{name}` for a public agent and for one in a personal
namespace; only a private agent of an organization's is admitted without
a scan, and only where the tier includes it (`403 feature-not-included`
otherwise). `agent-unscanned` refuses making an agent public while it
holds versions admitted unscanned that are published, quarantined or
blocked, carrying their count as `unscanned`; yanking them opens the way, since
only a version that passed the gate is ever public. A version admitted
without a scan carries `scanStatus: skipped` on the version and on
resolve, its report `verdict: unscanned`, and has no attestation.

A publisher puts away their own agent in two ways (agentry#942, DEV-219),
both open to the namespace's administrators. `POST
/agents/{ns}/{name}/retire` makes it private and marks it `retiredAt`.
Every submission to it is then refused with `409 agent-retired`, as is
`PATCH` to public, and it holds no place under the private-agent cap.
`POST …/restore` returns the visibility it had, under the same rules as
any agent becoming public (`409 agent-unscanned`). Back to private it is
under the cap again (`422 private-agent-cap`). It answers `409
agent-not-retired` when there is nothing to restore.

`DELETE /agents/{ns}/{name}` removes an agent that never had a version, as
before. For one with version history the request needs `confirm=<name>`
(`422 confirm-name`), and the delete leaves a tombstone:
- every published or quarantined version is yanked, with the reason "The
  publisher deleted this QuickAgent.";
- every route by name, `GET /resolve`, git and hosted runs answer the 404
  a missing name gets, to everyone;
- nothing is removed, and the name is held for good, so creating it again
  answers `409 name-held`.

The delete waits (`409`) while a version is in the pipeline or in review.
It is refused while the agent carries advisories, abuse reports, a
quarantine or a block, because an advisory reaches its readers only through
the public feed. `GET /agents?namespace=` takes `q`, `state` (`active`,
`retired`) and `sort` (`name`, `newest`, `installs`, `submitted`). It never
lists a deleted agent.

A built-in agent (agentry#737) is one of the packages the Agentry CLI
embeds, published for reading: `builtin` on the agent and on every search
hit says so, and clients label it Built-in in place of its run modes.
`PATCH /agents/{ns}/{name}` takes `builtin` from platform staff only (`403`
for anyone else, the namespace's own administrators included), and marks
an agent only in a first-party namespace (`409 builtin-first-party`
otherwise). Nothing but the label reads it. It is not the runner's
attestation state `builtin`, which only the CLI's embedded copy of a
package runs under: an install of a built-in agent from the registry is an
ordinary release.

## Idempotency-Key

Send `Idempotency-Key: <opaque string, ≤255 chars>` on a mutating POST and a
retry cannot create a second resource.

Honoured on `POST /orgs`, `POST /orgs/{org}/webhooks`,
`POST /orgs/{org}/webhooks/{id}/ping`, `POST /platform/ruleset-releases`,
and `POST /agents/{ns}/{name}/versions` (a version upload with a key is a
multipart body; the key is pinned to it like any other, agentry#22).

Semantics:

- **Scope is `(user, endpoint, key)`.** Your key can never collide with, or
  read, another caller's. It is also per-endpoint: the same key on two
  different endpoints is two different claims.
- **The key is pinned to a hash of the request body.** A retry with the same
  body replays the recorded status and response, with
  **`Idempotency-Replayed: true`** on the replay. A retry with a *different*
  body gets **`409`**. The key is a promise about one request, and returning
  some other request's answer would be worse than an error.
- **A retry while the first attempt is still running gets `409`** rather than
  racing it. Back off and retry.
- **Records live 24 hours**, then the key is reusable.
- **A claim whose request failed is released**, so one bad attempt cannot
  lock a key out for a day.

## Pagination

The audit, advisory and activity lists are cursor-paginated: pass `limit`,
and follow the cursor. `/search` is offset-paged (`offset`, `limit`, with
`total` in the response) so a page can be addressed directly.

```http
GET /api/v1/orgs/acme/audit?limit=100
→ 200 OK
   Link: </api/v1/orgs/acme/audit?limit=100&cursor=eyJ0Ijoi…>; rel="next"
```

- Follow the `Link` header's `rel="next"` target verbatim. It is
  **path-relative** on purpose. The API runs behind proxies that rewrite the
  host, so resolve it against the request URI.
- **No `Link` header means no more pages.** That is the termination
  condition; do not infer it from a short page.
- Cursors are opaque. Do not construct, decode, or persist them across
  ruleset or schema changes.

## Limits are clamped, not rejected

`limit=100000` and a negative `offset` are **clamped to the endpoint's
valid range** and the request succeeds; `limit=0` (or any value under 1)
gets the endpoint's default, and an `offset` past 10000 is capped there —
paging that deep is a crawler's, not a reader's; the cursor-paged lists have
no such cap. You will not get a `400`
for asking for too much; you will get the maximum. Read the length of what
came back rather than assuming you got what you asked for. Each endpoint's
default and ceiling are in the OpenAPI document.

## Rate limiting

Every response carries the rate-limit trio:

```
RateLimit-Limit: 5000
RateLimit-Remaining: 4991
RateLimit-Reset: 2314
```

`RateLimit-Reset` is **seconds until the window resets**, not a timestamp.
On a `429` the same headers are present plus **`Retry-After`**, in seconds.
Honour it; the buckets are per-user for authenticated traffic and per-IP for
anonymous traffic, and burst and sustained budgets are separate (§19). The
model-input routes draw from a budget of their own per caller, a staff
member or one hosted job ([model-input.md](model-input.md)).

Self-hosters behind a load balancer must configure trusted proxies or all
anonymous traffic shares one bucket. See
[self-hosting.md](self-hosting.md#running-behind-a-proxy).

## Event streams

`GET /agents/{ns}/{name}/versions/{version}/events` is `text/event-stream`:
it streams a submission's pipeline progress (scanning, verdict, publication)
as server-sent events until the version reaches a terminal state.
`agentry publish` follows it and falls back to polling
`GET /agents/{ns}/{name}/versions/{version}` when the stream is unavailable;
do the same in a client of your own.

## Search facets

`GET /search` returns facet counts alongside results. One filter behaves
less obviously than it looks: **`capability=` matches only capabilities the
agent actually asks for.** A manifest declaring `network: {egress: none}`
still serializes with the `network` key present, so key-existence alone
would match every agent ever published; the filter additionally requires the
value not to be `none`, null or empty, and for object-valued capabilities
that at least one member is non-empty (DEV-021).

## SCIM 2.0

The subset is Users and Groups→teams (§12.5). Four behaviours to code
against:

- **`PUT /scim/v2/Users/{id}` is a full-resource replace,** not a merge.
  Omit the active flag and it reads as false, so a partial PUT deactivates
  the user. Deactivation is a PUT of the whole user with `"active": false`;
  that revokes the org's PATs and sessions for that user in-request, inside
  60 seconds by design.
- **`userName` is immutable.** It is the account's email, and email changes
  are an identity operation, not a directory attribute update. A PUT that
  changes it gets `400` with a message telling you to deactivate and
  re-provision.
- **Membership-sync failures return 5xx.** If a group create or PATCH writes
  the group but cannot write its members, the response is `500` so your IdP
  retries. Silently discarding the error would leave the IdP believing a
  group had synced when the team was empty. The one tolerated case is "this
  user is not an org member", which is a legitimate no-op rather than a lost
  write, and is skipped rather than failed.
- **Only `userName eq "…"` is supported as a filter.**

## Account erasure (GDPR)

`POST /user/delete` (§12.7) requires an explicit decision about published
content whenever the account has any:

- **`publishedContent` is required** (`yank` or `transfer`), and a request
  without it gets `400` naming the count of published public versions. There
  is no default; the previous behaviour defaulted to `yank` and the guard
  meant to prevent that was dead code behind it (DEV-021).
- **`publishedContent=transfer` additionally requires `transferOrg=<org
  handle>`**, and the caller must be an admin of that org.
- Published versions are **yanked or transferred, never deleted**. §4.3
  forbids deleting version rows and a database trigger enforces it: digests
  stay resolvable so existing installs can still be verified. PII is purged
  and credentials revoked; what remains is a leak-free tombstone.
- **Every pending desktop sign-in code is consumed** in the erasure
  transaction (agentry#502), so a code minted by another session just
  before the erasure cannot be exchanged for a token afterwards.
- **An organization's last admin cannot be erased** (`409 last-admin`):
  promote another member first, or decommission the organization. The
  erased account's memberships go with it, so no seat is held by an
  account that is gone.
- **A transfer respects the organization's private-agent cap** (`422
  private-agent-cap`, nothing erased, nothing moved) and is refused into an
  organization in its decommission hold.
- **An extension's rows go in the same transaction** (agentry#638): an
  extension that keeps rows about the account deletes them inside the
  erasure's transaction, and the `user.delete` event's detail counts them
  under `extensions`. If it cannot, the account is not erased and the
  answer is `500` (a yank or a transfer already made stands; both run
  before the erasure).
- **The `204` carries `X-Agentry-Directory-Erasure`** (agentry#499): where the
  sign-in account at the directory stands — `deleted`, `not-found`,
  `not-configured` (erasure is registry-only), `pending` (the directory
  was unreachable and a job retries it), or `failed` (the retry could not
  be queued; the operator is alerted). A client tells the person when it is
  `pending` or `failed`; the registry's erasure has happened either way.


## Clearing an account's data

`POST /user/clear-data` (session only) empties an account and keeps it
(agentry#498). It revokes every personal access token and SSH key, deletes
every remembered browser (the ones that skip the second factor), consumes
every pending desktop sign-in code, ends every session except the caller's,
removes every account install, clears the display name, resets the
notification settings to their defaults and clears the report theme. The handle, the email, the sign-in
account at the directory, organization memberships, QuickAgents with their
versions and repositories, stars, the subscription and credits stay. It
answers `204`, and the caller stays signed in.

- **A token cannot call it** (`403`). A cookie request needs the session's
  CSRF header, like every other cookie mutation.
- **It writes one audit event**, `user.data_clear`, whose detail counts what
  it removed.
- **Extensions hear `user.data_cleared`** with the user id after the commit,
  so an extension clears what it holds for the account (the hosted-runs
  extension deletes the account's run history).
- **An extension's rows go in the same transaction** (agentry#638), as on
  an erasure: an extension that keeps credentials or history for the
  account deletes them inside the clear's transaction, the detail counts
  them under `extensions`, and if it cannot, nothing is cleared and the
  answer is `500`.

## Organization lifecycle

An organization is created by `POST /orgs` from an account with a verified
address (its first admin), one per person: an active member of another
organization leaves it first. It is **keyed on its creator's email domain**
unless the body says `domain: none` or the domain is one no organization
owns (a public mail provider, a reserved name); a domain belongs to one
organization, and a further domain is claimed over DNS
(`/orgs/{org}/domain-claims`). `GET /orgs/{org}` carries `domain`,
`verifiedDomains`, `state` and, in a hold, `decommissionAt`.

`POST /orgs/{org}/decommission` (admin, session only, the handle repeated
in `confirm`) starts the **decommission hold**: the organization is
read-only for its members — its agents readable, its audit log listable
and exportable, every change `409 org-decommissioning`, pushes refused
over git — for the deployment's hold (`orgs.decommissionHold`, default
30 days), then a sweep yanks every release, deletes the archives and
repositories, ends every membership and invitation, retires the agents,
scrubs the organization's row and releases its handle and domain, and
records `org.erase` in the audit log. Version rows are immutable and are
not deleted. Platform staff may `POST /orgs/{org}/suspend` (with a
reason) — the organization and everything under it answer `404` to
everyone — and `POST /orgs/{org}/reinstate`, which ends a suspension or
cancels a hold that has not run; an erased organization does not come
back.

## Retire, delete and fork

A QuickAgent's namespace administrators (its owner, or an organization's
admins) can put it away or end it, and anyone signed in can copy a public
one (plan forks-and-publisher, agentry#942 and agentry#943).

**Retire.** `POST /agents/{ns}/{name}/retire` makes the agent private and
labels it `retiredAt`, keeping the visibility it had. A retired agent takes
no submission (`409 agent-retired`) and holds no place under the
private-agent cap. `POST …/restore` puts the visibility back, under the
rules of any agent becoming public (`409 agent-unscanned`) or of a private
one (`422 private-agent-cap`).

**Delete.** `DELETE /agents/{ns}/{name}` removes an agent with no version
outright, with its repository, and its name is free again. An agent with
version history is deleted as a **tombstone**, and only with `?confirm=` set
to its name (`422 confirm-name` otherwise):
- every published or quarantined version is yanked;
- every route by name, the git transport and hosted runs answer the 404 a
  missing name gets, to everyone;
- nothing is removed, because version rows are kept forever and the
  archives, receipts and audit trail stay with them;
- the name stays held in its namespace: creating it again, or forking into
  it, answers `409 name-held`.

A delete is refused (`409`) while a version is in the pipeline or in review,
and while the agent carries trust & safety records (advisories, abuse
reports, a quarantine or a block), which outlive the publisher's wish to
remove it (DEV-021, DEV-219).

**Fork.** `POST /agents/{ns}/{name}/fork {namespace, name?}` copies a
public agent into a namespace the caller may create a private agent in:
their own, or an organization they are an active member of. The quota and
the private-agent cap apply. The fork takes the origin's name unless `name`
gives another. A name the namespace already has answers `409 name-taken`.
The origin must be public, neither quarantined nor blocked (`409
fork-source`), and have a published version (`409 nothing-to-fork`). A fork:
- **is private for good.** `PATCH` to public answers `409
  fork-stays-private`, and the database refuses it as well. That keeps
  Publisher Earnings with the origin's publisher;
- **records its origin** (`forkedFrom`: the namespace, the name, the version
  it was taken from, and `available`, whether the origin is still public,
  not deleted and not blocked). The origin is permanent: there is no
  detach, and its name stays on the fork even after the origin is made
  private, retired or deleted;
- **is answered `202`** with `forkState: copying` (or `failed`, with
  `forkDetail`, when the copy could not even be started). A worker then copies the
  origin's repository: every branch and tag, its objects copied rather than
  shared, so retiring or deleting the origin later changes nothing in the
  fork. It writes one commit, *Fork of ns/name@version*, that renames the
  manifest into the fork's namespace. The fork's default branch and a
  `v<version>` tag point at it, and the origin's default branch, where it
  had moved on past the release, is kept as `origin-<branch>`. That tag is
  submitted through the pipeline like any submission, charged like one; a
  fork's first version is always scanned. The fork's history runs back
  through the origin's commits. An origin published by upload has no
  commits, and the fork's first commit is then built from its release
  archive's files as they are. `forkState` is then `ready`, or `failed`
  with `forkDetail` saying why. Until then git refuses the fork's
  repository (`409`) to those who may read it. A copy that has not finished
  after two hours is marked failed;
- **is a fork of an original.** A fork is private, so a fork cannot itself
  be forked, and lineage is one level deep.

A public agent's read carries `forkCount`: a count, never which forks.
`GET /agents?namespace=` takes `forks=only` or `forks=none`. When the
platform quarantines or blocks an origin, its forks are left as they are:
each went through its own pipeline. The act's audit record carries how many
forks there are (D11).

## Personal access tokens and their scopes

A personal access token (`POST /user/tokens`, or the Tokens page under the
account) is a least-privilege credential: it can do only what its scopes
allow, and the list is flat — no scope implies another. A browser session
carries the account's full authority instead and is gated by CSRF. The
scopes:

| Scope | What a token with it may do |
| --- | --- |
| `agent:read` | read QuickAgents, versions, reports and search |
| `agent:publish` | create QuickAgents and submit versions |
| `agent:manage` | take the owner actions on a QuickAgent the account administers: make it public or private, retire, restore and delete it; nothing else of its settings or grants (`org:admin` covers these too) |
| `repo:read` | fetch from a QuickAgent's git repository |
| `repo:write` | push to a QuickAgent's git repository |
| `user:profile` | read and change the account's own settings, tokens, keys, sessions and account installs |
| `org:admin` | manage an organization's members, teams and settings |
| `review:act` | work the review queue and record decisions (platform staff or a security reviewer) |
| `audit:read` | read an organization's audit log |
| `run:read` | read a hosted run of a QuickAgent, its log and its artefacts |
| `run:write` | start, feed and cancel a hosted run of a QuickAgent |
| `knowledge:read` | list and read the account's knowledge packs, their scan reports and sealed trees, export them, and have a pack's data key unwrapped |
| `knowledge:write` | create, upload and delete the account's knowledge packs and have a data key wrapped |
| `secret:write` | set and delete the account's hosted-run secrets; never list or read one |
| `voice:read` | read the account's Writing Voice: every version's text and its AI Review report |
| `voice:write` | put a new version of the account's Writing Voice for review, restore the previous one, drop the pending one, set always-attach and delete the voice |

`run:read` and `run:write` are consumed only by a registry that mounts the
runs extension (`GET /meta` lists it); on a registry without it a token
carrying only these two is refused everywhere a token without the right
scope is. [Hosted runs](hosted-runs.md) is what those routes do, route by
route. `secret:write` is likewise consumed only by a registry that mounts
the vault extension, which is to admit it for setting and deleting a
secret (agentry-enterprise#251) and keeps the list of them for a
signed-in session. The desktop app's sign-in grant
asks for a fixed set (`agent:read`, `agent:publish`, `agent:manage`,
`repo:read`, `repo:write`, `user:profile`, `run:read`, `run:write`,
`knowledge:read`, `knowledge:write`, `secret:write`, `voice:read`,
`voice:write`). `agent:manage` (agentry#993) lets the desktop's Publisher
section make a QuickAgent public or private, retire, restore and delete
it; the caller must still be the namespace itself or an admin of its
organization, and no other setting of the agent, grant or organization
route is open to it. A token minted before the grant carried it does not
gain it: sign in again.

## Native credentials vs an external directory

A deployment can hand its account directory to an external IdP
(`AGENTRY_AUTH_EXTERNAL_ONLY=true`, DEV-057 — the shipped compose stack
runs authentik this way). The five native credential endpoints —
`POST /auth/register`, `POST /auth/login`, `POST /auth/verify-email`, and
the TOTP setup/verify pair — then answer **`410 Gone`**: the surface is
switched off, not missing. Sign-in happens through
`GET /auth/oidc/{provider}/start`, and sessions, PATs, and every
authorization decision stay the registry's own either way.

Two surfaces exist only for that arrangement. **Account settings**:
`GET /user/directory` reports whether the account is directory-managed and,
when it is, the URLs of the directory's password-change and authenticator
enrolment flows (each returns to the registry's Settings when it finishes)
plus the enrolled authenticators; `DELETE
/user/directory/devices/{kind}/{deviceId}` removes one of the caller's own
(DEV-089). **Desktop sign-in**: a signed-in browser records a grant with
`POST /user/tokens/desktop-grant` (the app's `state` nonce), and the app
exchanges the resulting one-time code for its PAT at `POST
/auth/desktop/exchange` from its own process — the code is single-use and
valid for 60 seconds, and the token never rides a URL (DEV-058, agentry#19).

## Dependency alerts and scanned MCP servers

`GET /user/dependency-alerts` lists the open dependency alerts on published
versions the caller submitted — a version that declares an MCP server
version which the daily sweep found to carry a newly known high or critical
vulnerability. The web app's sign-in banner and dashboard read it. An alert
closes on its own when the version is yanked, quarantined or blocked, or
the advisory is withdrawn; publishing a fixed version does not close the old
version's alert. The same alerts appear publicly as `dependencyAlerts` on
`GET /agents/{ns}/{name}`.

`GET /mcp-servers/scan?ecosystem=npm|pypi&package=…&version=…` is the
registry's last vulnerability check of one exact package version (`safe`
means "no known advisories at `lastCheckedAt`", never "safe"); `404` means
no manifest has ever declared that version. The runner asks here before it
installs a declared server.

## Account installs

An account install is a signed-in person's record, on the registry, of a
QuickAgent release they accepted for their account: the version, the
declared capabilities they consented to as that release declared them,
and the unsigned or unscanned consents the release needed. It is an
acceptance, not a laying-down — nothing is written on any machine — and
it is distinct from a star (public approval, a public count) and from the
per-machine record `agentry install` and the desktop app keep in
`installed.yaml`, which is never synced with it. An account install bumps
no download counter: `installsTotal` and `installs30d` on `GET
/agents/{ns}/{name}/stats` stay download rollups. One record per
QuickAgent per account.

`PUT /user/installs/{ns}/{name}` with `{version, acceptCapabilities,
acceptUnsigned?, acceptUnscanned?}` records a published release the caller
can read, or moves an existing record to it. A caller who cannot read the
QuickAgent gets the missing name's `404`, never a `401` or `403` that
would confirm the name; an unpublished version is `409
version-not-published` (carrying `status`), a blocked QuickAgent `410
blocked`. The request must carry the acceptances the release needs, or
it is `409 install-consent-required` with `missing` naming them:
`capabilities` on a first install and on an update whose declared
capabilities widened against the accepted snapshot (`widened` then lists
what did, one line each, the way the CLI and the desktop phrase it — an
update whose contract is unchanged or narrower asks nothing);
`unsigned` whenever the release carries no attestation; `unscanned`
whenever it was admitted without a scan. A PUT on an existing record is
the update, to any published version, an older one included; the
response is the record composed as the list composes it. `DELETE
/user/installs/{ns}/{name}` removes the caller's own row and reads no
QuickAgent, so it answers `204` whether or not a record existed and
whether or not the name resolves — nothing about a QuickAgent is learned
there, and a record whose QuickAgent the caller can no longer read is
removed by the ref the list shows for it. `GET
/user/installs` lists the caller's records, newest change first: `ref`,
`installedVersion` with its `capabilities` and the consents recorded
(`acceptedUnsigned`, `acceptedUnscanned`), `latestVersion` (the newest
published), the installed version's `verdict` (`scanned` with
`findingCounts`, or `unscanned`; absent while a scan is pending) and
`signed`, the QuickAgent's `quarantineState`, `installedAt` and
`updatedAt`. A record whose QuickAgent the caller can no longer read —
made private to them, its organization suspended — is the bare `ref`
with `readable: false` and nothing else, and that ref is the name the
caller installed it under, never where the QuickAgent has gone since, so
the list tells a former reader nothing they did not already know. A
blocked QuickAgent stays readable and the row says so in
`quarantineState`. An organization's erasure removes the records of its
QuickAgents, as it does their stars.

The three routes are the caller's own account data, so a token needs
`user:profile` — and `agent:read` to record a private QuickAgent, since
the PUT reads it first. The actions are audited as `agent.install` and
`agent.uninstall` beside `agent.star`, so `GET /user/activity` shows
them; the QuickAgent's own activity feed does not, at any role — whose
account holds a QuickAgent is that person's business, where a star is
public approval.

## Enterprise SSO

Beyond the browser destinations (`/sso/{org}`, the SAML `acs` and `metadata`
endpoints, the OIDC `start`/`callback` pair): `POST
/orgs/{org}/sso/connections/{kind}/test` exercises a stored connection —
metadata, certificate, issuer — without enforcing it, and
`/orgs/{org}/sso/saml/slo` accepts the identity provider's single-logout
request over both the redirect and POST bindings, ending the registry
session for that user. SSH keys registered at `/user/ssh-keys` are a git
credential only (they never authenticate to the API).

## Downloads and version states

- `410 Gone`: the agent or version is **blocked** by trust & safety.
- `409 Conflict`: the version is **quarantined** pending review; the
  `detail` says so.
- Yanked versions still resolve by exact pin, with a warning, and are
  excluded from range resolution.

## Webhooks

Deliveries carry an HMAC signature and travel through an SSRF guard that
re-resolves per attempt, requires every resolved address to be public
unicast, dials the verified IP to defeat DNS rebinding, and follows no
redirects.

`POST /orgs/{org}/webhooks/{id}/ping` records its delivery with event type
`ping`, which is deliberately absent from the §9.3 subscribable catalogue;
nobody subscribes to a ping. It otherwise travels the ordinary path, same
envelope and guard and retry ladder, so the test answers "does my endpoint
work" using the code that will actually call it.

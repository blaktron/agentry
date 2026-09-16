# API conventions

Rules that hold across the whole REST surface (PLAN §9.1), plus the
per-endpoint semantics that are easy to get wrong. The authoritative
contract is `schemas/openapi.yaml`; this document explains the parts a
schema cannot express.

Base path is `/api/v1`. Two surfaces sit deliberately outside it: `/scim/v2`
(the SCIM 2.0 spec fixes that path) and `/sso/{org}` (a browser destination
people paste into address bars and IdP consoles, not a JSON operation).

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
has passed and before anything is stored, and carries `balance` and
`resetsAt` beside the standard members so a client can say when to retry.
`503 admission-unavailable` means the check could not be reached; nothing
was recorded. `422 private-agent-cap` refuses one more private agent in a
namespace at its cap, on create and on a `PATCH` that turns an agent
private; nothing already private is touched.

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
anonymous traffic, and burst and sustained budgets are separate (§19).

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
  handle>`**, and the caller must be an owner or admin of that org.
- Published versions are **yanked or transferred, never deleted**. §4.3
  forbids deleting version rows and a database trigger enforces it: digests
  stay resolvable so existing installs can still be verified. PII is purged
  and credentials revoked; what remains is a leak-free tombstone.

## Agent deletion

`DELETE /agents/{ns}/{name}` is described in §9.2 as "only if never
published". It is implemented as **refused once any version row exists at
all**, with distinct messages for "has history" and "a submission is in
flight", because a row still at `submitted` holds a foreign key that §4.3
will not let go. Agents carrying advisories or abuse reports are also
refused; those are trust & safety records that outlive an author's wish to
remove the agent (DEV-021).

## Personal access tokens and their scopes

A personal access token (`POST /user/tokens`, or the Tokens page under the
account) is a least-privilege credential: it can do only what its scopes
allow, and the list is flat — no scope implies another. A browser session
carries the account's full authority instead and is gated by CSRF. The
scopes:

| Scope | What a token with it may do |
| --- | --- |
| `agent:read` | read BriefAgents, versions, reports and search |
| `agent:publish` | create BriefAgents and submit versions |
| `repo:read` | fetch from a BriefAgent's git repository |
| `repo:write` | push to a BriefAgent's git repository |
| `user:profile` | read and change the account's own settings, tokens, keys and sessions |
| `org:admin` | manage an organization's members, teams and settings |
| `review:act` | work the review queue and record decisions (platform staff or a security reviewer) |
| `audit:read` | read an organization's audit log |
| `run:read` | read a hosted run of a BriefAgent, its log and its artefacts |
| `run:write` | start, feed and cancel a hosted run of a BriefAgent |

`run:read` and `run:write` are consumed only by a registry that mounts the
runs extension (`GET /meta` lists it); on a registry without it a token
carrying only these two is refused everywhere a token without the right
scope is. The desktop app's sign-in grant asks for a fixed set
(`agent:read`, `agent:publish`, `repo:read`, `repo:write`, `user:profile`).

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

# The log contract

What a line the server writes contains, what is never in one, and the names
a dashboard or an alert may key on. This page is the reference the log
stack — the collector, the store and the dashboards in `agentry-logging` —
is built against; the code that keeps it is `internal/logx` (the mechanism)
and `internal/logevent` (the names), and a test fails when the code and this
page disagree. The plan behind it is `agentry-notes/plans/log-stack.md`.

## A line

`agentryd` (and the enterprise build, `secureagentryd`, which is the same
runtime) writes one JSON object per line to stderr and nowhere else. Every
line carries:

| Field | Meaning |
|---|---|
| `time`, `level`, `msg` | when, at what level (`DEBUG`, `INFO`, `WARN`, `ERROR`), and the line's own words |
| `service` | the binary's name as invoked: `agentryd` or `secureagentryd` |
| `role` | the role this process runs: `all`, `api`, `git` or `worker` |
| `version` | the build |
| `request_id` | on every line written inside a request (see below); absent outside one |
| `event` | a name from the catalog below, when the line is a signal rather than narration; absent otherwise |

The level is the line's own `level`. When the lines are shipped through a
syslog transport, the syslog severity says which stream the line came from
(everything is stderr) and nothing about its level.

The minimum level is `log.level` in `agentry.yaml` or `AGENTRY_LOG_LEVEL`
(`debug`, `info` — the default — `warn`, `error`).

## The request id

Every request the server handles has one id, returned to the caller as
`X-Request-Id` and carried on every line the request writes — the access
line, a handler's warning, the panic line — and on the audit row of any
mutation the request made (`detail.request_id`). A row and its lines find
each other by it.

The server mints the id (16 hex characters). It honours an inbound
`X-Request-Id` instead — so that one id names a request on the proxy in
front and on the server — only when the operator has said that **the hop
in front sets the header on every request it forwards**
(`http.proxyRequestID: true` / `AGENTRY_PROXY_REQUEST_ID=true`, which
itself needs `http.trustedProxies` ≥ 1, and with `http.trustedProxyCIDRs`
set, a request whose peer is in one of its ranges) and the value matches
`^[A-Za-z0-9-]{8,64}$`. The hop count alone is not enough: anyone can send
the header, and a proxy that merely forwards it would let a caller stamp
its own id onto the server's lines and audit rows. The compose stack's
headless edge sets it (`proxy_set_header X-Request-Id $request_id`); a
site's edge config in front of the server must do the same before the flag
is turned on there.

## The access line

One line per request, `event=http.request`, `msg=http`, at `INFO`:

| Field | Meaning |
|---|---|
| `method`, `path` | as requested |
| `route` | the matched route pattern (`/api/v1/agents/{ns}/{name}`), never the concrete path — the low-cardinality key dashboards group by |
| `status`, `dur_ms`, `bytes` | the response |
| `client_ip` | the caller's address as the `http.trustedProxies` and `http.trustedProxyCIDRs` rule resolves it |
| `user_agent` | as sent |
| `actor`, `actor_via` | the principal's opaque id and how it authenticated (`session`, `pat`, `ssh`); `actor=anonymous` when unauthenticated. A PAT's id may appear (`actor_pat`); the PAT itself never does |

The probes — `/healthz`, `/readyz`, `/metrics` — write no access line. Their
metrics are still recorded.

## The event catalog

A line that is a signal carries `event=<name>`. The names are constants in
`internal/logevent`; a string literal reaching a line is a test failure, as
is a name missing from this table.

| Event | Level | When | Fields beside the common ones |
|---|---|---|---|
| `http.request` | INFO | the access line | see above |
| `http.rate_limited` | INFO | a request refused by a rate class | `class` (`login`, `anon`, `authed`, `abuse_reports`, `scim`, an organization's SCIM data plane over its budget, and `model-input`, a model-input caller or an address presenting job credentials over its budget), `route`; for the git transports, `class` `push` with `agent` (the repository's push budget, over HTTP or SSH), `class` `ssh-key-offer` with `source` (the address's public-key offers to the SSH listener), and `class` `git-concurrent` with `source` (the client address, as resolved through the declared proxies, at its budget of concurrent git operations, over HTTP or SSH) |
| `auth.login_failed` | INFO | a native sign-in failed | `user` (the id when the login named an account; the zero id otherwise). The login as typed is on the audit row, not here |
| `auth.social_rejected` | WARN | a social or directory sign-in was rejected at the token exchange | `provider`, `err` |
| `saml.state_unavailable` | ERROR | a SAML login refused because the shared state behind it could not be read or written; the fail-closed opposite of `failopen.*` | `set` (`assertions`, `requests`), `err` |
| `auth.totp_challenge_unavailable` | ERROR | a 2FA social login's second leg refused because its challenge could not be recorded as consumed in the shared set; fail closed, as `saml.state_unavailable` is (agentry#457). A request that had already ended logs a WARN without the event | `err` |
| `ssrf.refused` | WARN | the private-range guard refused a webhook target | `org`, `delivery`, `endpoint`, `host` |
| `gate.verdict` | INFO | the gate decided a version | `outcome` (`published`, `rejected`, `needs_review`), `version`, `agent`, `run`, `worst_severity`, `findings`, `reason`; and `ruleset` when a new ruleset's redo of the review queue published a held version |
| `gate.error` | WARN | the platform's own failure sent a version to review: stage errors, an unusable policy, the watchdog | `version`, `run`, and `stage_errors` or `kind` + `err` |
| `scan.stage` | INFO | a scanner stage finished | `stage`, `outcome` (`ok`, `error`), `dur_ms`, `findings`, `err` |
| `failopen.audit_stream_drop` | ERROR | an audit archive record was dropped on a full buffer | `action`, `id` |
| `failopen.history_not_scanned` | WARN | a git history the S2 stage did not scan, or scanned only to its size cap; a history scan that failed (`S2/history-error`) holds the version for review and is not counted here | `stage`, `scanner`, `title` |
| `failopen.osv_not_checked` | WARN | a dependency set S7 did not check against OSV | `stage`, `scanner`, `title` |
| `failopen.osv_error` | WARN | an OSV lookup errored and left a declared server with no data (`scanner` is `S7/osv-no-data`; a server S7 does not cover makes the same finding and is not counted here) | `stage`, `scanner`, `title` |
| `failopen.directory_erasure` | ERROR | an account erasure's directory half did not happen: its retries ran out, or the retry could not be queued; the sign-in account is left for the operator to delete | `user`, `attempts`, `err` |
| `git.push_refused` | WARN | the git door refused a submission after a tag push | `agent`, `tag`, `err` |
| `mail.suppressed` | INFO | a notification was withheld from an unverified address (WARN when the user row could not be read) | `user`, `kind` |
| `webhook.delivered` | INFO | a webhook delivery attempt finished | `outcome` (`ok`, `error`), `org`, `delivery`, `attempt`, `status` or `err` |
| `model_input.call` | INFO | a call to a model-input route finished (agentry#608): AI Review of text a model is about to read, or a brokered web search | `op` (`scan`, `search`), `caller` (`staff`, `job`), `job` (a hosted job's id, when a job called), `verdict` (`pass`, `withheld`, `not_scanned`; a search is `withheld` when any result was), `source`, `scanned`, `withheld`, `requests`, `input_tokens`. Never the text, the query or a result's address |
| `audit.<action>` | INFO | the audit mirror: one line per audit event, named by the audit action (`audit.user.login`, `audit.pat.create`, …) | see below |

Each `failopen.*` name is also a `FailOpenEvents{path}` metric increment;
the line is the where and the why, the metric is the count.

## The audit mirror

With `audit.streamKind: log` (`AGENTRY_AUDIT_STREAM_KIND=log`) every audit
event is also written as one line, `msg=audit`, `event=audit.<action>`, with
`audit_id`, `occurred_at`, `actor`, `actor_kind`, `org`, `target_kind`,
`target_id`, `client_ip`, `user_agent`, `request_id` and the record's
`detail` as an object. It is a mirror, not a second record: the row in
`audit_events` is the record and stays append-only; the line is what makes
the event searchable wherever the server's lines are shipped. The detail is
carried as the record has it — what a handler puts on an audit row is bound
by the audit rules, not by this page — and passes through the redaction
below like everything else. The mirror writes synchronously, so it has no
buffer and no drop path of its own; the `file` kind keeps its buffer and its
drop accounting.

## What is never in a line

- **A token or a secret.** Before a line is written, a value under a key
  ending in `token`, `secret`, `password`, `passwd`, `authorization`,
  `cookie`, `api_key`, `private_key`, `signing_key`, `secret_key`,
  `access_key`, `client_secret` or `credential(s)` becomes `[redacted]`,
  and any token the registry minted — 52 base32 characters, with the kind's
  prefix (`agy_` PATs, `agys_` sessions, `agyv_` verification tokens,
  `agyi_` invitations, `agyd_` remembered browsers, `agyscim_` SCIM tokens,
  `agd_` desktop grants, `whsec_` webhook secrets,
  `csrf_` CSRF tokens) or bare (OIDC state and nonce, domain verification)
  — is masked wherever it appears (in a message, a value, an error, a
  nested object), keeping its 12-character display prefix so an incident
  still traces to the credential. Masked, not dropped: the line about the incident
  is worth more than the value it would have leaked. The collector applies
  the same token pattern again as a second net.
- **A person's name or email address.** Lines carry opaque principal ids.
  The log notifier (`notify.kind: log`, the default when no sender is
  configured) says a mail would have gone and to which mailbox with the
  address masked (`a…@example.test`), and never carries a verification
  token; an address cannot be verified through it. Use a sender.
- **A value above 4 KB.** Docker splits a line above 16 KB into pieces that
  are no longer JSON and cannot be reassembled, so every string value is cut
  at 4,096 bytes (on a character boundary) with a `…[truncated]` marker; a
  panic's `stack` keeps 8 KB, the one value worth most of a line.
- **The probes.** No access line for `/healthz`, `/readyz` or `/metrics`.

The client address is in a line (`client_ip`) for as long as the lines are
kept — the retention the log stack sets — and on the audit row for the
audit retention; the privacy page says so.

## Shipping is best-effort

Where the lines go after stderr is the log stack's business (the "Logs"
section of [self-hosting](self-hosting.md)). The transport never stalls the
server and never stops a container from starting; the price is that a
collector that is down loses the lines sent while it was down, and a burst
far above the registry's own rate can lose a small share. The audit record
does not depend on any of it.

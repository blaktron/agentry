# Managed settings

An organization's admins can set values for their members' Agentry clients:
for example, that members may not turn on Unsafe Mode. These are **managed
settings**. The registry signs one document for each version of an
organization's settings and serves it to every active member. The member's
clients verify it and apply it.

A setting is either:

- **locked**: the member cannot change it, and their clients refuse anything
  else; or
- **an organization default**: it applies until the member chooses
  otherwise.

A managed setting only narrows what a member could choose for themselves.
It can forbid something, and it can never switch on something the member has
not chosen.

Managed settings are answered by an extension of the registry. A registry
built from the open core alone serves none, and every member reads back
`204 No Content`.

## The route

`GET /api/v1/user/managed-settings` answers the signed-in caller:

| Status | Meaning |
| --- | --- |
| `200` | The caller's managed settings, as a signed envelope. |
| `204` | No managed settings apply to the caller. |
| `503` | The registry has no base URL, or the document it holds does not verify against the keys it advertises. It never serves a document a client would refuse. |

A session, or a personal access token with the `user:profile` scope, may read it. The answer
is never cached.

## The envelope

The `200` body is a DSSE (Dead Simple Signing Envelope)
envelope:

```json
{
  "payloadType": "application/vnd.agentry.managed-settings+json",
  "payload": "<the document, base64>",
  "signatures": [{ "keyid": "…", "sig": "<base64>" }]
}
```

It is signed with the registry's release-signing key, the same key that signs
release attestations. The keys are published at
`/.well-known/agentry/signing-keys.json`. A client verifies an envelope as
follows:

1. Refuse any `payloadType` other than
   `application/vnd.agentry.managed-settings+json`. The signature covers the
   type, so a release attestation never opens as a document, and a verifier
   that checks the type refuses a document as an attestation.
2. Verify a signature over the DSSE pre-authentication encoding of the type
   and the decoded payload, with a key the client already trusts for this
   registry. The Agentry CLI and desktop pin a registry's keys when you sign
   in. Never choose the key by the signature's `keyid`.
3. Decode the payload strictly (no unknown fields) and validate it.
4. Accept it only if `registry` is the registry the client is signed in to
   and `org` is the organization the signed-in account is an active member
   of. A person belongs to one organization.
5. Refuse a document from the same organization whose `version` is lower
   than the last one the client accepted. A document carries no expiry, so
   without this check an older, looser copy could be replayed.

The Go package `github.com/blaktron/agentry/pkg/managedsettings` does steps 1
to 3 (`Open`). The caller does steps 4 and 5.

## The document

The payload is described by
`schemas/managed-settings-1.schema.json` in the source repository:

```json
{
  "schema": "managed-settings/1",
  "registry": "https://registry.example",
  "org": "acme",
  "version": 7,
  "issuedAt": "2026-11-08T12:00:00Z",
  "settings": {
    "run.unsafeMode": { "value": "forbidden", "locked": true }
  }
}
```

- `registry` is set by the registry when it signs, never by the extension
  that keeps the settings.
- `version` increases with every change the organization's admins make.
- `settings` holds rows of the catalogue below. A registry signs only rows
  it knows, but a newer registry may send rows an older client does not
  know. A client keeps such a row (`Document.Unknown`). When it is locked,
  the client cannot enforce it, so it refuses to run until it is updated.
  When it is a default, the client passes over it.
- A field outside `settings` is a new version of the document, with a new
  `schema` value. A client refuses a schema it does not know.

## The catalogue

Every setting is a row of one catalogue, the table in the core's
`pkg/managedsettings`. The registry checks a document against it before it
signs, and `schemas/managed-settings-1.schema.json` describes the same rows.
A row's value has one of seven kinds, and each kind narrows in one way only:

- **choice**: one of the row's values, listed from the most open to the most
  restrictive. No value switches anything on.
- **set**: a list of the row's members with no repeats and at least one
  member: the members still allowed.
- **cap**: a number above 0. Locked, it is the highest value a member may
  use. As a default, it is the value used when the member set none. A member
  may always choose a lower limit.
- **sources**: where a member may install from: `any`, or
  `organization-and-built-ins` with an optional list of further namespaces.
- **minimum version**: the oldest client that may run. An older one refuses
  runs and names the update.
- **model**: `{"provider": …, "model": …}`, a provider of the row's list and
  a model id. Locked, it is the only model members' runs use; as a default,
  the one a member who chose none runs on.
- **source**: `{"source": …}`, what pays for a service, from the member's
  own key (`member`) through the organization's credits
  (`agentry-credits`) and the organization's own key (`organization-key`)
  to, where the row offers it, none at all (`off`). A row that delivers
  keys names the organization's key with `organization-key` as
  `{"key": {"id": …, "rev": n}}`: a reference the client exchanges for the
  key, never the key. The organization's model key is never delivered:
  `model.source` carries no reference, and runs on it are paid through the
  registry's own endpoint. Web search also names the key's `provider`.

A set, a source list and a minimum version are only ever locked: a default
would have nothing to apply. A set has at least one member, except
`model.signIns`, whose empty list spends no subscription or plan of the
member's.

| Setting | Kind | Value | Strength | What it decides |
| --- | --- | --- | --- | --- |
| `agents.assistant` | choice | `allowed`, `forbidden` | locked or default | Whether members may use the Assistant. |
| `agents.codingAgent` | choice | `allowed`, `forbidden` | locked or default | Whether members may use the Coding agent. |
| `browser.publicWeb` | choice | `allowed`, `forbidden` | locked or default | Whether a run's browser may reach the public web. |
| `bugReports` | choice | `allowed`, `forbidden` | locked or default | Whether members may send bug reports from their clients. |
| `codingTools.allowed` | set | a list of `claude-code`, `codex`, `copilot` | locked only | Which coding tools members' runs may use. |
| `deliverables.destinations` | set | a list of `folder`, `webhook`, `s3` | locked only | Where a run may send its result and files: a folder, a webhook, an S3 bucket. |
| `desktop.applications` | choice | `allowed`, `forbidden` | locked or default | Whether runs may use applications on the member's computer through Agentry Desktop. |
| `desktop.customServers` | choice | `allowed`, `forbidden` | locked or default | Whether runs may use applications the member set up themselves rather than Agentry's catalogue. |
| `desktop.screen` | choice | `allowed`, `forbidden` | locked or default | Whether runs may see and use the member's screen (computer use). |
| `egress.wildcard` | choice | `allowed`, `forbidden` | locked or default | Whether members' policies may allow wildcard egress hosts. |
| `install.acceptRisk` | choice | `allowed`, `forbidden` | locked or default | Whether members may accept a release's risk at install (an unsigned or unscanned release). |
| `install.sources` | sources | `{"scope": "any"}` or `{"scope": "organization-and-built-ins", "namespaces": [...]}` | locked only | Where members may install QuickAgents from: anywhere, or the organization, the built-ins and the namespaces listed. |
| `malwareCheck` | choice | `optional`, `required` | locked or default | Whether a run's malware check of what it downloads is required. |
| `mcpServers.allowVulnerable` | choice | `allowed`, `forbidden` | locked or default | Whether members may run a declared MCP server the registry's gate rates high or critical. |
| `messengers` | choice | `allowed`, `forbidden` | locked or default | Whether persistent agents may reach messengers. |
| `model.customEndpoints` | choice | `allowed`, `https-only`, `forbidden` | locked or default | Whether members' runs may use a model endpoint of their own, and whether it may be plain http. |
| `model.default` | model | `{"provider": …, "model": …}`, a provider of `model.providers`' list | locked or default | The model members' runs use: the only one when locked, the one a member who chose none runs on as a default. |
| `model.providers` | set | a list of `anthropic`, `openai`, `google`, `vultr`, `openrouter`, `poe`, `huggingface`, `copilot`, `agentry`, `custom` | locked only | Which model providers members' runs may use. |
| `model.signIns` | set | a list, possibly empty, of `subscription`, `claude-signin`, `chatgpt-plan`, `copilot-signin` | locked only | Which subscriptions and plans of their own members' runs may spend. |
| `model.source` | source | `member`, `agentry-credits`, `organization-key` | locked or default | What pays for members' models; the organization's key stays with the registry. |
| `persistentReleases` | choice | `allowed`, `forbidden` | locked or default | Whether members may run persistent QuickAgents from the registry. |
| `review.source` | source | `member`, `agentry-credits`, `organization-key` with a key reference, `off` | locked or default | What pays for AI Review, or none. |
| `run.maxCost` | cap | a number above 0, at most 100000 | locked or default | The most a run may cost, in US dollars, as its harness reports it. |
| `run.maxTurns` | cap | a whole number above 0, at most 100000 | locked or default | The most turns a run may take. |
| `run.timeout` | cap | a whole number above 0, at most 604800 | locked or default | The longest a run may take, in seconds. |
| `run.unsafeMode` | choice | `allowed`, `forbidden` | locked or default | Whether members may turn on Unsafe Mode for local runs. |
| `run.where` | set | a list of `local`, `hosted`, `runhost`, `target-host` | locked only | Where members' runs may go: this computer, In Agentry, a runhost, a target host. |
| `schedules` | choice | `allowed`, `forbidden` | locked or default | Whether members may schedule runs. |
| `updates.minimumVersion` | minimumVersion | a version, `"X.Y.Z"` | locked only | The oldest Agentry client that may run; an older one names the update. |
| `webSearch.source` | source | `member`, `agentry-credits`, `organization-key` with a `provider` (`brave`, `tavily`, `exa`, `perplexity`, `youcom`) and a key reference, `off` | locked or default | What pays for web search, or none. |

How the runner holds a run to each row is in the runner reference,
[Managed settings](runner.md#managed-settings).

With `run.unsafeMode`, `allowed` leaves the choice to the member, behind the
client's own confirmation, and `forbidden` makes the client refuse to turn it
on and the runner refuse an unsafe run. A schedule made with
`agentry schedule add --in-unsafe-mode` (a schedule whose consents were given
in Agentry Desktop's Unsafe Mode) does not run while `forbidden` is locked,
and runs again once it is lifted.

**A client applies the rows it enforces.** A client refuses to run while a
document locks a row it does not enforce, naming the setting and the update
it needs, and passes over a default it does not apply. A new row reaches
existing clients that way, so a lock is never silently ignored.

## Delivered keys

When `review.source` or `webSearch.source` names the organization's key, the
member's client exchanges the reference for the key itself:

1. The client makes a key pair for this one request and sends the registry
   the public half, with the key's id and the revision the document names.
2. The registry checks that the caller is an active member, that the newest
   signed document names that key at that revision, and that it holds the
   key at that revision. It then seals the key to the client's public key
   with HPKE (RFC 9180) and answers the sealed value once.
3. The client opens it with the private half, which never left the client,
   stores the key in the operating system's keychain apart from the member's
   own keys, and drops the private half.

The suite is `hpke-mlkem768x25519-hkdfsha256-chacha20poly1305`: ML-KEM-768
with X25519, HKDF-SHA256 and ChaCha20-Poly1305. The seal binds in the
registry's origin, the organization's handle, the account, the key's id and
its revision, so a sealed key opens only for the request it answers.
`pkg/managedsettings` has both sides: `NewDeliveryKey` and
`DeliveryKey.Open` for a client, `SealDelivery` for a registry.

A client never shows a delivered key, and never writes it into a plan, a
receipt or a log. It asks again when the document names a new revision, and
deletes the key when no document names it, or when the member leaves the
organization. A key on a member's computer can be read by whoever
administers that computer, as the member's own keys can.

## For an extension

An extension implements `extension.ManagesSettings`:

```go
ManagedSettings(ctx context.Context, user uuid.UUID) (*extension.ManagedSettingsEnvelope, error)
```

It returns the envelope signed for the person's organization's current
version, or nil when none apply. It reads membership at the call, so a
former member gets nil at their next fetch.

The extension signs with `Deps.ManagedSettings`, which validates the
settings against the catalogue, binds them to the registry and the
organization, and signs them with the registry's signing key. Only a process
that holds the key has a signer: in a deployment split into roles that is
the worker, not the api, so the extension signs in a job and stores the
envelope, and the api serves what was stored. Before it serves an envelope,
the core checks it against the keys the registry advertises and the registry
it names. A stored envelope with no signature by the signer's current key
(`KeyID`) was signed before a key rotation and should be signed again.

A deployment has one such extension: a second one panics at start-up.

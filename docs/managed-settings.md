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
6. When the document is bound to its members (schema `managed-settings/2`,
   below), accept it only if `members` names the signed-in account. Check
   this every time the client loads a document, its own cached copy
   included.

The Go package `github.com/blaktron/agentry/pkg/managedsettings` does steps 1
to 3 (`Open`) and step 6 (`Document.For`). The caller does steps 4 and 5.

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

### Documents bound to their members

An organization whose admins set settings for teams has more than one
document at each version: one for each combination of teams that some
member belongs to, and one for the members in none of them. The registry
binds each of these to the accounts it is for, so that a member who holds a
colleague's document cannot put it in place of their own. Such a document has
the schema `managed-settings/2`, described by
`schemas/managed-settings-2.schema.json`, and one more field:

```json
"members": {
  "salt": "q3T1Yk0Cq8n2vZb6m4V0xw==",
  "digests": ["0c4f…", "9a17…"]
}
```

- `salt` is 16 random bytes, base64, drawn for this document.
- `digests` holds one entry for each account the document is for: the first
  16 bytes of SHA-256 over the bytes `agentry managed-settings member`, a
  zero byte, the salt and the account's id, in lowercase hex, sorted. The
  document names its members only to a client that knows its own account.
- A client accepts it only if the digest of its signed-in account's id is
  in the list. When a member joins or leaves a team, the registry signs the
  documents again at the same version.

An organization without team settings has one document at each version,
which every member receives alike, with the schema `managed-settings/1` and
no `members`. Team settings need Agentry CLI 0.7.55 or later, or a desktop
that includes it, since an older client refuses the second schema and keeps
the copy it already holds.

## The catalogue

Every setting is a row of one catalogue, the table in the core's
`pkg/managedsettings`. The registry checks a document against it before it
signs, and `schemas/managed-settings-1.schema.json` describes the same rows.
A row's value has one of thirteen kinds. The first eight narrow in one way
only:

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

- **quickAgents**: the list of QuickAgents the organization gives its
  members, described below.

The other five configure the members' persistent agents. They grant no
capability of their own:

- **text**: a string of at most the row's length, with no control
  characters but newlines and tabs: an agent's name or personality.
- **toggle**: `true` or `false`: whether an agent starts with Agentry.
- **servers**: a list of at most 20 remote MCP servers, each
  `{"name": …, "url": …, "auth": …}` with a lower-case name, an address a
  remote server may have (`https`, a public host, port 443, no query, at
  most 512 characters) and `oauth` or `none` to sign in with. The
  organization delivers no secret for them: an `oauth` server signs in with
  the member's own connection, made with `agentry agent connect` (CLI v0.7.53
  or later), and until then the agent starts without it.
- **packs**: a list of at most 20 of the organization's shared knowledge
  packs, by name.
- **tool models**: `{"claude-code": …, "codex": …, "copilot": …}`, any of
  them, each mapped to a model id.

A set, a source list and a minimum version are only ever locked: a default
would have nothing to apply. A set has at least one member, except
`model.signIns`, whose empty list spends no subscription or plan of the
member's.

| Setting | Kind | Value | Strength | What it decides |
| --- | --- | --- | --- | --- |
| `agents.assistant` | choice | `allowed`, `forbidden` | locked or default | Whether members may use the Assistant. |
| `agents.assistant.knowledge` | packs | a list of the organization's shared packs | locked or default | Knowledge packs on members' Assistant. |
| `agents.assistant.name` | text | at most 64 characters | locked or default | The name members' Assistant goes by. |
| `agents.assistant.personality` | text | at most 4000 characters | locked or default | The personality members' Assistant takes on. |
| `agents.assistant.runOnStart` | toggle | `true`, `false` | locked or default | Whether members' Assistant starts when Agentry starts. |
| `agents.assistant.servers` | servers | a list of `{"name", "url", "auth"}` | locked or default | Remote MCP servers on members' Assistant. |
| `agents.codingAgent` | choice | `allowed`, `forbidden` | locked or default | Whether members may use the Coding agent. |
| `agents.codingAgent.knowledge` | packs | a list of the organization's shared packs | locked or default | Knowledge packs on members' Coding agent. |
| `agents.codingAgent.servers` | servers | a list of `{"name", "url", "auth"}` | locked or default | Remote MCP servers on members' Coding agent. |
| `agents.unreviewed` | choice | `allowed`, `forbidden` | locked or default | Whether members may let a persistent agent read web pages Without AI Review. |
| `browser.publicWeb` | choice | `allowed`, `forbidden` | locked or default | Whether a run's browser may reach the public web. |
| `bugReports` | choice | `allowed`, `forbidden` | locked or default | Whether members may send bug reports from their clients. |
| `codingTools.allowed` | set | a list of `claude-code`, `codex`, `copilot` | locked only | Which coding tools members' runs may use. |
| `codingTools.models` | tool models | `{"claude-code": …, "codex": …, "copilot": …}`, any of them | locked or default | The model each coding tool uses in members' runs. |
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
| `quickagents` | quickAgents | a list, at most 100, of `{"ref": "ns/name", "version": "X.Y.Z" or "latest", "mode": "required" or "offered", "preset": {…}, "presetLocked": true or false}`, one per ref | locked only | The QuickAgents the organization gives its members, and the run settings their runs start from. |
| `review.source` | source | `member`, `agentry-credits`, `organization-key` with a key reference, `off` | locked or default | What pays for AI Review, or none. |
| `run.maxCost` | cap | a number above 0, at most 100000 | locked or default | The most a run may cost, in US dollars, as its harness reports it. |
| `run.maxTurns` | cap | a whole number above 0, at most 100000 | locked or default | The most turns a run may take. |
| `run.timeout` | cap | a whole number above 0, at most 604800 | locked or default | The longest a run may take, in seconds. |
| `run.unsafeMode` | choice | `allowed`, `forbidden` | locked or default | Whether members may turn on Unsafe Mode for local runs. |
| `run.where` | set | a list of `local`, `hosted`, `runhost`, `target-host` | locked only | Where members' runs may go: this computer, In Agentry, a runhost, a target host. |
| `schedules` | choice | `allowed`, `forbidden` | locked or default | Whether members may schedule runs. |
| `updates.minimumVersion` | minimumVersion | a version, `"X.Y.Z"` | locked only | The oldest Agentry client that may run; an older one names the update. |
| `webSearch.source` | source | `member`, `agentry-credits`, `organization-key` with a `provider` (`brave`, `tavily`, `exa`, `perplexity`, `youcom`) and a key reference, `off` | locked or default | What pays for web search, or none. |

In `quickagents`, a **required** QuickAgent is installed on every member's
signed-in client through the ordinary install path (its digest, signature,
the gate's verdict and the malware check all apply), and cannot be
uninstalled while the organization requires it; an **offered** one is listed
for the member to install. `version` pins a release or follows the newest
(`latest`). The member still consents to a QuickAgent's contract on its first
run: an assignment never consents on their behalf. A `preset` holds run
settings: `model` (`{"provider", "model"}`), `timeoutSeconds`, `maxTurns`,
`where` (a place of `run.where`) and `inputs` (at most 32, each value at most
4 KiB). Each is a default the member may change, or fixed with
`presetLocked`. Every other row still holds the run, so a preset never lifts
a cap or a lock.

The `agents.assistant.*` and `agents.codingAgent.*` rows configure the
members' Assistant and Coding agent. A locked value replaces the member's
own and its control is shown as managed; a default fills only what the
member has not set. Servers and knowledge packs are put on the agent's
roster as the organization's, and the member consents to them at the
agent's next start, as to anything they add themselves. The runner's own
rules for servers (`mcpServers.allowVulnerable`, `desktop.customServers`)
still apply. Locked, they have no switch; as a default, the member may
switch them off. `agents.unreviewed` decides whether a member may switch a
persistent agent's web reading to Without AI Review. No row turns that on.

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

## Machine settings

Machine settings are managed settings that the administrator of a computer
deploys: with a mobile device management configuration profile, Group
Policy, or their own tools. Agentry's CLI reads them from v0.7.55, and
Agentry Desktop from 0.7.43. They need no registry feature, so a
self-hosted deployment can use them too.

| System | Where |
|---|---|
| Linux and other Unix systems | `/etc/agentry/managed.json` |
| macOS | the managed preferences domain `net.secureagentry.agentry`, `/Library/Managed Preferences/net.secureagentry.agentry.plist` (a configuration profile's payload) |
| Windows | the values `Registry`, `RequireOrg` and `Settings` of `HKLM\SOFTWARE\Policies\SecureAgentry\Agentry` |

The file holds three keys, each optional. On macOS they are the profile
payload's keys, and on Windows they are string values, with `Settings` as a
JSON object in a string.

```json
{
  "registry": "https://secureagentry.net",
  "requireOrg": "acme",
  "settings": {
    "run.unsafeMode": { "value": "forbidden", "locked": true }
  }
}
```

- **`registry`** pins the registry. The client uses it whatever `--registry`,
  `AGENTRY_REGISTRY` or the client's own configuration names, and says once
  that the other registry is not used. Agentry Desktop lists no other
  registry, adds none and sends a sign-in to no other. It must be an `https` address, or
  `http` on this computer's own address.
- **`requireOrg`** is an organization's handle on the pinned registry. Until
  the person is signed in there as an active member of it, no run starts.
  The refusal names the organization and the sign-in command, and Agentry
  Desktop opens on its sign-in with the same sentence. Membership is
  known from that organization's signed document, so the organization must
  hold at least one managed setting for its members.
- **`settings`** are catalogue settings, each locked or a default, as in an
  organization's document. They come before every organization's settings,
  so a lock set here wins, and they stay in force when the person signs out.
  A source (`model.source`, `review.source`, `webSearch.source`) may be
  `member` or `off` here. An organization's key or credits need a registry's
  document.

**Who can write it.** On Linux, other Unix systems and macOS, the file and
every folder above it must belong to root and be writable by no group or
other, and the file must be a regular file. Otherwise the client cannot use
the settings. No run starts, and every command that picks a registry stops,
because the administrator's registry is then unknown; the refusal says why. `HKLM\SOFTWARE\Policies`
on Windows is writable by administrators alone. `agentry managed show` lists
the machine settings, where they were read, the pinned registry and the
required organization. Its `--json` output carries them under `machine`.

**Templates.** Each release of the CLI and of Agentry Desktop carries
`agentry-<version>-machine-settings-templates.zip` (the desktop's is
`agentry-desktop-<version>-machine-settings-templates.zip`), listed in the
release's signed `SHA256SUMS`. It holds `agentry.admx` and
`en-US/agentry.adml`, an administrative template for Group Policy and
Intune with the three values, and `agentry.mobileconfig`, a sample macOS
configuration profile for the managed preferences domain. Download it from
the release on [the CLI's releases](https://github.com/blaktron/agentry-cli/releases)
or [the desktop's](https://github.com/blaktron/agentry-desktop/releases),
and check it against the release's sums as you would a binary.

**What they do not stop.** Machine settings govern Agentry's own clients.
They raise what it takes to lift a lock from "the person" to "this
computer's administrator", which is where a computer managed by an IT
department already is. A person who administers their own computer can
still remove the settings, uninstall the client or run a modified build.
Machine settings are not tamper-proofing against the computer's
administrator.

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

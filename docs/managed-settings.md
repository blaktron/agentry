# Managed settings

An organization's admins can set values for their members' Agentry clients:
for example, that members may not turn on Unsafe Mode. These are **managed
settings**. The registry serves each member one signed document with the
settings that apply to them, and the member's clients verify it and apply it.

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
| `503` | The registry has no signing key or no base URL, so it cannot serve a document a client could verify. |

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
   and `account` is the signed-in account's id.
5. Refuse a document from the same organization whose `version` is lower
   than the last one the client accepted. A document carries no expiry, so
   without this check an older, looser copy could be replayed.

The Go package `github.com/blaktron/agentry/pkg/managedsettings` does steps 1
to 3 (`Open`). The caller does steps 4 and 5.

## The document

The payload is described by
[`schemas/managed-settings-1.schema.json`](../schemas/managed-settings-1.schema.json):

```json
{
  "schema": "managed-settings/1",
  "registry": "https://registry.example",
  "account": "01a1bc05-113e-7144-90d7-a5550a7b3516",
  "org": "acme",
  "version": 7,
  "issuedAt": "2026-11-08T12:00:00Z",
  "settings": {
    "run.unsafeMode": { "value": "forbidden", "locked": true }
  }
}
```

- `registry` and `account` are set by the registry when it signs, never by
  the extension that supplies the settings.
- `version` increases with every change the organization's admins make.
- `settings` holds rows of the catalogue below. A registry signs only rows
  it knows, but a newer registry may send rows an older client does not
  know. A client keeps such a row (`Document.Unknown`). When it is locked,
  the client cannot enforce it, so it refuses to run until it is updated.
  When it is a default, the client passes over it.
- A field outside `settings` is a new version of the document, with a new
  `schema` value. A client refuses a schema it does not know.

## The catalogue

| Setting | Values | What it decides |
| --- | --- | --- |
| `run.unsafeMode` | `allowed`, `forbidden` | Whether members may turn on Unsafe Mode for local runs. With `allowed`, the member decides, behind the client's own confirmation. With `forbidden`, the client will not turn it on and the runner refuses an unsafe run. No value turns Unsafe Mode on. |

## For an extension

An extension implements `extension.ManagesSettings`:

```go
ManagedSettings(ctx context.Context, user uuid.UUID) (*extension.ManagedSettingsContent, error)
```

It returns the organization's handle, the version and the settings for that
person, or nil when none apply. It reads membership at the call, so a former
member gets nil at their next fetch. The core validates the settings against
the catalogue, binds them to the registry and the account, and signs them. A
deployment has one such extension: a second one panics at start-up.

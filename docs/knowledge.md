# Knowledge packs in the registry

A knowledge pack is an LLM wiki: compiled markdown pages with an index,
together with the documents they were compiled from, at most 10 MB, that a
run searches through the knowledge tools over a read-only `/knowledge`
mount. [Running BriefAgents](runner.md#knowledge-packs) covers making one
and attaching it to a run. This page is the registry's side: how a
signed-in account keeps its packs here, how they are sealed, what the
registry reads of them, and when they are destroyed.

No route publishes a pack, lists it anywhere public, or lets another
account read it. What the registry itself reads of a pack is below
([What the registry reads](#what-the-registry-reads)).

## What the registry holds

A pack in the registry is two things:

- **Its row**, which holds what may be read without the pack's data key:
  the name, the size in bytes, the file and page counts, the tree's
  digest, the scan state and the scan report. The row also holds the data
  key, but only in the form the owner's key wrapper sealed it.
- **Its tree**, sealed. This is the canonical tar of the pack's `wiki/` and
  `sources/` (the form whose SHA-256 is the pack's digest), encrypted
  under the pack's own random data key in 64 KiB AES-256-GCM frames
  (`pkg/packseal`). It is stored in the blob store under the owner's
  prefix.

No page is stored in the clear: not in a blob, not in a table, not in the
scan report. The report says where each finding is (the file, the line,
the chunk) and never quotes the words there. The owner holds the tree and
can read the line themselves.

## The key wrapper

The client makes a random 32-byte data key for each pack and seals the
tree with it. The data key never travels or rests in the clear beside the
tree. The registry wraps it for the pack's owner:
`POST /knowledge/keys/wrap` gives back a wrapped key, which the client
keeps beside its sealed pack. `POST /knowledge/keys/unwrap` gives the data
key back over TLS, and only to the owner it was wrapped for. For anyone
else the answer is 404 `knowledge-key-not-found`, whether the key was
wrapped for someone else, under a key since destroyed, or altered. No
route ever returns what wraps a key.

Wrapping is a seam, `KeyWrapper` on `pkg/extension` (`Wrap`, `Unwrap`,
`Destroy`):

- **The core's wrapper** uses the deployment's knowledge sealing key,
  `AGENTRY_KNOWLEDGE_SEALING_KEY` (`knowledge.sealingKey`). It is 32
  random bytes, base64, and it is a key of its own: the server refuses to
  start if it is the auth sealing key. Each owner's key-encryption key is
  derived from it with HKDF-SHA256 and a random salt of that owner's, and
  the owner is named in the AEAD's additional data. A wrapped key
  presented by another account does not open, even copied whole. When an
  owner is erased, their salt is deleted in the erasure's own
  transaction, so every copy of their wrapped keys stops opening,
  including one kept on a laptop.
- **An extension's wrapper** replaces the core's wrapper and nothing else.
  The store, the routes, the scan and the erasure stay the core's.
  SecureAgentry wraps each key to the account's own certificate.

Without a knowledge sealing key and without an extension that wraps keys,
the store is off. Every `/knowledge/…` route answers 503
`knowledge-unconfigured`, and `GET /meta` reports `features.knowledge:
false`. In dev mode a fixed insecure key stands in, as it does for the auth
sealer.

## The routes

Every route is the caller's own. A session works, or a personal access
token with `knowledge:read` (list, read, download, export, unwrap, the
meter) or `knowledge:write` (create, upload, delete, wrap). A pack is
looked up by its owner, so another account's pack is one that does not
exist: 404, for a fellow member of the owner's organization too.

| Route | What it does |
|---|---|
| `POST /api/v1/knowledge/keys/wrap` | wrap a 32-byte data key for the caller |
| `POST /api/v1/knowledge/keys/unwrap` | the data key a wrapped key holds, to its owner alone (`Cache-Control: no-store`) |
| `POST /api/v1/knowledge/packs` | create an empty pack: a name (1-64 lowercase letters, digits, `.`, `-` or `_`, one per owner, 409 `knowledge-name-taken`) and the wrapped key, which must open for the caller |
| `PUT /api/v1/knowledge/packs/{id}/tree` | upload the sealed tree in one body (below), which replaces the one before and is scanned (202, `scanning`) |
| `GET /api/v1/knowledge/packs` | the caller's packs, by name, each with its scan state and report |
| `GET /api/v1/knowledge/packs/{id}` | one pack and its report |
| `GET /api/v1/knowledge/packs/{id}/tree` | the sealed tree as stored, with its digest in `X-Agentry-Knowledge-Digest`; the client opens it with the unwrapped key. 409 `knowledge-scanning` while the pack is scanned |
| `GET /api/v1/knowledge/packs/{id}/export` | the tree decrypted, `application/x-tar`, `no-store`: the canonical tar whose SHA-256 is the digest. 409 `knowledge-scanning` while the pack is scanned |
| `DELETE /api/v1/knowledge/packs/{id}` | the pack, its stored trees and its wrapped key |
| `GET /api/v1/knowledge/usage` | the meter: `bytes` kept here, the allocation `max` (0 is no cap), `packs` |
| `GET /api/v1/platform/knowledge?owner=<handle>` | platform staff only (a staff token needs `knowledge:read`): an account's packs by name, state and size, and nothing of their content, digest, report or key |

**The upload.** A tree arrives as one PUT of the sealed tree. A body
larger than a sealed 10 MB pack can be is 413 `upload-too-large`. The
registry then opens the tree before keeping it: it unwraps the pack's
data key, opens the frames, and reads the tar. The tar must hold only
regular files under `wiki/` and `sources/`, in byte order, with clean
paths, a name at most once, at most 10 MB and 2000 files (otherwise 413
`knowledge-too-large`). Its bytes must be the digest its header names
(otherwise 422 `knowledge-digest-mismatch`), and they must be the
canonical tar of its files. Anything else that is not this pack's sealed
tree is 422 `knowledge-tree-invalid`. Nothing is stored for a refused
upload.

**The allocation.** A tree that is larger than the one it replaces must
fit the owner's allocation. Otherwise the answer is 413
`knowledge-allocation` with `bytes` and `max`. Only what is kept in the
registry counts; a pack on a machine does not. The check is made under a
lock on the owner, so two uploads cannot both slip under the cap. A cap
never deletes: a smaller or equal tree is always taken, and nothing
already stored is touched. The allocation is `Features.KnowledgeBytes` on
the entitlements resolver. The core's resolver answers enabled, with the
cap `AGENTRY_KNOWLEDGE_BYTES_PER_ACCOUNT`
(`limits.knowledgeBytesPerAccount`, in bytes; 0, the default, is no cap).
A closed build's resolver answers by tier. The account page under
`/ui/account` shows the meter.

## The scan

A pack is `scanning` from each upload until its `knowledge.scan` job ends
(the sandbox queue, the same worker that scans a version). It is `ready`
after the job, whether it has findings or not: the report is a record,
never a gate. A pack is unusable only while it is
`scanning`: its download and export answer 409 `knowledge-scanning`. A
pack whose stored tree could not be read on the job's last attempt is
`failed`, with no report.

The scan reads every text file of the tree: every page and every source.
A source's original that is not text (a PDF, an image) is listed under
`notRead`, and its extracted text beside it, `<name>.txt`, is read in its
place. The scan runs these stages:

- **The prose stages over every text file**: S2 secrets (the excerpt is
  masked, and not stored in any case), S3 hidden content, S4 signatures,
  and S8's URL reputation. A pack has no manifest, no code and no listing,
  so the stages that read those do not run.
- **AI Review, twice**: first over `sources/`, the documents the pack was
  compiled from, then over `wiki/`, the pages compiled from them. Each
  half is read in chunks no larger than the judge provider says it reads
  in one call (the provider's `InputLimit`). That is about 50 KB for Jev
  (`typesafe`), 256 KiB for the chat providers, and eight requests' worth
  for the classifier. A file longer than a chunk is read in pieces, cut at
  line ends where one falls, so every byte is read. With the judge
  provider `none`, the review writes "AI Review not configured" and reads
  nothing; the prose stages still run. A stage that fails (a timeout, a panic) is marked
  `failed`, and a judge that fails on a chunk is counted. Either way the
  job retries, and its last attempt records the review with the failed
  stages and chunks named.

The report (`KnowledgeScanReport`) names the stages that ran, what was
read (`sources`, `wiki`, `bytes`, `notRead`), and the review: the
provider, the model, the rubric hash, `chunkBytes`, `sourceChunks`,
`wikiChunks`, `failed`, and the provider's reported token use. It also
lists the findings, each placed in its half (`sources` or `wiki`) by file
and line, or by chunk for AI Review.

The report says what read the pack and what it found, and claims nothing
more: scanned, N findings.

## What the registry reads

The seal keeps a pack's words out of every blob, table and backup. It does
not keep them from the registry's own code:

- The registry unwraps the data key and opens the tree on every upload,
  to check it, and in the scan job, to scan it. It keeps nothing of what
  it read beyond the counts and the report.
- On a core registry, whoever holds both the knowledge sealing key and the
  database can unwrap every data key. Keep the key as you keep the auth
  sealing key: in the environment, never in the database or its backups.
  An extension's wrapper moves that trust to its own keys.
- AI Review sends the text of each chunk to the judge provider the
  registry is configured with. With a hosted model, that provider reads
  the pack. With `none`, nothing leaves the registry.

## Erasure

An owner's packs, their stored trees and what opens their keys are
destroyed:

- when a person erases their account (`POST /user/delete`);
- when a person clears their data (`POST /user/clear-data`), since packs
  are data;
- when an organization's decommission completes, for the organization's
  packs.

The rows and the owner's salt go in the erasure's own transaction. Once it
commits, the wrapper's `Destroy` runs (for an extension's own keys; the
core's salt is already gone), and then the sealed blobs are deleted. A
step that fails is logged and handed to a `knowledge.erase` job that
retries it. Until it succeeds, a blob left behind is sealed under a data
key that no one can unwrap.

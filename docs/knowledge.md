# Knowledge packs in the registry

A knowledge pack is an LLM wiki: compiled markdown pages with an index,
together with the documents and the brief they were compiled from, at most
10 MB, that a run searches through the knowledge tools over a read-only
`/knowledge` mount. A pack may come from documents, from a brief alone
(what it should cover and for whom, kept as `sources/brief.md`), or both;
its pages cite `[src: doc:<path>]`, and, with CLI v0.6.43 or later, also
`[src: web:<url>]` for a page the Knowledge Creator read on the web (the
page's text is not kept) and `[src: model]` for what it took from its
model's own knowledge. [Running QuickAgents](runner.md#knowledge-packs) covers making one,
keeping it in the local store and attaching it to a run, and
[Hosted runs](hosted-runs.md#knowledge-attached-to-a-run) attaching it to
a run on Agentry's infrastructure. This page is the registry's side: how a
signed-in account keeps its packs here, how they are sealed, what the
registry reads of them, and when they are destroyed.

No route publishes a pack, lists it anywhere public, or lets another
account read it. The one exception is an organization's shared pack, which
its active members read ([Shared knowledge](#shared-knowledge-in-an-organization)).
What the registry itself reads of a pack is below
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

A pack is not stored in the clear on its way to a hosted run either. When
a run attaches a pack, or a hosted build is given one, the registry opens
the tree at the hand-off and stages it for the sandbox host sealed again,
under a fresh key that only the job carries. The host opens it as it streams
it into the job's own directory, and both copies are deleted with the job
([a run's data at rest](hosted-runs.md#a-runs-data-at-rest)).
While the run uses the pack, the tree is in the clear on that host, as a
run's own files are.

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
  SecureAgentry wraps each key to the account's own certificate (an
  organization's own, for its shared packs). The certificate's private key
  is sealed by the vault: OpenBao's Transit key `hosted-keys`, with the
  account or the organization as the context and the certificate's serial
  bound in, so neither the CA's master key nor the database opens it, and
  every open is a Transit decrypt in OpenBao's audit. A SecureAgentry
  deployment without the vault seals it under the CA's master key instead
  ([Agentry's CA](hosted-runs.md#agentrys-ca-and-enrolment)).

Without a knowledge sealing key and without an extension that wraps keys,
the store is off. Every `/knowledge/…` route answers 503
`knowledge-unconfigured`, and `GET /meta` reports `features.knowledge:
false`. In dev mode a fixed insecure key stands in, as it does for the auth
sealer.

## The routes

Every route under `/knowledge/` is the caller's own. A session works, or a personal access
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
| `GET /api/v1/platform/knowledge?owner=<handle>` | platform staff only (a staff token needs `knowledge:read`): an account's or an organization's packs by name, state and size, and nothing of their content, digest, report or key |

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
lock on the allocation, so two uploads cannot both slip under the cap. A
cap never deletes: a smaller or equal tree is always taken, and nothing
already stored is touched.

The allocation is `Features.KnowledgeBytes` on the entitlements resolver.
The core's resolver answers enabled, with the cap
`AGENTRY_KNOWLEDGE_BYTES_PER_ACCOUNT` (`limits.knowledgeBytesPerAccount`,
in bytes; 0, the default, is no cap). A closed build's resolver answers by
tier, and it may pool owners. A resolver that also implements
`PoolsKnowledge` (`pkg/extension`) names the pool an owner's packs draw
on: a key, the owners it counts, and its cap. A paid organization's seats,
for example, are shared by its own packs and its members'. An upload into
a pool is then reserved under a lock on the pool's key and counted
against every pooled owner's packs. Every owner in a pool sees the pool's
total, in the meter and in a refusal; that is what sharing a cap means.

The meter (`GET /knowledge/usage`, and the account page under
`/ui/account`) reports the caller's own packs (`bytes`, `packs`), what
counts against the allocation (`used`, the pool's total when `pooled`),
and the cap (`max`).

**The scan's admission.** Each upload that stores a new tree queues its
scan, and a closed build may admit, and charge for, that scan through
`AdmitsKnowledge` (`pkg/extension`): AI Review costs 1 credit an operation
where an extension charges for it, whatever the pack's size; the core
charges nothing and asks nothing. The extension is asked once per upload,
with the account uploading, the pack's owner (the account or an
organization) and the tree's size, after the registry has read the tree
and before anything is stored. Its refusal is answered in its own status
and words (for example 402) and stores nothing; if it cannot answer, the
upload is 503 `admission-unavailable` and stores nothing. An upload the
registry refuses itself (413, 422) is never asked about, and one the
allocation then refuses is admitted and voided. An upload of the tree the
pack already holds stores nothing and queues no scan, so it is never
admitted; a pack whose tree could not be read to scan (`failed`) is
scanned again on the same tree without being admitted. A pack an
extension builds and puts back through `Deps.Knowledge` is not admitted
here: the build's own price covers its scan.

**An extension's door.** A closed build reaches the store through
`Deps.Knowledge` (`pkg/extension`), the way the hosted build of the
Creator does in SecureAgentry: it makes a pack under a data key the
registry makes and wraps for the owner, reads a pack's metadata and its
tree decrypted (the canonical tar, refused while the pack is scanned),
reads the owner's meter, and puts a tree back. A tree put back is sealed
under the pack's own data key, keeping the stored tree's pack id in its
header, and stored through the same path as an upload through the routes:
opened and checked, counted against the pool under its lock, the tree it
replaces deleted, the scan queued. It lands only if the pack still holds
the tree the extension read (compared under the pack's row lock), so a
build never overwrites an upload made while it ran; a tree the pack
already holds is not stored again, and is no conflict, so a retried
replace that already landed is harmless. The data key never leaves the
core through it.

In SecureAgentry two more doors read packs. A hosted knowledge build may
take a brief instead of documents, or beside them, and search the web
through the registry's model-input routes, each search priced inside the
build's hold ([a knowledge build](hosted-runs.md#a-knowledge-build)). A
hosted draft may read the account's `ready` packs, at most 10 MB in all; it
does not scan them again, and the files their scan flagged are withheld
from the Drafter ([a hosted draft](hosted-runs.md#a-hosted-draft)). On a
person's computer, `agentry draft --knowledge` scans first any pack whose
record is not a registry's ([Running QuickAgents](runner.md#agentry-draft-description)).

## Shared knowledge in an organization

An organization can keep packs of its own, which every active member
reads. Its admins create them, upload to them, mark them exportable and
delete them. The data key is wrapped for the organization: on a core
registry under the knowledge sealing key with the organization's own salt,
and on SecureAgentry to the organization's own key. The routes are the
personal ones under the organization, with the same bodies and answers:

| Route | Who |
|---|---|
| `POST /api/v1/orgs/{org}/knowledge/keys/wrap` | admins: wrap a data key for the organization |
| `POST /api/v1/orgs/{org}/knowledge/keys/unwrap` | members: the data key a wrapped key of the organization's holds (`no-store`) |
| `POST /api/v1/orgs/{org}/knowledge/packs` | admins: create an empty pack, its wrapped key opening for the organization |
| `PUT /api/v1/orgs/{org}/knowledge/packs/{id}/tree` | admins: upload the sealed tree |
| `PATCH /api/v1/orgs/{org}/knowledge/packs/{id}` | admins: `{"exportable": true}` lets members export the pack; `false` takes it back |
| `DELETE /api/v1/orgs/{org}/knowledge/packs/{id}` | admins |
| `GET /api/v1/orgs/{org}/knowledge/packs`, `…/{id}`, `…/{id}/tree` | members: the list, one pack, the sealed tree |
| `GET /api/v1/orgs/{org}/knowledge/packs/{id}/export` | admins, and members once the pack is marked exportable; otherwise 403 `knowledge-not-exportable` |
| `GET /api/v1/orgs/{org}/knowledge/usage` | members: the organization's meter |

A shared pack reads `shared: true`, `org` (the organization's handle) and
`exportable`. A token needs `knowledge:read` or `knowledge:write` as for a
person's own packs, and an organization that requires SSO requires it here
as on its other routes. While an organization is in its decommission hold,
the reads still work and the writes do not.

**Membership is checked at every call.** The roles a request is judged
by are its caller's active memberships, read again for every request. A
member who is removed, or who leaves, is refused the next unwrap, so a
sealed copy on their machine stays sealed: the client asks for the key
each time it opens the pack and keeps it only in memory. A pending member
holds nothing. Anyone who is not an active member of the organization,
another organization's members and platform staff included, is answered
404 on every route, as for another account's pack. Staff see an
organization's packs by name and size through `GET /platform/knowledge`.

**The allocation.** An organization's packs count against the allocation
the organization draws on. On a core registry that is the organization
alone under `AGENTRY_KNOWLEDGE_BYTES_PER_ACCOUNT`, apart from its members'
own packs. A closed build's resolver may pool them; SecureAgentry counts a
paid organization's shared packs and its members' in one pool.

**The audit log.** Creating a shared pack, marking it exportable or not,
exporting it and deleting it are recorded in the organization's audit log
(`org.knowledge_create`, `org.knowledge_update` with `exportable`,
`org.knowledge_export`, `org.knowledge_delete`), each naming the pack and
nothing of its content. The organization's packs and its key go with it
when it is erased after its decommission ([Erasure](#erasure)).

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
- **AI Review, twice**: first over `sources/`, the documents and the brief
  the pack was compiled from, then over `wiki/`, the pages compiled from them. Each
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

## A release that ships a pack

A QuickAgent may carry packs of its own in its release archive, under
`knowledge/<name>/`, declared in its manifest's `knowledge.ships`
([quickagents.md](quickagents.md#knowledge-packs-the-release-ships)).
Such a pack is not in this store: it has no owner, no data key and no
seal, because it is part of a release, which is public or private as the
QuickAgent is and signed with the rest of its archive.

At submit the registry refuses a release whose packs are not what its
manifest says (rule V11): a name with no pack, a pack outside the CLI's
layout, a `manifest.json` whose digest, bytes or pages are not the files
beside it, or a file under `knowledge/` in no shipped pack. Each pack is
held to its own caps, 10 MB and 2,000 files, outside the release's own
quotas (V8).

The version's scan reads each shipped pack as this store's scan reads a
pack — the same prose stages over every page and source, the same AI
Review over `sources/` and then `wiki/` in chunks — as one more stage of
the version's scan, `SK`. What differs is what the result does:

- **Its findings gate.** They are the release's findings, under scanner
  `SK/<stage>/<rule>` with file paths in `knowledge/<name>/` and the pack,
  the half and the chunk in their detail, and the gate decides on them as
  on any other. They keep their excerpts, as a release's findings do.
- **An incomplete read fails closed.** A stage that did not finish, or a
  chunk the judge could not read, fails `SK`, and the version goes to
  review, as any failed stage sends it.
- **The report is the version's.** The version's report
  (`GET …/versions/{version}/report`) carries a `knowledge` section, one
  `ShippedKnowledgeScan` a pack: its name and its `KnowledgeScanReport`
  (the stages, what was read, the review with its provider, model, chunk
  size and chunks of each half, or "AI Review not configured", and the
  pack's findings as this store places them). The section is part of the
  signed report, so the attestation's report digest covers what the scan
  read; the token use is left out of it, as it is for the version's own
  AI Review, and counted on the run.

The release's own stages read the release's own files: none of them reads
a shipped pack's text, since the release's AI Review would read it in one
call past what the judge takes. S1 still inventories every file of the
archive, so an executable or a nested archive in a pack is refused as
anywhere else; a pack's files that are not text (an image, a source's
original) are the release's stages' as anywhere else; a text file in a
pack that is not UTF-8, which the pack scan cannot read, is the finding
`SK/unread-text` (medium), which sends the version to a person whatever
the threshold, so nothing in a pack goes unread without one;
and the pack's `manifest.json` is read as a release file. `SK` has 20
minutes, within the scan's 30. The release's own AI Review is told the
packs it ships and where they are mounted (`/knowledge/<name>`), so an
instruction that reads its own pack is not taken for a capability the
release left out.

The archive extractor's bounds are raised to hold the most a release may
ship: 60 MB unpacked, 12,000 files and 10 MB a file, every other quota
being the manifest's to enforce. An upload through the API is at most
16 MiB compressed, the edge's request cap.

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
- On Agentry's own deployment (SecureAgentry with the vault): The keys that
  open your knowledge packs, your Writing Voice and your runs' results are
  sealed by a key that never leaves our vault. Each time one is opened it is
  a vault call, recorded in its audit log and allowed only to the parts of
  Agentry that need it. Agentry runs that vault, so this is not end-to-end
  encryption. Both the registry's api and its worker may open a key, since
  the paths above run in both. What holds them to a pack's owner, or an
  active member of its organization, is the code's owner check, not the
  vault's policy. A SecureAgentry deployment without the vault keeps the
  arrangement where the CA's master key with the database opens the
  keys.
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

On SecureAgentry the wrapper's `Destroy` deletes the sealed private keys the
erasure, data clear or decommission owes. The vault keeps no copy, so every
wrap of that holder's data keys, including one kept beside a pack on a
laptop, no longer opens from the live system. A sealed key remains in the
database's backups until they age out (on Agentry's deployment, two days of
point-in-time history and thirty nightly copies). A restore of one would
open those wraps again with the vault's key, or, for a backup taken before
the vault sealed the keys, with the CA's master key.
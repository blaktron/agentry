# The Writing Voice in the registry

A Writing Voice is the instructions an LLM follows to write the way one
person writes: one Markdown file, `VOICE.md`, at most 32 KiB, written as an
LLM skill (sentences, words, tone, structure, what never to do, a few short
examples). A run that has it attached reads it through one tool,
`voice_read`, and the System Prompt says it governs how the run writes and
nothing else ([Running QuickAgents](runner.md#the-system-prompt)).

A person keeps a voice in two places, never synced on their own: one on
their computer, made free by the built-in Voice Writer and never reviewed
(`agentry voice …`), and one in their account here. This page is the
registry's side: how an account keeps its voice, how a version is reviewed
before it is live, how it is sealed, what the registry reads of it, and
when it is destroyed.

A voice is not a [knowledge pack](knowledge.md). There is one per person,
it has no name, no wiki and no sources, nothing lists it, and it is the one
attached text a run follows as instructions. That is why a version reaches
runs only after AI Review has passed it.

## What the registry holds

A person's voice is at most three versions:

- **live**: the one a run In Agentry attaches;
- **pending**: a new version in review, or one AI Review flagged, shown
  with its findings beside the live one;
- **previous**: the one the live version replaced, for Restore.

Each version records its digest (`sha256:` of the text), its size, its
source (`build` and `ai-edit` for the Voice Writer run In Agentry, `edit`
for text saved on the web, `upload` for a voice sent from a client,
`restore`), its review report and the hash of the question set it was
reviewed under. The voice carries the account's `alwaysAttach` flag: on
when a voice first goes live, and the person's to change after.

Every version is sealed at rest under a random data key of the voice's own
(`pkg/packseal`, 64 KiB AES-256-GCM frames), and the key is kept only as
the person's key wrapper wrapped it: the knowledge store's wrapper, the
deployment's knowledge sealing key on a core registry, an extension's on
SecureAgentry ([The key wrapper](knowledge.md#the-key-wrapper)). No table
holds a voice's words in the clear, and the review report quotes nothing:
it names a line or an AI Review question.

## The routes

Every route is the caller's own. Another account's voice is one that does
not exist, and platform staff have no route to anyone's.

| Route | Scope | What it does |
| --- | --- | --- |
| `GET /voice` | `voice:read` | the voice: every version's text, its review and the flags; 404 `voice-not-found` when there is none |
| `PUT /voice` | `voice:write` | `{text, source}` with `source` `edit` or `upload`: the text becomes the pending version (replacing any pending one) and its review is queued (202) |
| `POST /voice/restore` | `voice:write` | the previous version back: at once when it was reviewed under the question set in use (200), else as a pending version, reviewed again (202); 409 `voice-no-previous` |
| `DELETE /voice/pending` | `voice:write` | drop the pending version, in review or flagged |
| `PUT /voice/settings` | `voice:write` | `{alwaysAttach}`; a field not sent keeps its value |
| `DELETE /voice` | `voice:write` | the voice, every version and its data key |

A text past 32 KiB is 413 `voice-too-large`; an empty one, one that is not
UTF-8 or one holding a NUL is 422 `voice-invalid`. Both are refused before
anything is admitted or stored. A session has the account's authority; the
desktop's and the CLI's sign-in grant carries both voice scopes.

## The review

A version goes live only when its review passes it. The review is a
`voice.review` job on the sandbox queue, the worker that scans versions
and packs, and it reads two things:

1. **The rule stages a pack's scan runs over text**: S2 (secrets), S3
   (hidden content), S4 (signatures) and S8 (URL reputation). A finding of
   medium severity or above flags the version. The release rubric (S5's
   six questions) is not asked: it reads a voice's instructions about
   writing as instructions to its reader.
2. **AI Review's `voice` question set**, asked of the whole text in one
   request to the deployment's Jev (`pkg/judge` `VoiceQuestions`), with
   the borderline band asked twice more as every set is. A question scored
   2 or more flags the version. The four questions ask whether the voice
   tells the model to:
   - do something other than write: use a tool, read or write a file,
     reach an address, run a command, reveal or send secrets or the
     conversation (`beyond_style`);
   - rank itself above the model's other instructions or the person's
     request, or keep from the person what the model did or that it
     follows a voice (`override`);
   - put something into what it writes that is not style: a particular
     link, a promotion, a claim to state as fact, a request to the reader,
     data (`inserted_content`);
   - change the work a task asks for: leave out, cut short, add to or
     replace part of it, hold back a result, or answer in another form
     than the task asks for (`task_change`).

What a verdict does:

- **Pass.** The version becomes live and the live one becomes previous.
  The first time a person's voice goes live, `alwaysAttach` comes on.
- **Flagged.** The version stays pending, flagged, with its findings; the
  live version stays live. The person edits it and saves again, or drops
  it. There is no human review queue.
- **Not finished.** A stage that failed, or a judge that did not answer,
  leaves the version in review with what was read so far on its report.
  The job is tried five times with backoff over about a quarter of an
  hour, and an hourly sweep queues a review still waiting an hour after
  its last try again. Nothing goes live unreviewed.

**What a pass does not mean.** The set was benched before it shipped on 13
voices that hold writing instructions only (nine written by the Voice
Writer from public-domain writers' samples, four by hand close to the
line) and 38 with one smuggled instruction each. In two full runs it
flagged no good voice and at least 80% of the voices built for each
question. It missed a voice that says to skip the fact checks a task asks
for, and, on `task_change`, one that adds insecure code to a task (which
`inserted_content` caught). A pass is AI Review's judgement of the text,
not a proof that a run will behave; the System Prompt's own words bound
the voice at run time.

**The question set's hash** is part of every version's record. A Restore
of a version reviewed under another set is reviewed again.

## What the registry reads

The seal keeps a voice's words out of every table and backup. It does not
keep them from the registry's own code: the registry opens every version
to review it and to answer `GET /voice`, and AI Review sends the whole
text to the configured judge provider. On a core registry, whoever holds
both the knowledge sealing key and the database can open every voice.
On Agentry's own deployment (SecureAgentry with the vault): The keys that
open your knowledge packs, your Writing Voice and your runs' results are
sealed by a key that never leaves our vault. Each time one is opened it is
a vault call, recorded in its audit log and allowed only to the parts of
Agentry that need it. Agentry runs that vault, so this is not end-to-end
encryption. The key that opens a voice is the person's own certificate
key, sealed by the vault's `hosted-keys` as for their packs
([The key wrapper](knowledge.md#the-key-wrapper)), and each open is a
Transit decrypt in OpenBao's audit. The parts that may open it are the
registry's api and worker; what holds them to the voice's owner is the
code's owner check. A SecureAgentry deployment without the vault seals the
key under the CA's master key instead.

## What a deployment needs

The store is on when the registry has a database, a key wrapper (the
knowledge sealing key, `AGENTRY_KNOWLEDGE_SEALING_KEY`, or an extension's)
and a Jev judge (`AGENTRY_JUDGE_PROVIDER=typesafe`), since no version could
pass a review without one. `GET /meta` reports `features.voice`; with the
store off every route answers 503 `voice-unconfigured`.

## An extension's doors

A closed build reaches the store through `pkg/extension`:

- **`AdmitsVoice`** admits, and may charge for, the review a route asks
  for: an edit saved, an upload, a Restore that is reviewed again. AI
  Review costs 1 credit an operation where an extension charges for it;
  the core charges nothing. A refusal is answered in its own
  status and words before anything is stored, and the ticket is voided
  when nothing was. A ticket whose version was stored is recorded in the
  `admitted_stores` table (kind `voice`) in the transaction that stores
  it, so a ticket with no row stored nothing, even when its void failed
  or the process stopped before the store.
- **`Deps.Voice`** reads a person's live voice (never a pending one) for a
  hosted run to attach, reads the whole voice for a Voice Writer run to
  improve or edit, and proposes a Voice Writer run's output as a pending
  version (`build` or `ai-edit`), reviewed like any other; its review is
  inside the build's price and is not admitted.

## The clients

Every client goes through the routes above, and none moves a voice between
a computer and the account on its own:

- **The CLI** keeps this computer's voice and runs the Voice Writer free
  ([A Writing Voice](runner.md#a-writing-voice)), over files of your
  writing and, with `--url`, pages of it on the web, which AI Review reads
  first with your own TypeSafe key
  ([samples from web addresses](runner.md#a-writing-voice)). `agentry voice upload`
  puts that text to `PUT /voice` with the source `upload` and changes
  nothing on the computer; `download` keeps the account's live version on
  the computer, held to its digest; `status` shows both; `attach on|off
  --account` is `PUT /voice/settings`.
- **The desktop** shows the two voices as two cards, **Local Voice** and
  **Cloud Voice**. The Local Voice page edits this computer's voice, runs
  **Edit with AI** on this computer for no credits (a note and optional
  samples or web addresses of your writing; with no voice, **Write with
  AI** creates one), and moves the
  voice: **Upload to Cloud** is the CLI's upload and **Download Cloud
  version** its download. Each says *Already the same* when the digests
  match and asks before it replaces a voice that looks newer. The Cloud
  Voice page is the site's Voice settings page: an editor whose Save is
  `PUT /voice` with the source `edit`, Edit with AI In Agentry, Discard,
  Restore and Delete, and the `alwaysAttach` switch.
- **The site** has two cards on the Dashboard's Voice page. **AI Voice
  Writer** runs the hosted Voice Writer: a new voice from samples, web
  addresses of your writing or both, or an Edit with AI, a note saying what
  should change with optional samples or addresses.
  **Voice settings** holds the account's voice in an editor whose Save is
  `PUT /voice` with the source `edit`, Discard for a pending version,
  Restore, Delete, and the `alwaysAttach` switch, which Settings → Profile
  also shows. The site offers no Improve; the CLI and the API keep it.

Both clients' editors show the voice as formatted text and save Markdown
(WYSIWYG): raw HTML and images stay text, no link opens from the editor, a
link's address and title and a code block's info string are shown, and an
edit leaves every block the person did not change exactly as it was read.

A client reads `features.voice` in `GET /meta` and draws none of this
where the store is off.

## On SecureAgentry

The SecureAgentry build adds three things through the doors above,
described with the rest of its runs on [Hosted runs](hosted-runs.md):

- **The hosted Voice Writer**, a run of the kind `voice_build` that
  creates, improves or AI-edits the person's voice on a sandbox host and
  proposes what it writes as the pending version
  ([A hosted Voice Writer run](hosted-runs.md#a-hosted-voice-writer-run)).
  An AI Edit takes optional samples beside its note, as `agentry voice
  edit --file` does. Each of the three also takes web addresses of the
  person's writing (`urls`, at most 20), each page read by AI Review before
  the Voice Writer reads it and a page drawn by scripts rendered in a
  headless browser. Each costs 20 credits flat, AI Review included, and a person on Standard
  starts one a billing cycle, whichever of the three.
- **A run in the voice**: a hosted run or session created with
  `voice: true` is handed the runner's live version at the hand-off
  ([A run in the Writing Voice](hosted-runs.md#a-run-in-the-writing-voice)).
- **The review's credit**: `AdmitsVoice` charges 1 credit for the review of
  an edit, an upload or a Restore reviewed again.

## Erasure

Deleting the voice removes every version and its data key. The account
erasure and a data clear delete it in their own transaction; the key that
opened it goes with the knowledge store's erasure of the same person (the
core wrapper's salt, or an extension wrapper's `Destroy`).

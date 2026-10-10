# Model input: AI Review before a model reads, and brokered web search

Two registry routes serve work that feeds a model text from outside: the
Drafter (the built-in package that drafts a QuickAgent from a person's
description) and, since agentry-cli#321, a hosted run's input files
([AI Review of a run's inputs](hosted-runs.md#ai-review-of-a-runs-inputs)). Both push text to
the registry rather than holding a key of their own (agentry#608; plan
`builder-rework.md` D20–D25):

- `POST /api/v1/model-input/scan` asks the deployment's judge whether a
  text an AI agent is about to read tries to steer it, and answers with a
  verdict: `pass`, `withheld` or `not_scanned`.
- `POST /api/v1/model-input/search` searches the web through the
  deployment's provider, with the registry's key, and scans every result
  the same way before returning it.
- `POST /api/v1/model-input/check` reads a finished draft's package the
  way AI Review will at publish, and asks whether the draft does the task
  it was drafted for, so the person knows before Submit (agentry#708; plan
  `builder-simplify.md` D6). See [the check of a finished draft](#the-check-of-a-finished-draft).

This is not the publication scan. A release is still scanned at
publication, by the pipeline (S1–S10), whatever these routes said about
the text its draft was made from ([trust.md](trust.md)).

## Who may call them

The routes spend the deployment's own judge and search keys, so no
account's token reaches them, whatever its scopes. Two callers do:

- **Platform staff, by session** (the instance admin on a self-host). A
  staff member's personal access token is refused like anyone's.
- **A hosted job**, by the credential an extension minted for that one
  job, in the `X-Agentry-Job-Token` header. The core has no such extension:
  on a core registry the header is answered 401. SecureAgentry's runs
  extension admits the Drafter's hosted draft kind, and a hosted run's or
  session's `input_file` scans (at most 400 a run), through the
  `AdmitsModelInput` seam of `pkg/extension`: it names the job a
  credential acts for, may refuse a call past the job's caps (a draft past
  its searches, say) in its own status and words, and hears what each
  admitted call spent. The credential never enters a run's containers; the
  sandbox host's tool plane presents it.

Anything else is 401 (no credential) or 403 (the wrong one). A request
carrying a session and a job credential together is 400.

## The scan

The request is `{"source": …, "text": …}`. `source` says what the text
is: `description`, `search_result`, `page`, `registry` or `input_file`.
`text` is at most 65,536 bytes of UTF-8 (eight chunks); a longer text is
sent in parts. A larger one is `413 model-input-too-large`.

The text is cut into 8 KiB chunks at line ends where it can be (never
inside a character), and every chunk is asked the **model-input question
set** in one request each, up to four chunks at once:

| Question | Asks whether the text… |
|---|---|
| `injection` | tries to instruct the AI agent reading it: override its instructions, change what it does next, make it work for someone else |
| `exfiltration` | directs the agent to send conversation history, secrets, credentials, keys or private files anywhere, a link or an image address included |
| `deception` | tells the agent to mislead the person it works for, or hide something from them |
| `obfuscation` | carries instructions that are encoded, hidden or disguised: base64 or hex payloads, invisible characters (zero-width or Unicode tag characters), comments or markup a person would not see |

These are four of the publication rubric's six, re-worded for text read
as data. The rubric's undeclared-capability and destructive-action
questions are not asked: they judge a release against its own declared
contract, and a page has none. Each question says what does not count
(installation steps, commands to run, configuration and API usage written
for a person; text that only documents or quotes an attack), because a
documented `curl | bash` must not read as an injection. The texts are
constants in `pkg/judge`, and nothing from the scanned text is rendered
into them: the text travels in the request's state beside its `source`,
as data.

Each answer is a probability; 0.5, 0.7 and 0.9 are scores 1, 2 and 3. An
answer between 0.30 and 0.70 is asked twice more and the highest kept,
never the mean. The text's score is the highest over every chunk and
question, and the verdict follows:

- **`withheld`**: some question scored 2 or more (the gate's medium). The
  caller gives the model the source's address and the reason, never the
  text.
- **`not_scanned`**: the judge could not answer for some chunk (an error,
  a timeout, an answer out of shape). A caller treats it as withheld: the
  scan fails closed.
- **`pass`**: neither.

A flag wins over a chunk that was not scanned. The answer carries each
chunk's scores (or its failure, `timeout` or `judge-error`), the flagged
questions, the pinned model, the question set's hash and `usage`, the
judge's requests and input tokens. `usage` is for the record. It is never
a price: AI Review is charged per operation, however many scans it makes
(DEV-150).

The question set was benched before anything used it, on hostile pages
(instructions in comments, hidden text, encoded, invisible and
tag-character payloads, fake tool calls, exfiltration through links) and
benign ones (install guides, API references with example keys, an article
that quotes an injection, an `AGENTS.md`, an `llms.txt`). The corpus is
`pkg/judge/testdata/model-input-bench`, the bench is `TestModelInputBench`
(it needs `AGENTRY_JUDGE_BENCH=1` and a Jev key), and the readings are in
the engineering record's `measurements/model-input-bench.md`. A bench
bounds what it measured, not what it did not: a sufficiently novel
injection can pass this scan as it can pass the publication scan.

## The search

The request is `{"query": …, "count": …}`: a query of 1 to 400 characters
with no control characters, and 1 to 10 results (5 when unset). The
registry asks its provider, drops any result without an absolute `http` or
`https` address (or with user information in it), folds and cuts each
title to 300 characters and each snippet to 1,000, and scans every result
as a `search_result`: its title, address and snippet together, since an
address can carry an instruction too.

Only scanned results come back. A result that passed carries its address,
title and snippet. One that was withheld or not scanned carries only its
origin (scheme and host), its verdict, score and flags: never its title, its
snippet or the rest of its address, since a path or a query can carry an
instruction too. `withheld` counts both. A provider that does not answer is
`502 web-search-failed`; nothing is returned. A redirect from the provider
is never followed, since the key rides on every request.

The query goes to the provider and to nowhere else: it is neither kept nor
logged. With no judge to scan the results the search is not made at all.

## The check of a finished draft

The request is `{"description": …, "files": [{"path": …, "content": …}]}`:
the person's description, at most 8,192 bytes, and every text file of the
rendered package, `agent.yaml` and its instruction file among them, at
most 32 files and 65,536 bytes in all. Each path must be relative and
clean and named once, and each file UTF-8. A package with no
`agent.yaml`, one that does not parse, or one without the instruction file
it names is `422 draft-unreadable`, and one past the bounds is
`413 draft-too-large`. Neither is asked anything, and a job's call is not
counted.

The check has two halves, both asked of the deployment's Jev with its key:

- **The release rubric**, exactly as stage S5 of the pipeline asks it at
  publish: the manifest as its canonical JSON (read as `agent.yaml`), then
  every file in path order, in the same 8 KiB chunks, with the manifest's
  capabilities and the packs it ships beside each chunk, and a fixed
  statement of what the runner gives every run (the read-only inputs, the
  run's own report files, its answer, and nothing else), the same six
  questions and the same band, under the rubric hash S5 records. The
  rubric's asking code is `pkg/judge`'s `RubricScanner`, which the
  pipeline's `typesafe` provider asks through too, so the two cannot drift
  apart. A question that scores 2 or more is a finding S5 would record;
  the answer names its id, its score, the file whose part scored highest,
  and the severity the gate would give it. A high one (a score of 3, or 2
  for `C1_injection`, `C3_undeclared_capability` and `C4_user_deception`;
  `C2_exfiltration` and `C6_destructive_actions` are medium at any score)
  sends the version to a person, and the half reads `flagged`; a medium one publishes with the
  finding shown, so it is a note and the half reads `pass`.
- **The draft question set**, asked once over a state of the description,
  the canonical manifest and the instruction:
  does the instruction do the task the description asks for (`off_task`:
  a different task, a part left out, or a different kind of result)? A
  score of 2 or more is a flag. The question was benched on the Drafter's
  ten fixture drafts and fifty broken variants of them before anything
  used it (`pkg/draftcheck` `TestDraftBench`, which needs
  `AGENTRY_JUDGE_BENCH=1` and a Jev key; the readings are the engineering
  record's `measurements/draft-check-bench.md`). A draft made for another
  task scored 0.96 or more and a good draft 0.18 at most. It also flags
  only three or four in ten drafts that leave out one part of the task, so
  a pass does not mean the draft does all of it. Two more questions were
  benched and not kept: one on capabilities the manifest does not grant,
  which flagged good drafts, and one on asking the person for what the
  description gave, which missed most.

The rubric half tells the person what S5 will record. Its state says
what the runner gives every run, so an instruction that reads its own
inputs and writes its report is not read as needing more than it
declares. On the Drafter's ten fixture drafts it draws no finding, a
result of wordings tuned on those same drafts and checked against the
attack corpus (agentry#731; the readings are the engineering record's
`measurements/draft-check-bench.md`). A draft that is flagged goes to
review at publish, not to refusal.

Each half answers `pass`, `flagged` or `not_scanned` on its own. A half
the judge could not answer for (an error, a timeout, or for the draft set
a part past its bound of 8, 16 and 32 KiB, or a state past 48 KiB in
all) is `not_scanned`, with its failure word, never a pass. The texts are constants in `pkg/judge`, and
nothing of the package is rendered into them.

This is not the publication scan. A submitted version is scanned in full
by the pipeline, S1 to S10, whatever the check said. `usage` counts both
halves' requests and tokens for the record; AI Review is still one credit
for a whole draft (DEV-150). `pkg/draftcheck` is the check as a package,
so the CLI checks a local draft with the person's own key and asks what
the registry asks.

## Configuration

The scan needs the deployment's judge to be TypeSafe's Jev
(`AGENTRY_JUDGE_TYPE=typesafe`; [self-hosting.md](self-hosting.md)), and
uses its key and pinned model. With any other judge, or none, the scan
answers `503 model-input-unavailable`, and so does the search when a
provider is configured: it makes no search whose results it could not
scan. With no provider the search answers `503 web-search-unavailable`
first.

The search needs a provider:

| Variable | Meaning |
|---|---|
| `AGENTRY_WEB_SEARCH_PROVIDER` | `none` (the default: `503 web-search-unavailable`), `youcom` (You.com's Web Search API), `brave` (Brave's LLM Context API: page chunks extracted for a model, read from its `grounding.generic` results; a query past Brave's 75 words or 600 bytes is searched on its opening words), `tavily` (Tavily's Search API at its basic depth), `exa` (Exa's search, each result's highlights as its snippet) or `perplexity` (Perplexity's Search API, not its chat completions). These three are there for a person's own key (agentry#783): Tavily's and Exa's terms keep a right to use queries, and Perplexity's published no-training statement covers its chat completions, not this endpoint, so none meets the terms the registry's own choice was held to (DEV-185) |
| `AGENTRY_WEB_SEARCH_API_KEY` | the provider's key; required with a provider, never logged |
| `AGENTRY_WEB_SEARCH_BASE_URL` | the provider's API root, for a test double; empty is the provider's own |

A provider named without its key, or a name the registry does not know,
refuses startup. The provider's host (`api.search.brave.com:443` for Brave,
`ydc-index.io:443` for You.com, `api.tavily.com:443`, `api.exa.ai:443` or
`api.perplexity.ai:443`) must be reachable from the registry's API
role, and so must the judge's (`api.typesafe.ai:443`, or its region's host
when `AGENTRY_JUDGE_REGION` is set), since every result is
scanned before it is returned; no sandbox host needs either. No client
follows a redirect, since each sends its key in a header that Go would carry
to another host.

## Budgets

Each caller (a staff member, or one job) has
`limits.modelInputPerMin` calls a minute (`AGENTRY_LIMITS_MODEL_INPUT_PER_MIN`,
120), refused with 429 past it. A job's calls are not drawn from the
anonymous rate class by address, because every sandbox host behind one NAT
shares an address. Instead an address presenting job credentials has ten
times a caller's budget, spent before the body is read, which bounds
guessing at credentials and sending bodies that will be refused.

Each API replica paces the routes' requests to the judge at 15 a second
(a burst of 20). Jev's limit, 1,200 a minute, is the key's, shared by every
replica and by the publication pipeline, so more than one replica under
full load can pass it. Jev then answers 429: the request is retried once,
and a chunk still unanswered is not scanned, which fails closed. A chunk
that cannot be asked before its call's 45-second deadline is not scanned
either.

## What is recorded

Nothing of a text, a query, a result's address or a draft's package is
kept. Each call
writes one `model_input.call` log line ([logging.md](logging.md)) with its
operation, caller kind, job, verdict, source and counts, and counts into
the `ModelInputCalls{op,verdict}` and `ModelInputJudgeTokens{op}` metrics.
A chunk that was not scanned also logs why: the judge's status when it
answered with an error, never its body, which could echo the text. A
search the provider did not answer logs its status alone, for the same
reason with the query.

## Scanning on a person's own machine

`pkg/judge` is the same client and the same question set, exported, so the
CLI and the desktop can scan a local draft's inputs with the person's own
Jev key and ask exactly what the registry asks (D25). `pkg/websearch` is
the provider client, for a person's own search key.

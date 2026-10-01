# Writing Voice

Instructions for writing in this person's voice. Everything here is drawn from
one sample: a long, formal style guide for code, written for a whole community
rather than one reader. Weight follows how clearly the sample shows each habit.
The sample's subject matter (its language, its tooling) is incidental — adopt
the shape of the writing, not its topic.

## Sentences

- Write short sentences. Most run 8–16 words; a rule can be a single sentence of
  five ("Spaces are the preferred indentation method.").
- Put one idea in a sentence, and one rule per paragraph. Paragraphs are one to
  four sentences; two is the common length.
- Open with the rule, in the imperative or with "should": "Use 4 spaces per
  indentation level." "Limit all lines to a maximum of 79 characters." "Imports
  are always put at the top of the file."
- Follow the rule with a second sentence that gives the reason. Never leave a
  rule unexplained: "Limiting the required editor window width makes it possible
  to have several files open side by side."
- Vary the rhythm by alternating a short flat rule with a longer explanatory
  sentence that carries its qualifications in `that`, `as`, `even if` and
  `provided that` clauses. Do not pile three qualifications into one sentence.
- Use the occasional one-sentence paragraph to land a point on its own, usually
  a concession or a warning.
- State a preference as permission rather than command: "it is permissible
  to…", "it's okay to…", "it is okay to increase the limit up to 99 characters".
  Reserve "must", "never" and "always" for the few things genuinely not
  negotiable.
- Hedge the edges, never the core. The base rule is stated flatly; the exception
  carries the softeners — "usually", "generally", "often", "may still be
  appropriate at times", "sparingly".
- Address the reader as "you" only when handing them a judgement to exercise:
  "Use your own judgment." "you may use them to separate pages". Otherwise keep
  the construction impersonal: "Absolute imports are recommended."
- Spell out a term once, in parentheses, then lean on the short form: "compound
  statements (multiple statements on the same line)".

## Words

- Plain, concrete, technical. Every word does work; nothing decorative.
- Prefer the shortest plain verb: use, avoid, put, keep, limit, place.
- Contractions appear, but sparingly and mostly in the informal asides: "it's",
  "don't", "that's". Keep the formal rule sentences uncontracted: "Imports are
  always put at the top of the file."
- Pick one spelling convention and never mix. The sample leans American: -ize
  endings ("recognize"), "judgment", "behavior". Keep whatever convention the
  piece already uses; do not switch mid-document.
- Names of code elements, operators and file features go in a monospace code
  style; concepts do not.
- Use RFC-style capitals for graded obligation when the audience is a whole
  community: MUST, SHOULD, MAY. Use lowercase for ordinary advice.
- Reach for: readability, consistency, convention, consistent locally, guideline,
  recommendation, pet peeve, defensible use case, for decades, in practice.
- Never use: hype, marketing adjectives, buzzwords, "leverage", "seamless",
  "powerful", or "simple" as a boast; no hedging filler ("kind of", "sort of",
  "basically", "just"); no apologetic openers.

## Tone

- Calm, dry, assured. Confident about the rule; unhurried about the argument.
- Friendly in a dry way, not a warm one: a joke in a heading, one exclamatory
  nudge per document ("And don't hesitate to ask!"), a wry label for a bad habit
  ("Pet Peeves").
- Disagree by explaining the mechanism, never by mocking anyone: "this can hurt
  readability in two ways: the operators tend to get scattered across different
  columns, and each operator is moved away from its operand."
- Praise by naming the effect: "Following the tradition from mathematics usually
  results in more readable code."
- Concede generously and out loud. Say where the guide takes no position, where
  a choice is down to taste, and where a team may prefer otherwise.
- Treat the reader as an adult with judgement: give the reason, then hand over
  the decision — "When in doubt, use your best judgment."
- Escalate disapproval in graded steps instead of one shout: acceptable →
  "permissible" → "Rather not:" → "Definitely not:".

## Structure

- Divide with short noun-phrase headings, two or three words, that name the
  subject rather than the conclusion ("Code Lay-out", "Blank Lines", "Imports").
  Allow a heading to be a question when the section exists to settle a debate
  ("Tabs or Spaces?").
- Open by saying what the document covers and what its status is. Do not warm up.
  Then give a table of contents so a reader can jump.
- Give every section the same shape: rule → one or two sentences of reason →
  example block → the exception → a pointer to the section that interacts with
  this one.
- Show, then say. Pair a correct example against a wrong one, each introduced by
  a one-word label, and annotate inside the example with a comment on why that
  case is right or wrong.
- Use a numbered list for ordered steps or enumerated exceptions; a bulleted list
  for a set of parallel prohibitions. Introduce every list with a full sentence,
  and keep each item to one or two sentences.
- Cross-reference rather than repeat: "(See the previous discussion on
  multiline if-statements.)"
- Close by pointing at what the guide does not cover, and by noting that it
  evolves over time — not with a summary.

## Punctuation and form

- Sentences end in full stops. Exclamation marks appear once per document at
  most, and only as an invitation to ask.
- Use em dashes for a mid-sentence aside, and parentheses for a qualification, a
  date or a version note.
- Use semicolons to join two closely bound short statements: "Extra blank lines
  may be used (sparingly)…; many tools treat these characters as page
  separators."
- Commas in lists, with the serial comma omitted: "parentheses, brackets and
  braces".
- Double quotes for concepts and terminology; single quotes inside code samples.
- Digits for measurements, limits and versions (4, 72, 79, 3.10); words for
  counts in prose ("two ways", "one defensible use case").
- No emoji. No bold for emphasis; italics for a term being introduced.

## Registers

- The register the sample shows is community-facing technical guidance:
  impersonal, reasoned, RFC-flavoured, and generous with exceptions.
- Carry that same voice into guidance for a team — keep the rule-first
  paragraphs, the stated reasons and the graded permissions. Drop the RFC
  keywords (MUST, SHOULD, MAY) for team notes, where "do" and "don't" read
  better, and let "we" appear when the team is the one deciding.
- The samples show no casual or personal writing. Do not invent any; where a
  lighter register is needed, keep the plain vocabulary and short sentences and
  change only the formality.

## Never

- Never give a rule without its reason.
- Never bury the rule at the end of a paragraph.
- Never use a rule as a cudgel: no scolding, no sarcasm aimed at a named person,
  no "obviously".
- Never declare one style the only correct one where taste is genuinely involved;
  say what the guide prefers, and that local consistency wins.
- Never let a sentence run past about 25 words.
- Never pad: no throat-clearing opener, no restating the conclusion at the end.
- Never write a paragraph of prose where a correct/wrong example pair would say
  it better.
- Never hedge a hard constraint, and never state a soft preference as a law.

## Examples

Short passages from the samples, at the writer's most characteristic. Quote them
for their shape, not their subject.

> A style guide is about consistency. Consistency with this style guide is
> important. Consistency within a project is more important. Consistency within
> one module or function is the most important.

> However, know when to be inconsistent – sometimes style guide recommendations
> just aren't applicable. When in doubt, use your best judgment. Look at other
> examples and decide what looks best. And don't hesitate to ask!

> Some teams strongly prefer a longer line length. For code maintained
> exclusively or primarily by a team that can reach agreement on this issue, it
> is okay to increase the line length limit up to 99 characters, provided that
> comments and docstrings are still wrapped at 72 characters.

> For decades the recommended style was to break after binary operators. But
> this can hurt readability in two ways: the operators tend to get scattered
> across different columns on the screen, and each operator is moved away from
> its operand and onto the previous line.

> Spaces are the preferred indentation method.
>
> Tabs should be used solely to remain consistent with code that is already
> indented with tabs.

> Wildcard imports should be avoided, as they make it unclear which names are
> present in the namespace, confusing both readers and many automated tools.
> There is one defensible use case for a wildcard import, which is to republish
> an internal interface as part of a public API.

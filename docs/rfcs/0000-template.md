# RFC 0000: <title>

| Field | Value |
|---|---|
| Status | draft \| accepted \| rejected \| superseded by RFC-NNNN |
| Author(s) | |
| Created | YYYY-MM-DD |
| Affects | manifest schema \| API \| ruleset format \| attestation predicate \| other |

## Summary

One paragraph. What changes, for whom.

## Motivation

What is broken or missing today. Concrete cases, not "it would be nice".
If this is a security change, say what an attacker can do now that they
could not before, or vice versa.

## Design

The change in enough detail to implement. For anything that crosses a
compatibility boundary, show the before and after:

- **Manifest / ruleset changes:** the schema delta, and what happens to
  documents written against the old shape.
- **API changes:** the OpenAPI delta. Within `/api/v1` this must be
  additive; anything breaking needs `/api/v2` and a migration story.
- **Attestation predicate changes:** what old verifiers do with new
  envelopes, and what new verifiers do with old ones. Signatures already
  issued must keep verifying, forever.

## Compatibility and migration

Who has to do what, and when. "Nobody has to do anything" is a valid and
welcome answer; say it explicitly.

## Security impact

Required for every RFC, even if the answer is "none". Consider: does this
widen what a published agent can express? Does it add a path that could
reach `published` without the gate? Does it change what a signature covers?

## Alternatives considered

Including the option of doing nothing, and why it loses.

## Open questions

Anything that needs a decision before this is implementable.

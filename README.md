# Agentry (working codename)

**A registry + git hosting platform for single-purpose AI agents — "GitHub for agents" — with mandatory pre-publication security scanning.** Open-source framework; hosted website is a product built on the framework.

## Status

**Phase: planning.** Nothing has been built. The deliverable of this phase is [PLAN.md](PLAN.md).

## Contents

| Path | What it is |
|---|---|
| [PLAN.md](PLAN.md) | **The deliverable.** Self-contained, agent-readable build plan. A builder agent should be able to implement the system from this document alone, after a human has reviewed it and resolved the items in its "Open questions" section. |
| [research/](research/) | Raw research reports gathered during planning (landscape, tooling). Background material only — **not** authoritative; PLAN.md supersedes anything here. A builder agent does not need to read these. |

## How this project proceeds

1. Human reviews PLAN.md, edits decisions, answers the Open Questions section (§20).
2. A builder agent is pointed at PLAN.md §0 ("How to use this document") and begins at milestone M0.
3. Deviations from the plan get recorded in `DEVIATIONS.md` (created by the builder), not by silently rewriting PLAN.md.

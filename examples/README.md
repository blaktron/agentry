# First-party example agents

Small, real agents that demonstrate the manifest, the capability contract, and
the publication pipeline. They are also our own dogfood: if a plausible,
well-written agent cannot get through the gate without a fight, that is a bug
in the gate, not in the agent.

| Agent | Kind | Why it is here |
|---|---|---|
| [incident-summarizer](incident-summarizer/) | autonomous | The canonical example: declares network egress to one host and one secret. |
| [pr-reviewer](pr-reviewer/) | autonomous | Pure instructions, no capabilities at all — the "empty means pure text" case. |
| [injection-defense](injection-defense/) | autonomous | **Discusses** prompt injection at length. It must publish cleanly; if a scanner flags it, our precision has regressed (§17.3 benign lookalike, as a shipped artifact). |
| [changelog-writer](changelog-writer/) | autonomous | Reads the workspace, writes nothing, no network. Shows a read-only filesystem declaration. |

## Publishing them

```bash
cd examples/incident-summarizer
agentry validate            # same rules the server runs, offline
agentry publish             # or tag the repo and let the pipeline pick it up
```

## What to copy from these

- `publish.include` is an allowlist. Everything you do not list stays out of
  the archive, including your scratch files and CI config.
- Declare the narrowest capabilities that actually work. `egress: [one.host]`
  beats `egress: ["*"]`, which is policy-gated to human review for good reason.
- Put the behaviour in the entrypoint file and the *explanation* in the README.
  The scanners read both, and reviewers read the README first.

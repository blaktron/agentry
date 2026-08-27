# pr-reviewer

A prompt-agent (pure instructions, no code, no capabilities) that reviews a
diff in priority order: correctness first, then security-relevant changes, then
unmentioned behaviour changes, then tests. Style comes last.

Written to produce short, specific reviews — a finding names the inputs that
trigger it and what happens — rather than long lists of hedged observations.

## Install

```bash
agentry install agentry/pr-reviewer --target=agents-md
```

This appends a section to your `AGENTS.md`. Re-installing replaces that
section rather than duplicating it.

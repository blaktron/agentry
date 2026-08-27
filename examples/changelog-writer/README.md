# changelog-writer

Writes release notes from the commits since your last tag, grouped by what
changed for the reader rather than by subsystem.

## Capabilities

| Capability | Why |
|---|---|
| `filesystem.read: workspace` | Read the commit range and match your existing `CHANGELOG.md` style. |
| `filesystem.write: none` | It prints the draft. You decide where it goes. |
| `network.egress: none` | The commits are already local. |

The write-nothing declaration is deliberate: a changelog draft that lands in
the repo without a human reading it is worse than no changelog.

## Install

```bash
agentry install agentry/changelog-writer --target=claude-skill
```

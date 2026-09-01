# The BriefAgent Builder

The Builder (`/build`, signed-in) authors a BriefAgent in the browser and
submits it straight into the publication pipeline. It is a front door, not
a side door: the server re-validates and re-packs what you submit, and the
same scanning and review gate applies as to a CLI publish.

## What the form covers

- **Identity** — name, namespace (your handle by default), kind (`skill`
  or `prompt-agent`), version, license, visibility, summary, tags.
- **The capability contract** — network egress (none / specific hosts /
  unrestricted), filesystem read and write, exec commands, secret *names*
  (never values), data-access categories, and declared **MCP servers**
  (one per line: `npm:pkg@1.2.3 tools=a,b secrets=X egress=host` — exact
  versions, pinned to this release and installed per-signature by the
  runner).
- **Instructions** — the entrypoint file itself (SKILL.md for a skill,
  AGENT.md for a prompt-agent).

Unrestricted egress is refused by runners unless the operator's policy
allows it, and routes the version to review by default — the form warns
you before you learn it the hard way.

## What submitting does

Submit packs `agent.yaml`, your instructions, a README, and the license
into the canonical archive and uploads it over the same path the CLI uses.
The pipeline decides from there; the agent's page shows the verdict, and a
version with findings goes to human review rather than publishing quietly.

For BriefAgents with code, additional files, or a repo history, use the
[template](https://github.com/blaktron/agentry-template) and `agentry
publish`, or the desktop app's Build tab — same pipeline, richer workspace.

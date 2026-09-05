# The BriefAgent Builder

The Builder (`/build`) authors a BriefAgent in the browser. It has two
exits, and only one of them needs an account:

- **Download package** — anyone, signed in or not. The form is packed into
  the canonical `.tar.zst` archive and handed to you; nothing touches the
  registry. Run it with `agentry run --local <dir> --allow-unsigned`, keep
  authoring in a repo, or `agentry publish` it later — it is byte-for-byte
  the archive the CLI would pack from the same files, and the response
  carries its digest in an `X-Archive-Digest` header.
- **Create & submit** — signed in. The same archive goes straight into the
  publication pipeline. This is a front door, not a side door: the server
  re-validates and re-packs what you submit, and the same scanning and
  review gate applies as to a CLI publish.

## What the form covers

- **Identity** — name, namespace (your handle by default), the run modes
  the release supports (autonomous, interactive, or both), version,
  license, visibility, summary, tags.
- **The capability contract** — network egress (none / specific hosts /
  unrestricted), filesystem read and write, exec commands, secret *names*
  (never values), data-access categories, and declared **MCP servers**
  (one per line: `npm:pkg@1.2.3 tools=a,b secrets=X egress=host` — exact
  versions, pinned to this release and installed per-signature by the
  runner).
- **Up-front questions** — the optional `intake` block: three structured
  rows (id, prompt, type, choices, required) plus a line-syntax textarea
  for more, and the interactive session's opening message.
- **Instructions** — the instruction file itself (`AGENT.md`).

Unrestricted egress is refused by runners unless the operator's policy
allows it, and routes the version to review by default — the form warns
you before you learn it the hard way.

## What the two buttons do

Both pack `agent.yaml`, your instructions, a README, and the license into
the canonical archive. **Download** stops there and gives you the file.
**Submit** uploads it over the same path the CLI uses; the pipeline decides
from there, the agent's page shows the verdict, and a version with findings
goes to human review rather than publishing quietly.

For BriefAgents with code, additional files, or a repo history, use the
[template](https://github.com/blaktron/agentry-template) and `agentry
publish`, or the desktop app's Build tab — same pipeline, richer workspace.

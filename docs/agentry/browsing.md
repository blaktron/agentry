# Browsing and reading a report card

The registry's job is to let you judge a BriefAgent **before** it touches
your machine. Everything on the browse and agent pages exists for that.

## Browse

**Browse** (`/search`) searches names, summaries, and READMEs, with filters
for kind, declared capability, license (faceted from what has actually been
published), verified organizations, and sort order (best match, most
installed, newest).

Click anywhere on a result row to open its **detail pane** beside the list:
the latest version, the scan verdict, declared capabilities, license, and
the install command — enough to decide without leaving the list. Click the
`org/name` identifier itself to go to the full page. The pane's state lives
in the URL, so a filtered view with a selection can be shared as a link.

## The agent page

Top to bottom, in reading order:

- **Declared capabilities** — what the manifest claims to need: network
  egress, filesystem access, exec, secret *names*, data categories,
  MCP servers. These are the author's declaration and the basis for
  scanning and policy; the registry cannot enforce them at run time. Your
  runtime should.
- **MCP servers & tools** — exactly which tools the runner will grant for
  this contract, and which MCP servers are installed with it (pinned to
  this release by version and digest).
- **Security report** — "scanned, N findings, signed", never "safe". The
  scan date, ruleset version, and adjudication mode are shown so you can
  judge how fresh the check is; the full report lists every finding, and
  reviewer dismissals stay visible **with their rationale**.
- **Install** — the command per target, and the git clone URL.
- **Code & README** — the exact published files, with invisible or
  obfuscated characters rendered visibly rather than hidden.
- **Provenance** — the content digest, the signing key, and the
  `agentry verify` command that checks both offline.
- **Releases and advisories** — every published version with its status
  (published, yanked, quarantined, blocked), and any advisories raised
  against them.

Stars and install counts are popularity signals, not safety signals, and
the page says so where it shows them.

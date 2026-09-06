# Browsing and reading a report card

The registry's job is to let you judge a BriefAgent **before** it touches
your machine. Everything on the browse and agent pages exists for that.

## Browse

**Browse** (`/search`) searches names, summaries, and READMEs, with filters
for run mode, declared capability, license (faceted from what has actually been
published), verified organizations, and sort order (best match, most
installed, newest). Every result carries its run-mode badges —
**autonomous**, **interactive**, or both — and the badges explain
themselves on hover; the mode filter says what a mode is.

Click anywhere on a result row to open its **detail pane** beside the list:
the latest version, the scan verdict, declared capabilities, license, and
the install command — enough to decide without leaving the list. Click the
`org/name` identifier itself to go to the full page. The pane's state lives
in the URL, so a filtered view with a selection can be shared as a link.

## The agent page

Top to bottom, in reading order:

- **Run modes** — the badges beside the name say how the release runs:
  from its files to a result (autonomous), as a conversation
  (interactive), or either. The [package format](../briefagents.md#modes-and-the-instruction-file)
  explains what each means.
- **Declared capabilities** — what the manifest claims to need: network
  egress, filesystem access, exec, secret *names*, data categories,
  MCP servers. These are the author's declaration and the basis for
  scanning and policy; the registry cannot enforce them at run time. Your
  runtime should.
- **MCP servers involved** — exactly which tools the runner will grant for
  this contract, and each MCP server the release declares (exact package
  version, the tools it is limited to) with the registry's last
  vulnerability check of that version: "no known advisories as of …", or
  the advisories it carries.
- **Dependency alerts** — when a published version declares an MCP server
  version that has since gained a high or critical advisory, the page says
  so above the advisories, with the advisory ids and the fixed versions;
  the author sees the same alert as a banner after signing in and on the
  dashboard.
- **Security report** — "scanned, N findings, signed", never "safe". The
  scan date, ruleset version, and adjudication mode are shown so you can
  judge how fresh the check is; the full report lists every finding, and
  reviewer dismissals stay visible **with their rationale**.
- **Install** — the command per target, and the git clone URL (HTTPS, and
  SSH when the instance advertises it).
- **Code & README** — the exact published files, with invisible or
  obfuscated characters rendered visibly rather than hidden.
- **Provenance** — the content digest, the signing key, and the
  `agentry verify` command that checks both offline.
- **Releases and advisories** — every published version with its status
  (published, yanked, quarantined, blocked), and any advisories raised
  against them. The registry's `/advisories` page is the global feed,
  newest first, each advisory with a permalink.

Stars and install counts are popularity signals, not safety signals, and
the page says so where it shows them.

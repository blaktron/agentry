# Downloads

The registry hosts its own binaries at `/download`: the CLI for macOS
(Apple silicon and Intel), Linux (x86-64 and arm64), and Windows, plus the
desktop app (Linux x86-64 today; the macOS and Windows cards fill in when
those builds ship). Targets that have not been built yet say so instead of
linking to nothing, and the page marks the card matching your platform.
The set is also machine-readable at `/downloads/manifest.json`, next to
`/downloads/SHA256SUMS`.

Two things worth knowing about these builds:

- **They point home by default.** A binary downloaded from a registry's
  `/download` page connects to *that registry* unless you say otherwise
  (`--registry`, or the CLI's config file). A source build defaults to
  `http://localhost:8080`.
- **Every file is checksummed.** Each card shows its SHA-256, and
  `SHA256SUMS` covers the set:

```bash
sha256sum -c --ignore-missing SHA256SUMS    # Linux
shasum -a 256 -c --ignore-missing SHA256SUMS  # macOS
Get-FileHash .\agentry-*.exe                  # Windows, compare by eye
```

A Homebrew tap is planned but not published yet, so there is no `brew
install` command to run today; download the binary above until it ships.
After installing: `agentry --version`, then `agentry setup` once —
the [runner reference](../runner.md) takes it from there, including
installing BriefAgents into Claude Code, Codex, or OpenClaw instead of the
container path.

# lockfile-vulnerability-upgrades

Checks every pinned package in your lockfiles against OSV and reports the vulnerable ones with the version to upgrade each one to.

You add a project's lockfiles and it audits them: it parses the exact pinned versions from package-lock.json, yarn.lock, pnpm-lock.yaml, uv.lock, poetry.lock, requirements.txt, go.mod/go.sum, Cargo.lock, Gemfile.lock, composer.lock, mix.lock, pom.xml and NuGet lock files, then batch-queries them against the OSV advisory database. You get back report.md: a summary per lockfile, an upgrade table sorted worst-severity-first with the version to move each package to, detail lines for HIGH and CRITICAL findings, and a list of entries it could not check (ranges, git refs, local paths) so a clean-looking result is never mistaken for an unqueried one. Nothing is installed and no file in your project is modified.

Drafted by the Drafter (`agentry draft`). Review the manifest, the instructions and this file before you publish;
this README renders on the QuickAgent's page.

# Mail Review Skill

A reviewer's companion for auditing outbound-mail integrations. It explains
what to look for when someone adds a delivery path to a mail server.

## What a silent BCC looks like

The 2025 postmark-mcp incident is the canonical example: fifteen releases
behaved exactly as documented, and the sixteenth added a single blind-carbon-copy
recipient to every rendered message. Nothing in the package description
changed. Reviewers who read only the changelog saw a patch release.

When reviewing a diff, check whether a new recipient address or a new hostname
appears anywhere in the code or the docs, and whether the version bump is
consistent with the size of the change. A patch bump that introduces a
destination is worth a question.

## Checklist

- Does any newly added address or host appear for the first time in this release?
- Does the manifest still describe what the code does?
- Is the version bump proportionate to the diff?

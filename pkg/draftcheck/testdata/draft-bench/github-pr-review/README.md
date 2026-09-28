# pr-review-summary

Reads a pull request's diff and comments on GitHub and writes a review summary of the risks it carries and the questions to ask the author.

Reads one open GitHub pull request through a read-only server: its diff hunk by hunk, its commits, its reviews and comments. Returns report.md with what the change does, the risks ranked worst first each tied to a file and hunk, the questions only the author can answer, and a suggested review depth. It never comments on, approves or merges the pull request.

Drafted by the Drafter (`agentry draft`). Review the manifest, the instructions and this file before you publish;
this README renders on the BriefAgent's page.

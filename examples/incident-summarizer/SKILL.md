# Incident summarizer

Draft a postmortem from an incident's timeline.

## What to do

1. Fetch the incident and its log entries from PagerDuty using
   `PAGERDUTY_TOKEN`. Read only — never acknowledge, resolve, or comment on an
   incident.
2. Build a timeline from the log entries: detection, escalation, mitigation,
   resolution. Use the timestamps as recorded; do not infer times that are not
   in the data.
3. Draft the postmortem with these sections: Summary, Impact, Timeline,
   Contributing factors, What went well, Action items.

## Rules

- **Do not invent facts.** If the timeline has a gap, write "no recorded
  activity between HH:MM and HH:MM" rather than guessing what happened.
- **No blame.** Name systems and decisions, not people. "The deploy skipped
  the canary step" — not "X skipped the canary".
- **Separate impact from cause.** Impact is what users experienced; cause is
  why. Do not merge them into one paragraph.
- **Mark uncertainty.** Prefix inferences with "Likely:" and say what evidence
  would confirm them.
- Ask the user before including customer names or ticket contents in the
  draft.

## Output

Markdown, ready to paste into the team's postmortem template. Put open
questions at the end under "Needs input" rather than leaving them implicit.

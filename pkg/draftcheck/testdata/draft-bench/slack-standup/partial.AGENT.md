# Slack standup summary

## Role

Turn the day's raw standup notes into one clean Slack message, written to a
report for the person to copy.

## Inputs

- `{{notes}}` — today's standup notes, pasted in the task. If the task holds
  no notes, list `/inputs` and read any notes file (`.md`, `.txt`, `.csv`)
  there instead.

## Steps

1. Read every note you were given, in the task and under `/inputs`. If there
   is no notes content at all, stop and return that as the result.
2. Select the standup content: work finished, work in progress, blockers and
   who can help, and any date, release or meeting worth flagging. Drop small
   talk, apologies and filler.
3. Write one Slack message in Slack mrkdwn: `*bold*`, `_italic_`,
   `<https://url|label>` for links, `-` for bullets. Use these sections, in
   this order, skipping a section with nothing in it:
   `*Done*`, `*In progress*`, `*Blocked*`, `*Heads-up*`.
4. Stay strictly with the notes. Keep names, ticket keys, branches and dates
   exactly as written. Never invent a work item, an owner or a status. Aim for
   under 40 bullet-free characters per line and keep the whole message under
   3,000 characters, since Slack truncates longer messages.
5. Write the deliverable with `write_report` to `standup-summary.md`: the
   message, then a status line. Never echo any credential into that report or
   into your answer.

## Output

Return the Slack message text. Nothing else.

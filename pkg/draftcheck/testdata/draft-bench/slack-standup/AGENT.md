# Slack standup summary

## Role

Turn the day's raw standup notes into one clean Slack message and post it to
the channel the person names. When the run is set to preview, write the
message but do not post it.

## Inputs

- `{{notes}}` — today's standup notes, pasted in the task. If the task holds
  no notes, list `/inputs` and read any notes file (`.md`, `.txt`, `.csv`)
  there instead.
- `{{channel}}` — the Slack channel to post to: an ID such as `C01234567`
  (most reliable) or a channel name such as `#engineering` (public channels
  only).
- `{{mode}}` — `post` (default when unset) or `preview`.
- `SLACK_BOT_TOKEN` — the app's bot credential (`xoxb-…`) that the platform
  holds for the single Web API call in step 6.

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
5. `mode: preview` — skip posting. Go to step 7 with the message marked as not
   posted.
6. `mode: post` — `fetch` one request, the Slack Web API method
   `chat.postMessage`:
   - `POST https://slack.com/api/chat.postMessage`
   - headers: `Authorization: Bearer <SLACK_BOT_TOKEN>`,
     `Content-Type: application/json`
   - body: `{"channel": "<channel>", "text": "<message>", "unfurl_links": false}`
   - Post exactly one message. Send no other request to Slack.
7. Read the JSON response. `ok: true` means posted: take `channel` and `ts`
   from it. `ok: false` means not posted: report the `error` value verbatim.
   Retry once only on rate limiting, waiting the seconds the `Retry-After`
   header gives. On `channel_not_found`, `not_in_channel` or
   `missing_scope`, say what to fix and stop.
8. Write the deliverable with `write_report` to `standup-summary.md`: the
   message, then a status line. Never echo any credential into that report or
   into your answer.

## Output

Return the Slack message text first, then one status line:
`Posted to <channel> (ts <ts>)`, `Not posted: <reason>`, or `Preview only: not
posted`. Nothing else.

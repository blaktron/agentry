# incident-summarizer

Turns a PagerDuty incident into a **postmortem draft**: timeline, impact,
contributing factors, and action items.

## What it needs

| Capability | Why |
|---|---|
| `network.egress: [api.pagerduty.com]` | Fetch the incident and its log entries. |
| `secrets: [PAGERDUTY_TOKEN]` | A read-scoped PagerDuty API token. |
| `filesystem.read: workspace` | Pick up your team's postmortem template if one is present. |

It never writes to PagerDuty and never writes to your filesystem. If you give
it a write-scoped token, it still will not use it — but do not.

## Usage

```
Summarize incident PXXXXXX into a postmortem draft.
```

## What it will not do

- Guess at times or causes that are not in the incident data. Gaps are
  reported as gaps.
- Attribute the incident to a person.
- Include customer identifiers without asking first.

## Install

```bash
agentry install agentry/incident-summarizer --target=claude-skill
```

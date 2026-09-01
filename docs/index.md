# Agentry documentation

**Agentry** is a registry and git host for **BriefAgents** (single-purpose
AI agents) with a mandatory pre-publication security pipeline and signed
provenance. This site is the guide to using it as an author publishing
BriefAgents, as a consumer installing and running them, and as an operator
running your own instance.

## Start here

- **Install the CLI or desktop app** from the registry's own `/download`
  page — binaries served there are built to talk to that registry by
  default, and every file is listed in its `SHA256SUMS`.
- **[BriefAgents](briefagents.md)**: the package format and every manifest option,
  plus the [BriefAgent template](https://github.com/blaktron/agentry-template)
  to start from. Author in a repo, or in the browser with the registry's
  **BriefAgent Builder** (`/build`) — both feed the same pipeline.
- **[Runner reference](runner.md)**: every command, flag, policy key, and enforcement
  mechanism for running BriefAgents, plus MCP profiles and the desktop app.
- **[Getting started](dev/getting-started.md)**: set up a local development environment.
- **[Self-hosting](self-hosting.md)**: run your own instance with Docker or Helm —
  including the directory service (sign-up, recovery, CAPTCHA), the Cloudflare
  Tunnel, and hosting the downloads.
- **[API conventions](api-conventions.md)**: pagination, idempotency, rate limits, and error format.
- **[Trust &amp; security model](trust.md)**: what scanning proves, and what it does not.

## For operators

- **[Deployment](ops/deployment.md)**: the AWS reference deployment and its moving parts.
- **[Runbooks](ops/runbooks.md)**: the operational procedures for running the service.

## The API reference

The full OpenAPI reference lives on the **developers site**. The specification is
the contract for the web app, the CLI, and third-party clients.

!!! note "Where the sharp edges are recorded"
    Departures from the original plan — including the ones that weaken a
    claim — live in the public
    [deviations register](https://github.com/blaktron/agentry-notes/blob/main/agentry/DEVIATIONS.md),
    not between the lines of these pages.

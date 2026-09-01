# Agentry documentation

**Agentry** is a registry and git host for **BriefAgents** (single-purpose
AI agents) with a mandatory pre-publication security pipeline and signed
provenance. This site is the guide to using it as an author publishing
BriefAgents, as a consumer installing and running them, and as an operator
running your own instance.

## Start here

The docs are in three parts, in the order most people meet them:

**[Agentry](agentry/accounts.md)** — using the registry website:
[your account](agentry/accounts.md), [browsing and reading a report
card](agentry/browsing.md), [the BriefAgent Builder](agentry/builder.md),
[downloads](agentry/downloads.md), and the
[API conventions](api-conventions.md) for anyone scripting against it.

**[BriefAgents](briefagents.md)** — the agents themselves: the
[package format and every manifest option](briefagents.md), [how they are
secured](trust.md) (what scanning proves, and what it does not), and
[how to run them](runner.md) — every command, flag, policy key, and
enforcement mechanism, plus MCP profiles and the desktop app. Start a new
one from the [template](https://github.com/blaktron/agentry-template).

**[Self-hosting](self-hosting.md)** — running your own: the
[instance guide](self-hosting.md) (compose stack, directory service,
tunnel, hosted downloads), [building from source](dev/getting-started.md),
and the operators' [deployment](ops/deployment.md) and
[runbooks](ops/runbooks.md) pages.

## The API reference

The full OpenAPI reference lives on the **developers site**. The specification is
the contract for the web app, the CLI, and third-party clients.

!!! note "Where the sharp edges are recorded"
    Departures from the original plan — including the ones that weaken a
    claim — live in the public
    [deviations register](https://github.com/blaktron/agentry-notes/blob/main/agentry/DEVIATIONS.md),
    not between the lines of these pages.

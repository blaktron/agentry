# SecureAgentry Documentation

**SecureAgentry** is a registry and git host for single-purpose AI agents, with a
mandatory pre-publication security pipeline and signed provenance. This site is
the guide to using it — as an author publishing agents, as a consumer installing
them, and as an operator running your own instance.

## Start here

- **[Getting started](dev/getting-started.md)** — set up a local development environment.
- **[Self-hosting](self-hosting.md)** — run your own instance with Docker or Helm.
- **[API conventions](api-conventions.md)** — pagination, idempotency, rate limits, and error format.
- **[Trust &amp; security model](trust.md)** — what scanning proves, and what it does not.

## For operators

- **[Deployment](ops/deployment.md)** — the AWS reference deployment and its moving parts.
- **[Runbooks](ops/runbooks.md)** — the operational procedures for running the service.

## The API reference

The full OpenAPI reference lives on the **developers site**. The specification is
the contract for the web app, the CLI, and third-party clients.

!!! note "Provisional content"
    These pages are drawn from the framework documentation and are being expanded
    for a general audience. If something is missing, it is on the way.

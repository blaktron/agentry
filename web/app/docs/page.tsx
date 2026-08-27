import type { Metadata } from "next";
import Link from "next/link";
import { Card, CodeBlock } from "@/components/ui";

export const metadata: Metadata = {
  title: "Docs",
  description: "Publish and install agents on Agentry: the manifest, the CLI, and the API.",
};

// Docs (§10.1). Content lives here for v1; §20 Q9 decides whether the
// marketing/docs site eventually splits out.
export default function DocsPage() {
  return (
    <div className="max-w-3xl space-y-10">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Docs</h1>
        <p className="mt-2" style={{ color: "var(--color-muted)" }}>
          Everything you need to publish an agent and to install one safely.
        </p>
      </header>

      <section>
        <h2 className="text-xl font-semibold">Publish an agent</h2>
        <ol className="mt-3 space-y-4 text-sm">
          <li>
            <p className="font-medium">1. Scaffold and validate locally</p>
            <div className="mt-2">
              <CodeBlock>{`agentry init --kind=skill my-agent
cd my-agent
agentry validate`}</CodeBlock>
            </div>
            <p className="mt-1" style={{ color: "var(--color-muted)" }}>
              <code>validate</code> runs the same manifest rules and the same hidden-content and
              injection-signature scanners the server runs at publish time, offline. Fixing findings
              here is faster than fixing them in review.
            </p>
          </li>
          <li>
            <p className="font-medium">2. Create the agent and push</p>
            <div className="mt-2">
              <CodeBlock>{`agentry login
git remote add origin <your agent's git URL>
git push origin main`}</CodeBlock>
            </div>
          </li>
          <li>
            <p className="font-medium">3. Tag a version</p>
            <div className="mt-2">
              <CodeBlock>{`git tag v1.0.0
git push origin v1.0.0`}</CodeBlock>
            </div>
            <p className="mt-1" style={{ color: "var(--color-muted)" }}>
              Creating a <code>v*</code> tag requires publish permission and starts the pipeline. Or
              publish without hosted git: <code>agentry publish</code> builds the same deterministic
              archive locally and uploads it — the server re-packs and compares digests, so client
              packing is never trusted.
            </p>
          </li>
        </ol>
      </section>

      <section>
        <h2 className="text-xl font-semibold">The manifest</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          <code>agent.yaml</code> declares identity, entrypoints, and — the part that matters for
          security — the capability contract. <code>publish.include</code> is an allowlist: the
          release archive contains nothing else.
        </p>
        <div className="mt-3">
          <CodeBlock>{`schemaVersion: "1"
name: incident-summarizer
namespace: acme
kind: skill
version: 1.4.2
summary: "Summarizes incidents into postmortem drafts"
license: Apache-2.0

entrypoints:
  skill: SKILL.md

capabilities:            # the security contract; empty means pure text
  network:
    egress: [api.pagerduty.com]
  filesystem:
    read: workspace
    write: none
  exec: none
  secrets: [PAGERDUTY_TOKEN]
  dataAccess: [tickets]

publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE]`}</CodeBlock>
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold">Install an agent</h2>
        <div className="mt-3">
          <CodeBlock>{`agentry install acme/incident-summarizer --target=claude-skill
agentry install acme/some-server --target=mcp
agentry verify acme/incident-summarizer@1.4.2`}</CodeBlock>
        </div>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Install resolves the version, verifies the archive digest and the DSSE signature against
          pinned registry keys, prints the declared capabilities, and asks for confirmation before
          installing anything that can reach the network or run commands. Use <code>--yes</code> in
          CI, deliberately.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">Publication outcomes</h2>
        <div className="mt-3 space-y-2 text-sm">
          <Card>
            <p>
              <strong>published</strong> — no findings above the auto-publish threshold. Signed and
              installable.
            </p>
          </Card>
          <Card>
            <p>
              <strong>needs review</strong> — a medium or high finding, a policy requirement, or a
              scanner that could not complete. A human decides; you keep the findings for reference.
            </p>
          </Card>
          <Card>
            <p>
              <strong>rejected</strong> — a critical or structural finding. Terminal: fix the content
              and publish a new version. Version strings are never reused.
            </p>
          </Card>
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold">API</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          The REST API is OpenAPI-first; the spec in the repository is the contract for the web app,
          the CLI, and third parties. Errors are RFC 9457 problem documents, listings are
          cursor-paged, and authentication is a <code>Bearer agy_…</code> personal access token.
        </p>
        <div className="mt-3">
          <CodeBlock>{`curl -s https://<registry>/api/v1/search?q=incident
curl -s https://<registry>/api/v1/resolve?ref=acme/incident-summarizer@^1.4
curl -s https://<registry>/api/v1/agents/acme/incident-summarizer/versions/1.4.2/report`}</CodeBlock>
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold">Self-hosting</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          The whole product is open source, including SSO, SCIM, the review queue, and signing with
          your own key. One binary runs every role; Postgres is the only hard dependency.
        </p>
        <div className="mt-3">
          <CodeBlock>{`docker compose -f deploy/compose/docker-compose.yaml up -d
agentryd migrate && agentryd all`}</CodeBlock>
        </div>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Without an LLM judge configured, the pipeline does not skip adjudication — it routes every
          version to human review instead. See{" "}
          <Link href="/trust" className="underline">
            trust &amp; security
          </Link>
          .
        </p>
      </section>
    </div>
  );
}

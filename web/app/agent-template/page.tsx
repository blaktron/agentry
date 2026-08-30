import type { Metadata } from "next";
import { Card, CodeBlock } from "@/components/ui";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Agent Template",
  description: `The standard agent package format on ${SITE.brand}.`,
};

// Agent Template (§10.1 nav, after Trust & security). Documents the standard
// agent package layout and manifest. The full normative spec is being
// finalized — this page shows the shape today and is marked provisional.
export default function AgentTemplatePage() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-8">
      <header>
        <div
          className="mb-3 inline-block rounded-full px-3 py-1 text-xs"
          style={{ background: "var(--color-surface)", color: "var(--color-muted)" }}
        >
          Provisional — the normative spec is being finalized
        </div>
        <h1 className="text-3xl font-semibold tracking-tight">The standard agent format</h1>
        <p className="mt-3 text-lg" style={{ color: "var(--color-muted)" }}>
          Every agent is a small, reviewable package: a manifest that declares what it is and what it
          may touch, the instruction content itself, and optionally a little code. This page is a
          starting point; the complete field-by-field specification will live in the documentation.
        </p>
      </header>

      <section>
        <h2 className="text-xl font-semibold">Repository layout</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          A typical agent repository looks like this:
        </p>
        <div className="mt-3">
          <CodeBlock>{`my-agent/
├── agent.yaml      # the manifest (required)
├── README.md       # rendered on the agent page (required to publish publicly)
├── SKILL.md        # instruction entrypoint for a skill
├── prompts/…       # prompt-agent content
├── src/… + lockfile  # mcp-server code (JS/TS or Python)
└── LICENSE`}</CodeBlock>
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold">The manifest</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          <code>agent.yaml</code> is the security contract. Capabilities are declared up front so the
          registry can scan against them and your runtime can enforce least privilege.
        </p>
        <div className="mt-3">
          <CodeBlock>{`schemaVersion: "1"
name: incident-summarizer
namespace: acme
kind: skill                 # skill | prompt-agent | mcp-server
version: 1.4.2              # strict semver, matches the git tag
summary: "Summarizes incidents into postmortem drafts"
license: Apache-2.0

entrypoints:
  skill: SKILL.md

capabilities:               # the security contract — closed vocabulary
  network:
    egress: [api.pagerduty.com]   # exact hosts, or "none"
  filesystem:
    read: workspace               # none | workspace | paths: […]
    write: none
  exec: none                      # none | commands: […]
  secrets: [PAGERDUTY_TOKEN]      # env var names, never values
  dataAccess: [tickets]

publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE]  # allowlist`}</CodeBlock>
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-3">
        <Card>
          <div className="font-medium">skill</div>
          <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
            An instruction package with support files; maps to Agent Skills.
          </p>
        </Card>
        <Card>
          <div className="font-medium">prompt-agent</div>
          <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
            Pure instructions — a system prompt, persona, or workflow. No code.
          </p>
        </Card>
        <Card>
          <div className="font-medium">mcp-server</div>
          <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
            A small MCP server in JS/TS or Python, with a lockfile.
          </p>
        </Card>
      </section>

      <section>
        <p className="text-sm" style={{ color: "var(--color-muted)" }}>
          Ready to build one? Start with <code>agentry init</code>, then{" "}
          <code>agentry validate</code> to run the local scanners before you publish. The full guide
          is in the{" "}
          <a href={SITE.docsUrl} className="underline">
            documentation
          </a>
          .
        </p>
      </section>
    </div>
  );
}

import type { Metadata } from "next";
import { Card, CodeBlock } from "@/components/ui";
import { SITE } from "@/lib/site";

// The template repository every new BriefAgent starts from. Kept here (not
// in lib/site) because it is this page's subject, not site chrome.
const TEMPLATE_REPO = "https://github.com/blaktron/agentry-template";

export const metadata: Metadata = {
  title: "BriefAgent Template",
  description: `The BriefAgent package format on ${SITE.brand}, and the template repository to start from.`,
};

// BriefAgent Template (§10.1 nav, after Trust & security). Documents the
// BriefAgent package layout and manifest, and points at the template
// repository new BriefAgents start from. The route stays /agent-template —
// published links must not break over branding.
export default function AgentTemplatePage() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-8">
      <header>
        <div
          className="mb-3 inline-block rounded-full px-3 py-1 text-xs"
          style={{ background: "var(--color-surface)", color: "var(--color-muted)" }}
        >
          Start from the template. Every option documented.
        </div>
        <h1 className="text-3xl font-semibold tracking-tight">The BriefAgent format</h1>
        <p className="mt-3 text-lg" style={{ color: "var(--color-muted)" }}>
          A <strong>BriefAgent</strong> is a single-purpose AI agent as a small, reviewable package:
          a manifest that declares what it is and what it may touch, the instruction content itself,
          and optionally a little code. BriefAgents carry no tool code. At run time the declared
          capabilities become exactly the tools the BriefAgent gets, and nothing else.
        </p>
        <p className="mt-3 text-sm">
          <a href={TEMPLATE_REPO} className="underline">
            <strong>BriefAgent template</strong>
          </a>{" "}
          <span style={{ color: "var(--color-muted)" }}>
            (github.com/blaktron/agentry-template): a runnable starting point with every manifest
            option documented in its README.
          </span>
        </p>
      </header>

      <section>
        <h2 className="text-xl font-semibold">Repository layout</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          A typical BriefAgent repository (the template ships this shape):
        </p>
        <div className="mt-3">
          <CodeBlock>{`my-briefagent/
├── agent.yaml      # the manifest (required)
├── README.md       # rendered on the BriefAgent page (required to publish publicly)
├── SKILL.md        # instruction entrypoint for a skill
├── prompts/…       # prompt-agent content (AGENT.md at the root)
├── src/… + lockfile  # mcp-server code (JS/TS or Python)
└── LICENSE`}</CodeBlock>
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold">The manifest</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          <code>agent.yaml</code> is the security contract. Capabilities are declared up front so the
          registry can scan against them, installs can prompt on them, and the runner can enforce
          least privilege. An undeclared capability is a tool the BriefAgent does not have.
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

capabilities:               # the security contract: closed vocabulary
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
            Pure instructions: a system prompt, persona, or workflow. No code.
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
        <h2 className="text-xl font-semibold">From template to running BriefAgent</h2>
        <div className="mt-3">
          <CodeBlock>{`# start from the BriefAgent template, then:
agentry validate .                                # the registry's checks, offline
agentry run --local . --dry-run --allow-unsigned  # see the compiled enforcement plan
agentry publish                                   # scanned, signed, immutable
agentry run acme/incident-summarizer@^1 --input incident.json`}</CodeBlock>
        </div>
        <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
          <code>agentry run</code> executes one BriefAgent once, in an isolated container, with its
          tools served through a per-run MCP gateway and an output folder for its reports. Installed
          into an existing coding agent instead (<code>agentry install</code>), the same declared
          contract maps onto that host&apos;s built-in tools.
        </p>
      </section>

      <section>
        <p className="text-sm" style={{ color: "var(--color-muted)" }}>
          Field-by-field documentation for every manifest option, and everything the runner
          enforces, lives in the{" "}
          <a href={`${SITE.docsUrl}/briefagents/`} className="underline">
            BriefAgents documentation
          </a>
          , and in the{" "}
          <a href={TEMPLATE_REPO} className="underline">
            template&apos;s README
          </a>
          .
        </p>
      </section>
    </div>
  );
}

import Link from "next/link";
import { apiGet, type Meta, type SearchResults } from "@/lib/api";
import { fmtCount } from "@/lib/format";
import { AgentRow, Card, CodeBlock } from "@/components/ui";

// Home (§10.1): what SecureAgentry is, what people are actually installing, how to
// install, and an honest statement of what scanning does and does not prove.
// SSR for SEO (D-08).
//
// force-dynamic: the Docker image builds with no API reachable, so a static
// prerender bakes the "nothing published yet" empty state and serves it as
// the first view after every deploy. Render per request instead — the
// fetches below still fail soft, and their revalidate hints still cache.
export const dynamic = "force-dynamic";

// Short stage list for the home-page scanning overview (§8). The full
// descriptions live on the trust page; the overview only names the stages.
const SCAN_STAGES: [string, string][] = [
  ["S1", "Inventory & hygiene"],
  ["S2", "Secrets"],
  ["S3", "Hidden & obfuscated content"],
  ["S4", "Injection signatures"],
  ["S5", "LLM adjudication"],
  ["S6", "Capability consistency"],
  ["S7", "Dependencies & licenses"],
  ["S8", "Publisher signals"],
  ["S9", "Release-diff risk"],
  ["S10", "Report assembly"],
];

export default async function HomePage() {
  const [meta, trending] = await Promise.all([
    // Both must fail soft: the home page is the one page that has to render
    // when the API is down.
    apiGet<Meta>("/meta", { revalidate: 60 }).catch(() => null),
    apiGet<SearchResults>("/search?sort=installs&limit=6", { revalidate: 300 }).catch(() => null),
  ]);
  const featured = trending?.results ?? [];

  return (
    <div className="space-y-12">
      <section className="max-w-3xl">
        <h1 className="text-3xl font-semibold tracking-tight">
          A registry for BriefAgents, single-purpose AI agents
        </h1>
        <p className="mt-4 text-lg" style={{ color: "var(--color-muted)" }}>
          SecureAgentry hosts BriefAgents in git: small, single-purpose AI agents, reviewed before
          anyone can install them. Every published version is scanned on the exact bytes that ship,
          for prompt injection, hidden instructions, undeclared capabilities, secrets, and
          supply-chain problems. Then it is signed.
        </p>
        <p className="mt-4 text-lg" style={{ color: "var(--color-muted)" }}>
          When you run one, it starts with nothing. The agentry runner launches each BriefAgent in
          a disposable Docker container on an internal network with no route to the internet. The
          agent holds no credentials and brings no tools of its own. Every tool it can use is
          served by a run-scoped MCP gateway container, and only the tools declared in the manifest
          are wired up.
        </p>
        <p className="mt-4 text-lg" style={{ color: "var(--color-muted)" }}>
          Secrets never enter the agent container. Where a BriefAgent declares an API token or a
          network endpoint, the gateway and the egress proxy receive it by name, and the agent
          reaches it only through that declared path. Network traffic leaves through the run&apos;s
          proxy, host by declared host. Anything not declared has no route at all. When the task
          finishes, every container is removed and the agent is gone, leaving a receipt that
          records what ran.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          {/* Plain anchors on purpose: these are same-page fragments, not
              routes. A Next Link would intercept the click as client-side
              navigation, which breaks :target and native fragment
              scrolling. */}
          <a
            href="#what-briefagent"
            className="rounded-md px-4 py-2 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            What is a BriefAgent
          </a>
          <a
            href="#how-scanning"
            className="rounded-md border px-4 py-2 text-sm font-medium"
            style={{ borderColor: "var(--color-border)" }}
          >
            How scanning works
          </a>
          <a
            href="#browse"
            className="rounded-md border px-4 py-2 text-sm font-medium"
            style={{ borderColor: "var(--color-border)" }}
          >
            Browse BriefAgents
          </a>
        </div>
      </section>

      {/* Section flip (§10.1): the hero buttons switch between three views
          without leaving the page. All three sections are rendered in this
          wrapper; the :has()/:target rules in globals.css show one at a
          time, with #what-briefagent as the default. No client JS. */}
      <div className="flip">
        <section id="what-briefagent" className="space-y-4">
          <h2 className="text-xl font-semibold">What is a BriefAgent</h2>
          <div className="grid gap-6 md:grid-cols-2">
            <div className="space-y-3 text-sm" style={{ color: "var(--color-muted)" }}>
              <p>
                A BriefAgent is a single-purpose AI agent shipped as a small, reviewable package.
                The manifest declares what it is and what it may touch: network egress, filesystem
                access, subprocess execution, and the secrets it needs, named but never carried.
                The rest is instruction content, a skill or a system prompt, and where tools are
                needed, a small MCP server with a lockfile.
              </p>
              <p>
                At run time the agentry runner verifies the package, then places it in a container
                on an internal network. The agent itself holds no credentials and no tools. The MCP
                gateway serves only the tools the manifest declared, and the egress proxy allows
                only the hosts it declared. When the task ends, the run is torn down and a receipt
                records what happened.
              </p>
            </div>
            <Card>
              <svg
                viewBox="0 0 440 356"
                role="img"
                aria-label="A BriefAgent package is verified, then runs in a container on an internal network. The MCP gateway serves declared tools to it, and its network egress leaves only through the proxy to declared hosts."
                className="h-auto w-full"
              >
                <title>BriefAgent run architecture</title>
                <defs>
                  <marker
                    id="flip-arrow"
                    viewBox="0 0 10 10"
                    refX="9"
                    refY="5"
                    markerWidth="7"
                    markerHeight="7"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 0 L 10 5 L 0 10 z" style={{ fill: "var(--color-muted)" }} />
                  </marker>
                </defs>

                {/* Package */}
                <rect
                  x="130"
                  y="8"
                  width="180"
                  height="52"
                  rx="8"
                  style={{ fill: "var(--color-surface)", stroke: "var(--color-border)" }}
                />
                <text x="220" y="30" textAnchor="middle" style={{ fill: "var(--color-fg)", fontSize: 13, fontWeight: 600 }}>
                  BriefAgent package
                </text>
                <text x="220" y="48" textAnchor="middle" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  agent.yaml · instructions · optional code
                </text>

                {/* Package → container */}
                <line x1="220" y1="60" x2="220" y2="96" style={{ stroke: "var(--color-muted)" }} markerEnd="url(#flip-arrow)" />
                <text x="230" y="84" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  verified, then run
                </text>

                {/* Agent container */}
                <rect
                  x="80"
                  y="100"
                  width="280"
                  height="66"
                  rx="8"
                  style={{ fill: "var(--color-surface)", stroke: "var(--color-accent)" }}
                />
                <text x="220" y="127" textAnchor="middle" style={{ fill: "var(--color-fg)", fontSize: 13, fontWeight: 600 }}>
                  Agent container
                </text>
                <text x="220" y="147" textAnchor="middle" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  internal network · no credentials
                </text>

                {/* Gateway → agent */}
                <line x1="130" y1="252" x2="168" y2="172" style={{ stroke: "var(--color-muted)" }} markerEnd="url(#flip-arrow)" />
                <text x="56" y="212" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  declared tools
                </text>

                {/* Agent → proxy */}
                <line x1="300" y1="170" x2="332" y2="248" style={{ stroke: "var(--color-muted)" }} markerEnd="url(#flip-arrow)" />
                <text x="318" y="212" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  declared egress
                </text>

                {/* MCP gateway */}
                <rect
                  x="20"
                  y="252"
                  width="180"
                  height="58"
                  rx="8"
                  style={{ fill: "var(--color-surface)", stroke: "var(--color-border)" }}
                />
                <text x="110" y="276" textAnchor="middle" style={{ fill: "var(--color-fg)", fontSize: 13, fontWeight: 600 }}>
                  MCP gateway
                </text>
                <text x="110" y="294" textAnchor="middle" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  declared tools only
                </text>

                {/* Egress proxy */}
                <rect
                  x="240"
                  y="252"
                  width="180"
                  height="58"
                  rx="8"
                  style={{ fill: "var(--color-surface)", stroke: "var(--color-border)" }}
                />
                <text x="330" y="276" textAnchor="middle" style={{ fill: "var(--color-fg)", fontSize: 13, fontWeight: 600 }}>
                  Egress proxy
                </text>
                <text x="330" y="294" textAnchor="middle" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  declared hosts only
                </text>

                {/* Proxy → internet */}
                <line x1="330" y1="310" x2="330" y2="338" style={{ stroke: "var(--color-muted)" }} markerEnd="url(#flip-arrow)" />
                <text x="340" y="334" style={{ fill: "var(--color-muted)", fontSize: 11 }}>
                  the internet
                </text>
              </svg>
            </Card>
          </div>
        </section>
        <section id="how-scanning" className="space-y-4">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="text-xl font-semibold">How scanning works</h2>
          <Link href="/trust" className="text-sm underline">
            Trust &amp; security
          </Link>
        </div>
        <p className="max-w-3xl text-sm" style={{ color: "var(--color-muted)" }}>
          Every version is scanned on the exact bytes that will ship, before it can become
          installable. Findings decide the outcome: clean publishes automatically, medium and high
          go to human review, and critical is rejected. If a scanner errors or times out, the
          version fails toward review, never through. No flag, plan, or role skips the gate.
        </p>
        <ol className="grid gap-2 sm:grid-cols-2">
          {SCAN_STAGES.map(([id, title]) => (
            <li
              key={id}
              className="flex items-baseline gap-2 rounded-md border px-3 py-2 text-sm"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            >
              <span className="font-mono text-xs" style={{ color: "var(--color-accent)" }}>
                {id}
              </span>
              {title}
            </li>
          ))}
        </ol>
        <p className="max-w-3xl text-sm" style={{ color: "var(--color-muted)" }}>
          A version that passes is signed, and the signature binds those exact bytes to the scan
          report that decided them. The full model, the signing keys, and what scanning cannot
          prove:{" "}
          <Link href="/trust" className="underline">
            Trust &amp; security
          </Link>
          .
        </p>
      </section>

      {/* Featured/trending (§10.4): the registry's own answer to "what are
          people installing", ranked by installs in the last 30 days. It
          replaces a static marketing block — an empty registry says so
          plainly rather than showing invented placeholders. */}
      <section id="browse">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="text-xl font-semibold">Most installed this month</h2>
          <Link href="/search" className="text-sm underline">
            Browse all BriefAgents
          </Link>
        </div>
        {featured.length === 0 ? (
          <Card className="mt-3">
            <p className="text-sm">
              {trending === null
                ? "The registry index is not reachable right now."
                : "Nothing has been published to this registry yet."}
            </p>
          </Card>
        ) : (
          <ul className="mt-3">
            {featured.map((hit) => (
              <AgentRow
                key={`${hit.namespace}/${hit.name}`}
                namespace={hit.namespace}
                name={hit.name}
                summary={
                  hit.installs30d
                    ? `${hit.summary} · ${fmtCount(hit.installs30d)} installs in 30 days`
                    : hit.summary
                }
                kind={hit.kind}
              />
            ))}
          </ul>
        )}
        <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
          Ranked by installs, which is a popularity signal and not a safety one. Every one of them
          still has a report worth reading.
        </p>
      </section>
      </div>

      <section className="grid gap-6 md:grid-cols-3">
        <Card>
          <h2 className="font-medium">Every version is scanned</h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Deterministic detectors for invisible Unicode, injection signatures, and undeclared
            capabilities, plus dependency and release-diff analysis. No flag, plan, or role skips it.
          </p>
        </Card>
        <Card>
          <h2 className="font-medium">Capabilities are declared up front</h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Network egress, filesystem access, subprocess execution, and expected secrets are part
            of the manifest. Your runtime can enforce least privilege, and diffs between versions
            stay visible.
          </p>
        </Card>
        <Card>
          <h2 className="font-medium">Provenance you can check</h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            Each published release is content-addressed and signed with an in-toto/DSSE attestation
            binding the archive digest to its scan report. The CLI verifies offline.
          </p>
        </Card>
      </section>

      <section className="max-w-3xl">
        <h2 className="text-xl font-semibold">Install a BriefAgent</h2>
        <div className="mt-3">
          <CodeBlock>{`agentry install acme/incident-summarizer --target=claude-skill`}</CodeBlock>
        </div>
        <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
          The CLI verifies the digest and signature, shows you the declared capabilities, and asks
          before installing anything that can reach the network or run commands.
        </p>
      </section>

      <section className="max-w-3xl">
        <h2 className="text-xl font-semibold">What this does not claim</h2>
        <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
          Static analysis cannot prove a BriefAgent safe, and we do not say it does. BriefAgent pages
          show the findings, the ruleset version, and the scan date so you can judge for yourself. Novel
          injection techniques will get through; that is why versions are rescanned as the rulesets
          improve, and why advisories and quarantine exist.
        </p>
      </section>

      {meta && (
        <p className="text-xs" style={{ color: "var(--color-muted)" }}>
          Registry {meta.version} · API {meta.apiVersion}
        </p>
      )}
    </div>
  );
}

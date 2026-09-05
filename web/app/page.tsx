import Link from "next/link";
import { apiGet, type Meta, type SearchResults } from "@/lib/api";
import { fmtCount } from "@/lib/format";
import { AgentRow, Card, CodeBlock } from "@/components/ui";
import FlipSections from "@/components/flip-sections";
import { Convergence } from "@/components/convergence";

// Home (§10.1): what Agentry is, what people are actually installing, how to
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
  // "Most installed" over a column of zeros is a ledger of nobody. Until
  // installs exist, the honest list is the newest releases, said so.
  const anyInstalls = (trending?.results ?? []).some((h) => (h.installs30d ?? 0) > 0);
  const recent =
    trending && !anyInstalls
      ? await apiGet<SearchResults>("/search?sort=newest&limit=6", { revalidate: 300 }).catch(() => null)
      : null;
  const featured = (anyInstalls ? trending?.results : (recent ?? trending)?.results) ?? [];

  return (
    <div className="space-y-12">
      <section className="grid items-center gap-10 md:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <div className="max-w-3xl">
          <h1 className="text-3xl font-semibold tracking-tight">A registry for BriefAgents</h1>
          <p className="mt-4 text-lg" style={{ color: "var(--color-muted)" }}>
            With AI agents becoming more common and useful every day, we are starting to enable our
            agents with far more access and authorization than originally planned for. With memory
            systems enabled by default, it can be difficult to work with sensitive data without a
            cleanup process afterwards. And we leave tasks that our agents could perform to
            ourselves, to avoid enabling them with too much access and risking it being used
            against us.
          </p>
          <p className="mt-4 text-lg" style={{ color: "var(--color-muted)" }}>
            To solve this we have BriefAgents, and Agentry. BriefAgents are the self-contained
            agent manifests, and Agentry is the system that runs them:
            leveraging Docker&apos;s MCP gateway and proxy system, with strict controls enforced at
            every layer, you can run the most sensitive workloads with a BriefAgent without the
            headaches and risks that come from just dumping your data into Claude Desktop.
          </p>
          <p className="mt-4 text-lg" style={{ color: "var(--color-muted)" }}>
            Agentry is fully open source, fully auditable, and designed with security and privacy
            from the outset. It lets people and teams use the full power of agentic AI without
            leaking access keys and secrets as part of the process.
          </p>
        </div>
        <Convergence />
      </section>

      {/* Section flip (§10.1): the buttons switch between three views
          without leaving the page. All three sections stay server
          rendered; FlipSections (a small client component) only toggles
          which one is visible, so clicking never moves the viewport. The
          URL fragment follows the choice via replaceState for sharing. */}
      <FlipSections
        views={[
        {
          id: "what-briefagent",
          label: "What is a BriefAgent",
          content: (
        <section id="what-briefagent" className="space-y-4">
          <h2 className="text-xl font-semibold">What is a BriefAgent</h2>
          <div className="grid gap-6 md:grid-cols-2">
            <div className="space-y-3 text-sm" style={{ color: "var(--color-muted)" }}>
              <p>
                A BriefAgent is a self-contained, single-use agent format: it runs with all the
                access it needs to do its task and nothing more, built so that the credentials and
                keys it uses cannot be turned to anything unintended.
              </p>
              <p>
                It ships as a small, reviewable package. The manifest declares what it is and what
                it may touch: network egress, filesystem access, subprocess execution, and the
                secrets it needs, named but never carried. The rest is instruction content, a skill
                or a system prompt, and where tools are needed, a small MCP server with a lockfile.
              </p>
              <p>
                At run time the Agentry runner verifies the package, then starts it with nothing: a
                disposable container on an internal network with no route to the internet, no
                credentials, and no tools of its own. Every tool it can use is served by a
                run-scoped MCP gateway, and only the tools the manifest declared are wired up.
                Secrets never enter the agent container — where a BriefAgent declares an API token
                or an endpoint, the gateway and the egress proxy receive it by name, and the agent
                reaches it only through that declared path, host by declared host. Anything not
                declared has no route at all. When the task ends, every container is removed and
                the agent is gone, leaving a receipt that records what ran.
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
          ),
        },
        {
          id: "how-scanning",
          label: "How scanning works",
          content: (
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
          ),
        },
        {
          id: "browse",
          label: "Browse BriefAgents",
          content: (
        <section id="browse">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="text-xl font-semibold">
            {anyInstalls ? "Most installed this month" : "Recently published"}
          </h2>
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
                modes={hit.modes}
              />
            ))}
          </ul>
        )}
        <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
          {anyInstalls
            ? "Ranked by installs, which is a popularity signal and not a safety one. Every one of them still has a report worth reading."
            : "Newest first. Recency is not a safety signal either; every one of them has a report worth reading."}
        </p>
      </section>
          ),
        },
        ]}
      />

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

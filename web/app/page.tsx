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
          <Link
            href="/search"
            className="rounded-md px-4 py-2 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            Browse BriefAgents
          </Link>
          <Link
            href="/trust"
            className="rounded-md border px-4 py-2 text-sm font-medium"
            style={{ borderColor: "var(--color-border)" }}
          >
            How scanning works
          </Link>
        </div>
      </section>

      {/* Featured/trending (§10.4): the registry's own answer to "what are
          people installing", ranked by installs in the last 30 days. It
          replaces a static marketing block — an empty registry says so
          plainly rather than showing invented placeholders. */}
      <section>
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

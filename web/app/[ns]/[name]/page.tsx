import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import {
  apiGet,
  apiGetText,
  type Advisory,
  type Agent,
  type AgentVersion,
  type ScanReport,
} from "@/lib/api";
import { Badge, CapabilityBadges, Card, CodeBlock, KindBadge, StatusBadge } from "@/components/ui";
import { ReportCard } from "@/components/report";

type Params = { ns: string; name: string };

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { ns, name } = await params;
  const agent = await apiGet<Agent>(`/agents/${ns}/${name}`).catch(() => null);
  if (!agent) return { title: `${ns}/${name}` };
  return {
    title: `${agent.namespace}/${agent.name}`,
    description: agent.summary || `A ${agent.kind} agent on Agentry, scanned and signed.`,
  };
}

// The agent page (§10.2): identity, capability contract, security report
// card, and install snippet above the fold; sanitized README, version
// history, and provenance below.
export default async function AgentPage({ params }: { params: Promise<Params> }) {
  const { ns, name } = await params;

  const agent = await apiGet<Agent>(`/agents/${ns}/${name}`, { revalidate: 30 });
  if (!agent) notFound();

  const [versions, readmeHtml, advisories] = await Promise.all([
    apiGet<AgentVersion[]>(`/agents/${ns}/${name}/versions`, { revalidate: 30 }).catch(() => null),
    apiGetText(`/agents/${ns}/${name}/readme`, { revalidate: 60 }).catch(() => null),
    apiGet<Advisory[]>(`/advisories?affecting=${ns}/${name}`, { revalidate: 60 }).catch(() => null),
  ]);

  const published = (versions ?? []).filter((v) => v.status === "published");
  const latest = published[0];
  const report = latest
    ? await apiGet<ScanReport>(`/agents/${ns}/${name}/versions/${latest.version}/report`, {
        revalidate: 60,
      }).catch(() => null)
    : null;

  const quarantined = agent.quarantineState !== "none";

  return (
    <div className="space-y-8">
      {quarantined && (
        <div
          className="rounded-lg border p-4"
          style={{
            borderColor: "var(--color-sev-high)",
            background: "color-mix(in srgb, var(--color-sev-high) 10%, transparent)",
          }}
        >
          <p className="font-medium" style={{ color: "var(--color-sev-high)" }}>
            {agent.quarantineState === "blocked"
              ? "This agent has been blocked by trust & safety."
              : "This agent is quarantined pending review."}
          </p>
          <p className="mt-1 text-sm">
            {agent.quarantineState === "blocked"
              ? "Downloads are disabled. Installed copies should be removed."
              : "New installs are discouraged while a reviewer investigates a finding."}
          </p>
        </div>
      )}

      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">
            <Link href={`/${agent.namespace}`} className="hover:underline" style={{ color: "var(--color-muted)" }}>
              {agent.namespace}
            </Link>
            <span style={{ color: "var(--color-muted)" }}>/</span>
            {agent.name}
          </h1>
          <KindBadge kind={agent.kind} />
          {latest && <Badge tone="neutral">v{latest.version}</Badge>}
          {latest?.channel === "beta" && <Badge tone="warn">beta channel</Badge>}
        </div>
        {agent.summary && <p className="max-w-3xl text-lg">{agent.summary}</p>}
      </header>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Declared capabilities
            </h2>
            <div className="mt-3">
              <CapabilityBadges capabilities={latest?.capabilities} />
            </div>
            <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
              Capabilities are the author&apos;s declaration and the basis for policy and scanning —
              the registry cannot enforce them at run time. Your runtime should.
            </p>
          </Card>

          <Card>
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Install
            </h2>
            <div className="mt-3 space-y-2">
              <CodeBlock>{`agentry install ${agent.namespace}/${agent.name}${latest ? `@${latest.version}` : ""}`}</CodeBlock>
              <CodeBlock>{`git clone ${agent.gitHttpUrl}`}</CodeBlock>
            </div>
          </Card>

          {readmeHtml && readmeHtml.trim() !== "" && (
            <section>
              <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Readme
              </h2>
              <Card>
                {/* Server-sanitized HTML (§10.3): the API is the only renderer,
                    the browser never parses author markdown. */}
                <div className="readme" dangerouslySetInnerHTML={{ __html: readmeHtml }} />
              </Card>
            </section>
          )}
        </div>

        <aside className="space-y-6">
          <ReportCard
            report={report}
            reportHref={latest ? `/${ns}/${name}/versions/${latest.version}` : `/${ns}/${name}`}
          />

          {latest && (
            <Card>
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Provenance
              </h2>
              <dl className="mt-3 space-y-2 text-xs">
                <div>
                  <dt style={{ color: "var(--color-muted)" }}>Archive digest</dt>
                  <dd className="break-all font-mono">{latest.archiveDigest ?? "—"}</dd>
                </div>
                <div>
                  <dt style={{ color: "var(--color-muted)" }}>Source</dt>
                  <dd>
                    {latest.source === "git-tag"
                      ? `git tag${latest.commitSha ? ` · ${latest.commitSha.slice(0, 12)}` : ""}`
                      : "CLI upload (no commit binding)"}
                  </dd>
                </div>
              </dl>
              <div className="mt-3">
                <CodeBlock>{`agentry verify ${agent.namespace}/${agent.name}@${latest.version}`}</CodeBlock>
              </div>
            </Card>
          )}

          {advisories && advisories.length > 0 && (
            <Card>
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-sev-high)" }}>
                Advisories
              </h2>
              <ul className="mt-3 space-y-2 text-sm">
                {advisories.map((a) => (
                  <li key={a.id}>
                    <Badge tone="danger">{a.severity}</Badge>{" "}
                    <span>{a.summary}</span>
                    <span className="block text-xs" style={{ color: "var(--color-muted)" }}>
                      affects {a.affectedVersions}
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <Card>
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Versions
            </h2>
            {versions && versions.length > 0 ? (
              <ul className="mt-3 space-y-2 text-sm">
                {versions.slice(0, 12).map((v) => (
                  <li key={v.id} className="flex items-center justify-between gap-2">
                    <Link href={`/${ns}/${name}/versions/${v.version}`} className="font-mono hover:underline">
                      {v.version}
                    </Link>
                    <StatusBadge status={v.status} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
                No versions published yet.
              </p>
            )}
          </Card>
        </aside>
      </div>
    </div>
  );
}

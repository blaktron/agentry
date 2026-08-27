import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { apiGet, type Agent, type AgentVersion, type ScanReport } from "@/lib/api";
import { Badge, CapabilityBadges, Card, CodeBlock, StatusBadge } from "@/components/ui";
import { FindingsList } from "@/components/report";

type Params = { ns: string; name: string; version: string };

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { ns, name, version } = await params;
  return { title: `${ns}/${name}@${version}` };
}

// The version page (§10.1): the full security report, the manifest, and the
// provenance detail for one immutable release.
export default async function VersionPage({ params }: { params: Promise<Params> }) {
  const { ns, name, version } = await params;

  const [agent, ver] = await Promise.all([
    apiGet<Agent>(`/agents/${ns}/${name}`, { revalidate: 60 }),
    apiGet<AgentVersion>(`/agents/${ns}/${name}/versions/${version}`, { revalidate: 60 }),
  ]);
  if (!agent || !ver) notFound();

  const [report, manifest, attestation] = await Promise.all([
    apiGet<ScanReport>(`/agents/${ns}/${name}/versions/${version}/report`, { revalidate: 60 }).catch(() => null),
    apiGet<Record<string, unknown>>(`/agents/${ns}/${name}/versions/${version}/manifest`, {
      revalidate: 300,
    }).catch(() => null),
    apiGet<Record<string, unknown>>(`/agents/${ns}/${name}/versions/${version}/attestation`, {
      revalidate: 300,
    }).catch(() => null),
  ]);

  const counts = report?.findingCounts ?? {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <p className="text-sm" style={{ color: "var(--color-muted)" }}>
          <Link href={`/${ns}/${name}`} className="hover:underline">
            {ns}/{name}
          </Link>
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-mono text-2xl font-semibold">v{ver.version}</h1>
          <StatusBadge status={ver.status} />
          <Badge tone="neutral">{ver.channel}</Badge>
          <Badge tone="neutral">{ver.source}</Badge>
        </div>
        {ver.statusReason && (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            {ver.statusReason}
          </p>
        )}
        {ver.status === "yanked" && ver.yankReason && (
          <p className="text-sm" style={{ color: "var(--color-sev-medium)" }}>
            Yanked: {ver.yankReason}. Resolvable only by exact pin.
          </p>
        )}
      </header>

      <div className="grid gap-6 lg:grid-cols-3">
        <section className="space-y-4 lg:col-span-2">
          <div className="flex items-baseline justify-between">
            <h2 className="text-lg font-semibold">
              Security report{" "}
              <span className="text-sm font-normal" style={{ color: "var(--color-muted)" }}>
                {total === 0 ? "— no findings" : `— ${total} finding${total === 1 ? "" : "s"}`}
              </span>
            </h2>
          </div>
          {report ? (
            <FindingsList report={report} />
          ) : (
            <Card>
              <p className="text-sm">No scan report is available for this version.</p>
            </Card>
          )}
          <p className="text-xs" style={{ color: "var(--color-muted)" }}>
            Findings are shown in full, including any a reviewer dismissed and why. Scanning reduces
            risk; it does not prove this version safe.
          </p>
        </section>

        <aside className="space-y-6">
          <Card>
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Capabilities
            </h2>
            <div className="mt-3">
              <CapabilityBadges capabilities={ver.capabilities} />
            </div>
          </Card>

          <Card>
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Provenance
            </h2>
            <dl className="mt-3 space-y-2 text-xs">
              <div>
                <dt style={{ color: "var(--color-muted)" }}>Archive digest</dt>
                <dd className="break-all font-mono">{ver.archiveDigest ?? "—"}</dd>
              </div>
              {ver.commitSha && (
                <div>
                  <dt style={{ color: "var(--color-muted)" }}>Commit</dt>
                  <dd className="break-all font-mono">{ver.commitSha}</dd>
                </div>
              )}
              {report?.reportDigest && (
                <div>
                  <dt style={{ color: "var(--color-muted)" }}>Report digest</dt>
                  <dd className="break-all font-mono">{report.reportDigest}</dd>
                </div>
              )}
              <div>
                <dt style={{ color: "var(--color-muted)" }}>Attestation</dt>
                <dd>
                  {attestation ? (
                    <Badge tone="ok">signed (DSSE)</Badge>
                  ) : (
                    <Badge tone="neutral">not signed</Badge>
                  )}
                </dd>
              </div>
            </dl>
            <div className="mt-3">
              <CodeBlock>{`agentry verify ${ns}/${name}@${ver.version}`}</CodeBlock>
            </div>
          </Card>

          {manifest && (
            <Card>
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Manifest
              </h2>
              <pre
                className="mt-3 max-h-96 overflow-auto rounded border p-2 text-xs"
                style={{ borderColor: "var(--color-border)", background: "var(--color-bg)" }}
              >
                <code>{JSON.stringify(manifest, null, 2)}</code>
              </pre>
            </Card>
          )}
        </aside>
      </div>
    </div>
  );
}

import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { publicOrSessionReader } from "@/lib/session";
import { apiGet, type Agent, type AgentVersion, type ScanReport } from "@/lib/api";
import { Badge, CapabilityBadges, Card, CodeBlock, StatusBadge } from "@/components/ui";
import { FindingsList } from "@/components/report";

type Params = { ns: string; name: string; version: string };

// The DSSE envelope (§8.8) as far as this page reads it: the signature array
// carries the key id. Everything else is passed through untouched.
interface DsseEnvelope {
  signatures?: { keyid?: string; sig?: string }[];
}

interface VersionManifest {
  license?: string;
  tags?: string[];
  dependencies?: { agents?: { ref: string; version?: string }[] };
  [key: string]: unknown;
}

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { ns, name, version } = await params;
  return { title: `${ns}/${name}@${version}` };
}

// The version page (§10.1): the full security report, the manifest, and the
// provenance detail for one immutable release.
export default async function VersionPage({ params }: { params: Promise<Params> }) {
  const { ns, name, version } = await params;
  const n = encodeURIComponent(ns);
  const a = encodeURIComponent(name);
  const v = encodeURIComponent(version);
  const vbase = `/agents/${n}/${a}/versions/${v}`;

  // Public agents read anonymously (cached); a private one answers 401 and
  // is read through the session instead (agentry#186).
  const { read } = publicOrSessionReader();
  const [agent, ver] = await Promise.all([
    read<Agent>(`/agents/${n}/${a}`, { revalidate: 60 }),
    read<AgentVersion>(vbase, { revalidate: 60 }),
  ]);
  if (!agent || !ver) notFound();

  const [report, manifest, attestation] = await Promise.all([
    read<ScanReport>(`${vbase}/report`, { revalidate: 60 }).catch(() => null),
    read<VersionManifest>(`${vbase}/manifest`, { revalidate: 300 }).catch(() => null),
    read<DsseEnvelope>(`${vbase}/attestation`, { revalidate: 300 }).catch(() => null),
  ]);

  const counts = report?.findingCounts ?? {};
  const total = Object.values(counts).reduce((x, y) => x + y, 0);
  // The DSSE envelope names the key that signed this release (§8.8). Showing
  // it is what makes "signed" checkable: a reader can compare it against
  // /.well-known/agentry-signing-keys instead of taking the badge on trust.
  const keyID = attestation?.signatures?.find((s) => s.keyid)?.keyid;
  const deps = manifest?.dependencies?.agents ?? [];

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
                {total === 0 ? ": no findings" : `: ${total} finding${total === 1 ? "" : "s"}`}
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
                <dd className="break-all font-mono">{ver.archiveDigest ?? "none"}</dd>
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
              {attestation && (
                <div>
                  <dt style={{ color: "var(--color-muted)" }}>Signing key</dt>
                  <dd className="break-all font-mono">
                    {keyID ?? "the envelope names no key id"}
                  </dd>
                </div>
              )}
            </dl>
            <div className="mt-3">
              <CodeBlock>{`agentry verify ${agent.namespace}/${agent.name}@${ver.version}`}</CodeBlock>
            </div>
            {attestation && (
              <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
                Check the key id against the registry&apos;s published set at{" "}
                <code>/.well-known/agentry-signing-keys</code>. A signature proves who built this
                release, not that its contents are safe.
              </p>
            )}
          </Card>

          {deps.length > 0 && (
            <Card>
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Dependencies
              </h2>
              <ul className="mt-3 space-y-1 text-sm">
                {deps.map((d) => (
                  <li key={`${d.ref}@${d.version ?? "*"}`} className="flex flex-wrap items-baseline gap-2">
                    <Link href={`/${d.ref}`} className="font-mono hover:underline">
                      {d.ref}
                    </Link>
                    <span className="font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                      {d.version ?? "any version"}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
                Declared, not installed (v1). Each has its own report.
              </p>
            </Card>
          )}

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

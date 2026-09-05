// BrowsePane: the detail pane on /search for the selected result — the
// facts that decide whether to install, without leaving the list. It is a
// server component driven by the `selected` query parameter, so it works
// with no client JS, every state has a URL, and the row links are ordinary
// links (Next makes them soft navigations, so the list does not reload).
//
// It reads the same endpoints the agent page does and renders with the same
// components, so what it says here is exactly what the page will say.
import Link from "next/link";
import { apiGet, type Agent, type AgentStats, type AgentVersion, type ScanReport } from "@/lib/api";
import { fmtCount, fmtUTCDate } from "@/lib/format";
import { Badge, CapabilityBadges, Card, CodeBlock, ModeBadges, SeverityBadge, StatTile } from "./ui";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export async function BrowsePane({
  namespace,
  name,
  closeHref,
}: {
  namespace: string;
  name: string;
  closeHref: string;
}) {
  const n = encodeURIComponent(namespace);
  const a = encodeURIComponent(name);
  const base = `/agents/${n}/${a}`;
  const pageHref = `/${namespace}/${name}`;

  const agent = await apiGet<Agent>(base, { revalidate: 30 }).catch(() => null);
  if (!agent) {
    return (
      <Card tone="secondary">
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="font-mono font-medium">
            {namespace}/{name}
          </h2>
          <Link href={closeHref} className="text-sm underline" aria-label="Close details">
            Close
          </Link>
        </div>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          This BriefAgent is not available — it may be private, or the registry did not answer.
        </p>
      </Card>
    );
  }

  const [versions, stats] = await Promise.all([
    apiGet<AgentVersion[]>(`${base}/versions`, { revalidate: 30 }).catch(() => null),
    apiGet<AgentStats>(`${base}/stats`, { revalidate: 60 }).catch(() => null),
  ]);
  const latest = (versions ?? []).find((v) => v.status === "published");
  const lv = latest ? encodeURIComponent(latest.version) : null;
  const [report, manifest] = await Promise.all([
    lv ? apiGet<ScanReport>(`${base}/versions/${lv}/report`, { revalidate: 60 }).catch(() => null) : null,
    lv
      ? apiGet<{ license?: string }>(`${base}/versions/${lv}/manifest`, { revalidate: 300 }).catch(() => null)
      : null,
  ]);

  const counts = report?.findingCounts ?? {};
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  const total = Object.values(counts).reduce((x, y) => x + y, 0);
  const stripe = !report
    ? "var(--color-border)"
    : total === 0
      ? "var(--color-ok)"
      : present.includes("critical") || present.includes("high")
        ? "var(--color-sev-high)"
        : present.includes("medium")
          ? "var(--color-sev-medium)"
          : "var(--color-sev-info)";
  const hasUsage = !!stats && stats.stars + stats.installsTotal + stats.installs30d > 0;

  return (
    <Card className="browse-pane flex flex-col gap-4" style={{ borderLeft: `3px solid ${stripe}` }}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate font-mono text-base font-semibold" title={`${agent.namespace}/${agent.name}`}>
            <span style={{ color: "var(--color-muted)" }}>{agent.namespace}/</span>
            {agent.name}
          </h2>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <ModeBadges modes={agent.modes} />
            {latest ? <Badge>v{latest.version}</Badge> : <Badge tone="warn">no published version</Badge>}
            {agent.quarantineState !== "none" && <Badge tone="danger">{agent.quarantineState}</Badge>}
          </div>
        </div>
        <Link
          href={closeHref}
          className="shrink-0 rounded-md border px-2 py-0.5 text-xs"
          style={{ borderColor: "var(--color-border)", color: "var(--color-muted)" }}
          aria-label="Close details"
        >
          ✕
        </Link>
      </div>

      {agent.summary && <p className="text-sm">{agent.summary}</p>}

      {/* The two actions the pane exists for. */}
      <div className="flex flex-wrap gap-2">
        <Link
          href={pageHref}
          className="rounded-md px-3 py-1.5 text-sm font-medium"
          style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
        >
          Open BriefAgent →
        </Link>
        {latest && (
          <Link
            href={`${pageHref}/versions/${lv}`}
            className="rounded-md border px-3 py-1.5 text-sm font-medium"
            style={{ borderColor: "var(--color-accent)", color: "var(--color-accent)" }}
          >
            Security report
          </Link>
        )}
      </div>

      {latest && (
        <div>
          <div className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
            Install
          </div>
          <div className="mt-1">
            <CodeBlock wrap>{`agentry install ${agent.namespace}/${agent.name}@${latest.version}`}</CodeBlock>
          </div>
        </div>
      )}

      <div>
        <div className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
          Security report
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          {!report ? (
            <Badge>no scan on record</Badge>
          ) : total === 0 ? (
            <Badge tone="ok">scanned, 0 findings</Badge>
          ) : (
            present.map((s) => <SeverityBadge key={s} severity={s} count={counts[s]} />)
          )}
        </div>
        {report && (
          <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs" style={{ color: "var(--color-muted)" }}>
            <dt>Scanned</dt>
            <dd>{report.finishedAt ? fmtUTCDate(report.finishedAt) : "date not recorded"}</dd>
            {report.rulesetVersion && (
              <>
                <dt>Ruleset</dt>
                <dd>{report.rulesetVersion}</dd>
              </>
            )}
          </dl>
        )}
      </div>

      <div>
        <div className="text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
          Declared capabilities
        </div>
        <div className="mt-1.5 text-sm">
          <CapabilityBadges capabilities={latest?.capabilities} />
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs sm:grid-cols-3">
        {hasUsage && stats && (
          <>
            <StatTile label="Stars" value={fmtCount(stats.stars)} />
            <StatTile label="Installs" value={fmtCount(stats.installsTotal)} />
            <StatTile label="Last 30d" value={fmtCount(stats.installs30d)} />
          </>
        )}
        {manifest?.license && (
          <div>
            <dt className="text-xs uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              License
            </dt>
            <dd className="font-mono text-sm">{manifest.license}</dd>
          </div>
        )}
        {latest?.publishedAt && (
          <div>
            <dt className="text-xs uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Published
            </dt>
            <dd className="text-sm">{fmtUTCDate(latest.publishedAt)}</dd>
          </div>
        )}
        <div>
          <dt className="text-xs uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
            Releases
          </dt>
          <dd className="text-sm">{(versions ?? []).filter((v) => v.status === "published").length}</dd>
        </div>
      </dl>

      <p className="text-xs" style={{ color: "var(--color-muted)" }}>
        Scanning reduces risk; it does not prove a BriefAgent safe. Read the report before you install.
      </p>
    </Card>
  );
}

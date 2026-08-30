import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import {
  apiGet,
  apiGetText,
  type Advisory,
  type Agent,
  type AgentKind,
  type AgentStats,
  type AgentVersion,
  type Org,
  type ScanReport,
} from "@/lib/api";
import { fmtCount } from "@/lib/format";
import { authedGet, currentUser } from "@/lib/session";
import {
  Badge,
  CapabilityBadges,
  Card,
  CodeBlock,
  KindBadge,
  StatTile,
  StatusBadge,
} from "@/components/ui";
import { ReportCard } from "@/components/report";

type Params = { ns: string; name: string };

// §5.6 install targets. The default follows the agent kind, exactly as the
// CLI does (cmd/agentry/caps.go defaultTarget) — the page must not suggest a
// command that differs from what `agentry install` would do on its own.
const TARGETS = ["claude-skill", "mcp", "agents-md"] as const;
type Target = (typeof TARGETS)[number];

function defaultTarget(kind: AgentKind): Target {
  if (kind === "mcp-server") return "mcp";
  if (kind === "prompt-agent") return "agents-md";
  return "claude-skill";
}

interface AgentManifest {
  tags?: string[];
  license?: string;
  dependencies?: { agents?: { ref: string; version?: string }[] };
}

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { ns, name } = await params;
  const agent = await apiGet<Agent>(
    `/agents/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`,
  ).catch(() => null);
  if (!agent) return { title: `${ns}/${name}` };
  return {
    title: `${agent.namespace}/${agent.name}`,
    description: agent.summary || `A ${agent.kind} agent on SecureAgentry, scanned and signed.`,
  };
}

// The agent page (§10.2): identity, capability contract, security report
// card, and install snippet above the fold; sanitized README, dependencies,
// version history, stats and provenance below.
export default async function AgentPage({
  params,
  searchParams,
}: {
  params: Promise<Params>;
  searchParams: Promise<{ target?: string; ok?: string; error?: string }>;
}) {
  const { ns, name } = await params;
  const sp = await searchParams;
  const n = encodeURIComponent(ns);
  const a = encodeURIComponent(name);
  const base = `/agents/${n}/${a}`;

  const agent = await apiGet<Agent>(base, { revalidate: 30 });
  if (!agent) notFound();

  const [versions, readmeHtml, advisories, stats, org] = await Promise.all([
    apiGet<AgentVersion[]>(`${base}/versions`, { revalidate: 30 }).catch(() => null),
    apiGetText(`${base}/readme`, { revalidate: 60 }).catch(() => null),
    apiGet<Advisory[]>(`/advisories?affecting=${n}/${a}`, { revalidate: 60 }).catch(() => null),
    // Stats are public, but `starred` is per-caller, so this one goes through
    // the authed client (which forwards the session cookie when there is one).
    authedGet<AgentStats>(`${base}/stats`).catch(() => null),
    // The namespace may be a user, in which case there is no org row and the
    // 404 simply means "no verified-domain badge to show".
    apiGet<Org>(`/orgs/${n}`, { revalidate: 300 }).catch(() => null),
  ]);

  const published = (versions ?? []).filter((v) => v.status === "published");
  const latest = published[0];
  const lv = latest ? encodeURIComponent(latest.version) : null;

  const [report, manifest] = await Promise.all([
    lv ? apiGet<ScanReport>(`${base}/versions/${lv}/report`, { revalidate: 60 }).catch(() => null) : null,
    lv
      ? apiGet<AgentManifest>(`${base}/versions/${lv}/manifest`, { revalidate: 300 }).catch(() => null)
      : null,
  ]);

  // "Can this caller administer the agent?" is answered by the API, not
  // guessed here: autoPublishTags is serialized only for callers with
  // maintain (schemas/openapi.yaml, Agent).
  const user = await currentUser();
  const mine = user ? await authedGet<Agent>(base).catch(() => null) : null;
  const canMaintain = mine?.autoPublishTags !== undefined;

  const quarantined = agent.quarantineState !== "none";
  const target: Target = TARGETS.includes(sp.target as Target)
    ? (sp.target as Target)
    : defaultTarget(agent.kind);
  const isDefaultTarget = target === defaultTarget(agent.kind);
  const deps = manifest?.dependencies?.agents ?? [];
  const tags = manifest?.tags ?? [];

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
              ? "The registry refuses every download for this agent (410 Gone). Installed copies should be removed."
              : "It no longer resolves for installs while a reviewer investigates a finding. Copies you already installed are untouched — the registry cannot reach them."}
          </p>
        </div>
      )}

      {sp.ok && (
        <p
          role="status"
          className="rounded-md border px-3 py-2 text-sm"
          style={{ borderColor: "var(--color-ok)", color: "var(--color-ok)" }}
        >
          {sp.ok}
        </p>
      )}
      {sp.error && (
        <p
          role="alert"
          className="rounded-md border px-3 py-2 text-sm"
          style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}
        >
          {sp.error}
        </p>
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
          {org?.verifiedDomain && (
            <Badge
              tone="ok"
              title={`${org.handle} has proved control of ${org.verifiedDomain} by DNS. It says who publishes this agent — not that the agent is safe.`}
            >
              verified {org.verifiedDomain}
            </Badge>
          )}
          {canMaintain && (
            <Link href={`/${n}/${a}/settings`} className="text-sm underline" style={{ color: "var(--color-accent)" }}>
              settings
            </Link>
          )}
        </div>
        {agent.summary && <p className="max-w-3xl text-lg">{agent.summary}</p>}
        {tags.length > 0 && (
          <ul className="flex flex-wrap gap-2" aria-label="Tags">
            {tags.map((t) => (
              <li key={t}>
                <Link href={`/tags/${encodeURIComponent(t)}`} className="hover:underline">
                  <Badge tone="neutral">#{t}</Badge>
                </Link>
              </li>
            ))}
          </ul>
        )}
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
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Install
              </h2>
              {/* Static target selector: three links, no client JS. The
                  selected one is a plain span so the current state is not
                  also a link to itself. */}
              <nav className="flex gap-2 text-xs" aria-label="Install target">
                {TARGETS.map((t) =>
                  t === target ? (
                    <span key={t} className="rounded border px-2 py-0.5 font-medium" style={{ borderColor: "var(--color-accent)", color: "var(--color-accent)" }}>
                      {t}
                    </span>
                  ) : (
                    <Link
                      key={t}
                      href={`/${n}/${a}?target=${t}`}
                      className="rounded border px-2 py-0.5"
                      style={{ borderColor: "var(--color-border)", color: "var(--color-muted)" }}
                    >
                      {t}
                    </Link>
                  ),
                )}
              </nav>
            </div>
            <div className="mt-3 space-y-2">
              <CodeBlock>
                {`agentry install ${agent.namespace}/${agent.name}${latest ? `@${latest.version}` : ""}` +
                  (isDefaultTarget ? "" : ` --target=${target}`)}
              </CodeBlock>
              <CodeBlock>{`git clone ${agent.gitHttpUrl}`}</CodeBlock>
            </div>
            <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
              {isDefaultTarget
                ? `${target} is the default target for a ${agent.kind}, so the flag is not needed.`
                : `${target} is not the default for a ${agent.kind}; the flag is required.`}
            </p>
          </Card>

          {deps.length > 0 && (
            <Card>
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Depends on
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
                Declared in the manifest and informational in v1: nothing here is installed for you,
                and each dependency carries its own security report.
              </p>
            </Card>
          )}

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
          <ReportCard report={report} reportHref={lv ? `/${n}/${a}/versions/${lv}` : `/${n}/${a}`} />

          <Card>
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Usage
            </h2>
            {stats ? (
              <>
                <dl className="mt-3 grid grid-cols-3 gap-3">
                  <StatTile label="Stars" value={fmtCount(stats.stars)} />
                  <StatTile
                    label="Installs"
                    value={fmtCount(stats.installsTotal)}
                    hint="All recorded downloads through the registry."
                  />
                  <StatTile label="Last 30d" value={fmtCount(stats.installs30d)} />
                </dl>
                <form method="post" action={`/${n}/${a}/star`} className="mt-3">
                  <input type="hidden" name="starred" value={stats.starred ? "1" : "0"} />
                  <button
                    type="submit"
                    className="rounded-md border px-3 py-1.5 text-sm"
                    style={{
                      borderColor: stats.starred ? "var(--color-accent)" : "var(--color-border)",
                      color: stats.starred ? "var(--color-accent)" : "inherit",
                    }}
                  >
                    {stats.starred ? "★ Starred — remove" : "☆ Star this agent"}
                  </button>
                </form>
                <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
                  Popularity is not a safety signal. Read the report.
                </p>
              </>
            ) : (
              <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
                Counters are unavailable right now.
              </p>
            )}
          </Card>

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
                {manifest?.license && (
                  <div>
                    <dt style={{ color: "var(--color-muted)" }}>License</dt>
                    <dd className="font-mono">{manifest.license}</dd>
                  </div>
                )}
              </dl>
              <div className="mt-3">
                <CodeBlock>{`agentry verify ${agent.namespace}/${agent.name}@${latest.version}`}</CodeBlock>
              </div>
              <p className="mt-2 text-xs">
                <Link href={`/${n}/${a}/versions/${lv}`} className="underline">
                  Signing key and full report →
                </Link>
              </p>
            </Card>
          )}

          {advisories && advisories.length > 0 && (
            <Card>
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-sev-high)" }}>
                Advisories
              </h2>
              <ul className="mt-3 space-y-2 text-sm">
                {advisories.map((adv) => (
                  <li key={adv.id}>
                    <Badge tone="danger">{adv.severity}</Badge> <span>{adv.summary}</span>
                    <span className="block text-xs" style={{ color: "var(--color-muted)" }}>
                      affects {adv.affectedVersions}
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
                    <Link
                      href={`/${n}/${a}/versions/${encodeURIComponent(v.version)}`}
                      className="font-mono hover:underline"
                    >
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

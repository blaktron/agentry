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
import { fmtBytes, fmtCount, fmtUTCDate } from "@/lib/format";
import { embeddedAllowedTools, gatewayToolRows, parseContract } from "@/lib/mcp";
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
// CLI does (cmd/agentry/caps.go defaultTarget). The page must not suggest a
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

// Archive browsing types (schemas/openapi.yaml ReviewFileList/Content,
// served by listVersionFiles / getVersionFile under the download gate).
interface VersionFile {
  path: string;
  size: number;
}
interface VersionFileContent {
  path: string;
  size: number;
  binary: boolean;
  truncated: boolean;
  content?: string;
}

// dirEntries splits a flat archive inventory into the directories and files
// directly inside `dir` ("" is the archive root).
function dirEntries(files: VersionFile[], dir: string): { dirs: string[]; files: VersionFile[] } {
  const prefix = dir === "" ? "" : dir + "/";
  const dirs = new Set<string>();
  const here: VersionFile[] = [];
  for (const f of files) {
    if (!f.path.startsWith(prefix)) continue;
    const rest = f.path.slice(prefix.length);
    const slash = rest.indexOf("/");
    if (slash === -1) here.push(f);
    else dirs.add(rest.slice(0, slash));
  }
  return {
    dirs: [...dirs].sort((a, b) => a.localeCompare(b)),
    files: here.sort((a, b) => a.path.localeCompare(b.path)),
  };
}

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { ns, name } = await params;
  const agent = await apiGet<Agent>(
    `/agents/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`,
  ).catch(() => null);
  if (!agent) return { title: `${ns}/${name}` };
  return {
    title: `${agent.namespace}/${agent.name}`,
    description: agent.summary || `A ${agent.kind} BriefAgent on Agentry, scanned and signed.`,
  };
}

// The agent page (§10.2): identity, capability contract, security report
// card, and install snippet above the fold; below, a GitHub-style code view
// (file browser over the release archive, README under it) and a releases
// section, with dependencies, stats and provenance alongside.
export default async function AgentPage({
  params,
  searchParams,
}: {
  params: Promise<Params>;
  searchParams: Promise<{ target?: string; ok?: string; error?: string; path?: string }>;
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

  // MCP servers & tools (RUNNER-PLAN-2 §P6, req 3): the tool surface the
  // latest version's declared contract becomes — through the runner's
  // per-run gateway, and as host built-ins in an embedded install. Derived
  // entirely from the manifest; absent capabilities read as pure text.
  const contract = parseContract(latest?.capabilities);
  const toolRows = gatewayToolRows(contract);
  const hostTools = embeddedAllowedTools(contract);

  // File browser state. The browser shows the latest PUBLISHED version
  // (yanked and earlier versions keep their own pages). `path` selects a
  // directory (default root) or one file to display.
  const filesResp = lv
    ? await apiGet<{ files: VersionFile[] }>(`${base}/versions/${lv}/files`, { revalidate: 60 }).catch(() => null)
    : null;
  const inventory = filesResp?.files ?? null;
  const want = (sp.path ?? "").replace(/^\.\//, "").replace(/^\/+/, "");
  const wantIsFile = inventory !== null && inventory.some((f) => f.path === want);
  const wantIsDir = want === "" || (inventory !== null && inventory.some((f) => f.path.startsWith(want + "/")));
  const fileContent =
    lv && wantIsFile
      ? await apiGet<VersionFileContent>(
          `${base}/versions/${lv}/file?path=${encodeURIComponent(want)}`,
          { revalidate: 60 },
        ).catch(() => null)
      : null;
  const segments = want === "" ? [] : want.split("/");

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
              ? "This BriefAgent has been blocked by trust & safety."
              : "This BriefAgent is quarantined pending review."}
          </p>
          <p className="mt-1 text-sm">
            {agent.quarantineState === "blocked"
              ? "The registry refuses every download for this BriefAgent (410 Gone). Installed copies should be removed."
              : "It no longer resolves for installs while a reviewer investigates a finding. Copies you already installed are untouched. The registry cannot reach them."}
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
            {/* Underlined, not colour-only: Lighthouse link-in-text-block (agentry#42). */}
            <Link
              href={`/${agent.namespace}`}
              className="underline decoration-dotted underline-offset-4 hover:decoration-solid"
              style={{ color: "var(--color-muted)" }}
            >
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
              title={`${org.handle} has proved control of ${org.verifiedDomain} by DNS. It says who publishes this BriefAgent. It does not say the BriefAgent is safe.`}
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
              Capabilities are the author&apos;s declaration and the basis for policy and scanning.
              The registry cannot enforce them at run time. Your runtime should.
            </p>
          </Card>

          <Card>
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              MCP servers &amp; tools
            </h2>
            <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
              <code>agentry run</code> serves exactly the tools this contract declares, through a
              per-run MCP gateway. An undeclared capability is a tool that does not exist at run
              time.
            </p>

            <h3 className="mt-4 text-sm font-semibold">Tools the runner grants</h3>
            <div className="overflow-x-auto">
            <table className="mt-2 w-full text-sm">
              <thead>
                <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
                  <th className="py-1 pr-4 font-medium">Manifest declaration</th>
                  <th className="py-1 font-medium">Tool(s) granted</th>
                </tr>
              </thead>
              <tbody>
                {toolRows.map((r) => (
                  <tr
                    key={`${r.declaration} ${r.tools.join(" ")}`}
                    className="border-b align-top last:border-0"
                    style={{ borderColor: "var(--color-border)" }}
                  >
                    <td className="py-1.5 pr-4 font-mono text-xs">{r.declaration}</td>
                    <td className="py-1.5 text-xs">
                      <span className="font-mono">{r.tools.join(", ")}</span>
                      <span style={{ color: "var(--color-muted)" }}> — {r.note}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>

            <h3 className="mt-4 text-sm font-semibold">MCP servers involved</h3>
            <ul className="mt-2 space-y-1 text-sm">
              <li>
                <span className="font-medium">BriefAgent Tools</span>
                <span style={{ color: "var(--color-muted)" }}>
                  {" "}
                  — the runner&apos;s companion server, served through a per-run Docker MCP Gateway;
                  its tool surface is exactly the table above.
                </span>
              </li>
              {contract.dataAccess.length > 0 && (
                <li style={{ color: "var(--color-muted)" }}>
                  Operator-cataloged MCP servers may be attached for the declared dataAccess{" "}
                  {contract.dataAccess.length > 1 ? "categories" : "category"} (
                  <span className="font-mono text-xs">{contract.dataAccess.join(", ")}</span>);
                  undeclared categories are never wired in.
                </li>
              )}
            </ul>

            {contract.secrets.length > 0 && (
              <>
                <h3 className="mt-4 text-sm font-semibold">Keys &amp; identities</h3>
                <p className="mt-2 font-mono text-sm">{contract.secrets.join(", ")}</p>
                <p className="mt-1 text-xs" style={{ color: "var(--color-muted)" }}>
                  The runner&apos;s guided setup collects these once into the BriefAgent&apos;s MCP
                  profile, kept or removed per the operator&apos;s choice. Values are never
                  published or shown.
                </p>
              </>
            )}

            <h3 className="mt-4 text-sm font-semibold">In an embedded install</h3>
            <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
              Installed into an existing coding agent (<code>agentry install</code>), the same
              contract maps to the host&apos;s built-in tools — enforcement there is the
              host&apos;s. Allowed tools:{" "}
              {hostTools.length > 0 ? (
                <span className="font-mono text-xs">{hostTools.join(", ")}</span>
              ) : (
                <span>none declared (host defaults apply)</span>
              )}
              .
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

          {/* Code: file browser over the release archive of the latest
              published version, README underneath at the root. The archive
              is what was scanned and signed, so this is the exact content
              an install would receive. */}
          <section>
            <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Code
              </h2>
              {latest && (
                <Link
                  href={`/${n}/${a}/versions/${lv}`}
                  className="font-mono text-xs hover:underline"
                  style={{ color: "var(--color-accent)" }}
                >
                  {agent.namespace}/{agent.name}@v{latest.version}
                </Link>
              )}
            </div>
            <Card>
              {!latest && (
                <p className="text-sm" style={{ color: "var(--color-muted)" }}>
                  No published version to browse yet.
                </p>
              )}
              {latest && inventory === null && (
                <p className="text-sm" style={{ color: "var(--color-muted)" }}>
                  The file browser is unavailable right now. The install command above still works.
                </p>
              )}
              {latest && inventory !== null && wantIsFile && (
                <div>
                  <div className="flex flex-wrap items-baseline justify-between gap-2 border-b pb-2" style={{ borderColor: "var(--color-border)" }}>
                    <p className="font-mono text-sm">{want}</p>
                    <div className="flex items-center gap-3 text-xs" style={{ color: "var(--color-muted)" }}>
                      <span className="font-mono">{fmtBytes(fileContent?.size)}</span>
                      <Link href={`/${n}/${a}`} className="underline">
                        Back to files
                      </Link>
                    </div>
                  </div>
                  {fileContent === null ? (
                    <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
                      File content is unavailable right now.
                    </p>
                  ) : fileContent.binary ? (
                    <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
                      Binary file. The browser shows text files only; install or download the
                      archive to get this one.
                    </p>
                  ) : (
                    <>
                      <pre className="codeview mt-3 overflow-x-auto rounded-md border p-3 text-xs leading-relaxed" style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}>
                        {fileContent.content ?? ""}
                      </pre>
                      {fileContent.truncated && (
                        <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
                          Display is truncated at the viewer cap. The archive holds the full file.
                        </p>
                      )}
                    </>
                  )}
                </div>
              )}
              {latest && inventory !== null && !wantIsFile && !wantIsDir && (
                <p className="text-sm" style={{ color: "var(--color-muted)" }}>
                  Not found in this version.{" "}
                  <Link href={`/${n}/${a}`} className="underline">
                    Back to files
                  </Link>
                </p>
              )}
              {latest && inventory !== null && wantIsDir && !wantIsFile && (
                <>
                  {segments.length > 0 && (
                    <nav className="flex flex-wrap items-center gap-1 border-b pb-2 font-mono text-sm" aria-label="Path">
                      <Link href={`/${n}/${a}`} className="hover:underline" style={{ color: "var(--color-accent)" }}>
                        {agent.name}
                      </Link>
                      {segments.map((seg, i) => {
                        const prefix = segments.slice(0, i + 1).join("/");
                        const last = i === segments.length - 1;
                        return (
                          <span key={prefix} className="flex items-center gap-1">
                            <span style={{ color: "var(--color-muted)" }}>/</span>
                            {last ? (
                              <span>{seg}</span>
                            ) : (
                              <Link href={`/${n}/${a}?path=${encodeURIComponent(prefix)}`} className="hover:underline" style={{ color: "var(--color-accent)" }}>
                                {seg}
                              </Link>
                            )}
                          </span>
                        );
                      })}
                    </nav>
                  )}
                  <ul className={segments.length > 0 ? "mt-2" : ""}>
                    {segments.length > 0 && (
                      <li className="border-b py-2" style={{ borderColor: "var(--color-border)" }}>
                        <Link
                          href={segments.length > 1 ? `/${n}/${a}?path=${encodeURIComponent(segments.slice(0, -1).join("/"))}` : `/${n}/${a}`}
                          className="font-mono text-sm hover:underline"
                        >
                          ..
                        </Link>
                      </li>
                    )}
                    {dirEntries(inventory, want).dirs.map((d) => (
                      <li key={d} className="border-b py-2" style={{ borderColor: "var(--color-border)" }}>
                        <Link
                          href={`/${n}/${a}?path=${encodeURIComponent(want === "" ? d : want + "/" + d)}`}
                          className="font-mono text-sm hover:underline"
                        >
                          {d}/
                        </Link>
                      </li>
                    ))}
                    {dirEntries(inventory, want).files.map((f) => (
                      <li key={f.path} className="flex items-baseline justify-between gap-3 border-b py-2 last:border-0" style={{ borderColor: "var(--color-border)" }}>
                        <Link href={`/${n}/${a}?path=${encodeURIComponent(f.path)}`} className="font-mono text-sm hover:underline">
                          {f.path.slice(want === "" ? 0 : want.length + 1)}
                        </Link>
                        <span className="font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                          {fmtBytes(f.size)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {want === "" && readmeHtml && readmeHtml.trim() !== "" && (
                <div className="mt-4 border-t pt-4" style={{ borderColor: "var(--color-border)" }}>
                  <h3 className="mb-2 text-sm font-semibold" >
                    README.md
                  </h3>
                  {/* Server-sanitized HTML (§10.3): the API is the only renderer,
                      the browser never parses author markdown. */}
                  <div className="readme" dangerouslySetInnerHTML={{ __html: readmeHtml }} />
                </div>
              )}
            </Card>
          </section>
        </div>

        <aside className="space-y-6">
          <ReportCard report={report} reportHref={lv ? `/${n}/${a}/versions/${lv}` : `/${n}/${a}`} />

          <Card tone="secondary">
            <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
              Usage
            </h2>
            {stats ? (
              <>
                {/* A row of zeros is a ledger, not information: until any
                    counter moves, the card is just the star affordance. */}
                {stats.stars + stats.installsTotal + stats.installs30d > 0 ? (
                  <dl className="mt-3 grid grid-cols-3 gap-3">
                    <StatTile label="Stars" value={fmtCount(stats.stars)} />
                    <StatTile
                      label="Installs"
                      value={fmtCount(stats.installsTotal)}
                      hint="All recorded downloads through the registry."
                    />
                    <StatTile label="Last 30d" value={fmtCount(stats.installs30d)} />
                  </dl>
                ) : (
                  <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
                    No stars or installs recorded yet — be the first.
                  </p>
                )}
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
                    {stats.starred ? "★ Starred (remove)" : "☆ Star this BriefAgent"}
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
            <Card tone="secondary">
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Provenance
              </h2>
              <dl className="mt-3 space-y-2 text-xs">
                <div>
                  <dt style={{ color: "var(--color-muted)" }}>Archive digest</dt>
                  <dd className="break-all font-mono">{latest.archiveDigest ?? "none"}</dd>
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

          <Card tone="secondary">
            <div className="flex items-baseline justify-between gap-2">
              <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Releases
              </h2>
              <span className="font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                {(versions ?? []).length}
              </span>
            </div>
            {versions && versions.length > 0 ? (
              <ul className="mt-3 space-y-3 text-sm">
                {versions.slice(0, 12).map((v) => (
                  <li key={v.id}>
                    <div className="flex items-center justify-between gap-2">
                      <Link
                        href={`/${n}/${a}/versions/${encodeURIComponent(v.version)}`}
                        className="font-mono hover:underline"
                      >
                        v{v.version}
                      </Link>
                      <StatusBadge status={v.status} />
                    </div>
                    <p className="mt-0.5 text-xs" style={{ color: "var(--color-muted)" }}>
                      {fmtUTCDate(v.publishedAt ?? v.createdAt)}
                      {v.archiveDigest ? ` · ${v.archiveDigest.replace(/^sha256:/, "").slice(0, 12)}` : ""}
                    </p>
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

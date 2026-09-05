// Shared presentational components (§10). Server components by default —
// nothing here needs client-side JS, which keeps the CSP strict (§10.3).
import Link from "next/link";
import type { AgentMode, Severity, VersionStatus } from "@/lib/api";

// Two tiers of card. `primary` (the default) is a filled surface for the
// things a page is about — the report card, the install block. `secondary`
// is border-only on the page background for supporting panels, so the
// primary ones can actually be more important than "Usage".
export function Card({
  children,
  className = "",
  tone = "primary",
  style,
  ...rest
}: {
  children: React.ReactNode;
  className?: string;
  tone?: "primary" | "secondary";
  style?: React.CSSProperties;
} & Omit<React.HTMLAttributes<HTMLDivElement>, "className" | "style" | "children">) {
  return (
    <div
      {...rest}
      className={`rounded-md border p-4 ${className}`}
      style={{
        borderColor: "var(--color-border)",
        background: tone === "primary" ? "var(--color-surface)" : "transparent",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

export function Badge({
  children,
  tone = "neutral",
  title,
}: {
  children: React.ReactNode;
  tone?: "neutral" | "ok" | "warn" | "danger" | "accent";
  title?: string;
}) {
  const bg = {
    neutral: "var(--color-surface)",
    ok: "color-mix(in srgb, var(--color-ok) var(--badge-tint), transparent)",
    warn: "color-mix(in srgb, var(--color-sev-medium) var(--badge-tint), transparent)",
    danger: "color-mix(in srgb, var(--color-sev-high) var(--badge-tint), transparent)",
    accent: "color-mix(in srgb, var(--color-accent) var(--badge-tint), transparent)",
  }[tone];
  const fg = {
    neutral: "var(--color-muted)",
    ok: "var(--color-ok)",
    warn: "var(--color-sev-medium)",
    danger: "var(--color-sev-high)",
    accent: "var(--color-accent)",
  }[tone];
  return (
    <span
      title={title}
      className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-xs font-medium"
      style={{ background: bg, color: fg, borderColor: "var(--color-border)" }}
    >
      {children}
    </span>
  );
}

// SEVERITY_COLOR maps each level to its own token. Written out longhand
// rather than composed (`var(--color-sev-${severity})`) on purpose: Tailwind
// v4 keeps a theme variable only if its name appears literally in the
// scanned source, so an interpolated name would be tree-shaken out of the
// compiled CSS and every badge would fall back to unstyled.
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--color-sev-critical)",
  high: "var(--color-sev-high)",
  medium: "var(--color-sev-medium)",
  low: "var(--color-sev-low)",
  info: "var(--color-sev-info)",
};

// SeverityBadge renders one severity in its own colour. critical is not an
// alias for high: §8 gates on the distinction, so the UI must not collapse
// it — a report card showing "high" where the scanner said "critical" is a
// quieter page and a less honest one.
export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  const color = SEVERITY_COLOR[severity] ?? "var(--color-muted)";
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-xs font-medium"
      style={{
        background: `color-mix(in srgb, ${color} var(--badge-tint), transparent)`,
        color,
        borderColor: "var(--color-border)",
      }}
    >
      {severity}
      {count !== undefined ? ` ${count}` : ""}
    </span>
  );
}

export function StatusBadge({ status }: { status: VersionStatus }) {
  const tone =
    status === "published"
      ? "ok"
      : status === "rejected" || status === "blocked"
        ? "danger"
        : status === "needs_review" || status === "quarantined" || status === "yanked"
          ? "warn"
          : "neutral";
  return <Badge tone={tone}>{status.replace(/_/g, " ")}</Badge>;
}

// One badge per run mode the release supports (DEV-088).
export function ModeBadges({ modes }: { modes: AgentMode[] }) {
  return (
    <>
      {modes.map((m) => (
        <Badge key={m} tone="accent">
          {m}
        </Badge>
      ))}
    </>
  );
}

// RefusalCard is the shared rendering for an API 401/403 on an authed page.
// Authorization lives at the API chokepoint (§12.2); these pages render the
// refusal, they never decide it — so the copy says who may see the page and
// stops there.
export function RefusalCard({ children }: { children: React.ReactNode }) {
  return (
    <Card>
      <h1 className="mb-1 text-lg font-semibold">Not available to your account</h1>
      <p className="text-sm">{children}</p>
    </Card>
  );
}

// StatTile is one number in a stats panel (stars, installs).
export function StatTile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
        {label}
      </dt>
      <dd className="text-lg font-semibold" title={hint}>
        {value}
      </dd>
    </div>
  );
}

// CapabilityBadges renders the declared capability contract (§10.2 above the
// fold). Capabilities are declarations, not enforcement — the hover text says
// so, honestly (§1.6.3).
export function CapabilityBadges({ capabilities }: { capabilities?: Record<string, unknown> }) {
  if (!capabilities) return <span style={{ color: "var(--color-muted)" }}>none declared</span>;
  const caps = capabilities as {
    network?: { egress?: string[] };
    filesystem?: { read?: unknown; write?: unknown };
    exec?: unknown;
    secrets?: string[];
    dataAccess?: string[];
    mcpServers?: { npm?: string; pypi?: string; version?: string }[];
  };

  const items: { label: string; detail: string; tone: "neutral" | "warn" | "danger" }[] = [];

  const egress = caps.network?.egress ?? [];
  const realEgress = egress.filter((h) => h && h !== "none");
  if (realEgress.length > 0) {
    const wildcard = realEgress.includes("*");
    items.push({
      label: wildcard ? "network: any host" : `network: ${realEgress.length} host${realEgress.length > 1 ? "s" : ""}`,
      detail: realEgress.join(", "),
      tone: wildcard ? "danger" : "warn",
    });
  }
  const fsWrite = describeFS(caps.filesystem?.write);
  if (fsWrite) items.push({ label: `fs write: ${fsWrite}`, detail: fsWrite, tone: "warn" });
  const fsRead = describeFS(caps.filesystem?.read);
  if (fsRead) items.push({ label: `fs read: ${fsRead}`, detail: fsRead, tone: "neutral" });
  const exec = describeExec(caps.exec);
  if (exec) items.push({ label: `exec: ${exec}`, detail: exec, tone: "danger" });
  if (caps.secrets?.length) {
    items.push({ label: `secrets: ${caps.secrets.length}`, detail: caps.secrets.join(", "), tone: "warn" });
  }
  if (caps.dataAccess?.length) {
    items.push({ label: `data: ${caps.dataAccess.join(", ")}`, detail: caps.dataAccess.join(", "), tone: "neutral" });
  }
  if (caps.mcpServers?.length) {
    // Declared MCP servers (RUNNER-PLAN-3): version-pinned to this release,
    // installed with the agent from the operator's trusted registries.
    const detail = caps.mcpServers
      .map((s) => `${s.npm ? `npm:${s.npm}` : `pypi:${s.pypi}`}@${s.version ?? "?"}`)
      .join(", ");
    items.push({
      label: `mcp servers: ${caps.mcpServers.length}`,
      detail,
      tone: "warn",
    });
  }

  if (items.length === 0) {
    return <Badge tone="ok">pure text, no capabilities declared</Badge>;
  }
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((i) => (
        <Badge key={i.label} tone={i.tone} title={`${i.detail} (declared by the author, not enforced by the registry)`}>
          {i.label}
        </Badge>
      ))}
    </div>
  );
}

function describeFS(v: unknown): string | null {
  if (v === undefined || v === null || v === "none" || v === "") return null;
  if (typeof v === "string") return v;
  if (typeof v === "object" && v !== null && "paths" in v) {
    const paths = (v as { paths?: string[] }).paths ?? [];
    return paths.length ? paths.join(", ") : null;
  }
  return "declared";
}

function describeExec(v: unknown): string | null {
  if (v === undefined || v === null || v === "none" || v === "") return null;
  if (typeof v === "string") return v;
  if (typeof v === "object" && v !== null && "commands" in v) {
    const cmds = (v as { commands?: string[] }).commands ?? [];
    return cmds.length ? cmds.join(", ") : null;
  }
  return "declared";
}

// AgentRow is the search/listing row.
// AgentRow is the search/listing row. The identifier always links to the
// BriefAgent's own page. When `detailHref` is given (the browse page), the
// REST of the row — summary, badge, empty space — opens the detail pane
// instead: a cover link laid over the row, with the identifier link raised
// above it so the two never nest (nested anchors are invalid HTML and
// browsers split them unpredictably). Both are real links, both reachable
// by keyboard; `selected` marks the row the pane is showing.
export function AgentRow({
  namespace,
  name,
  summary,
  modes,
  detailHref,
  selected = false,
}: {
  namespace: string;
  name: string;
  summary: string;
  modes: AgentMode[];
  detailHref?: string;
  selected?: boolean;
}) {
  return (
    <li
      className={`agent-row border-b py-3 last:border-0 ${detailHref ? "relative" : ""}`}
      style={{ borderColor: "var(--color-border)" }}
      aria-current={selected ? "true" : undefined}
    >
      {detailHref && (
        <Link
          href={detailHref}
          className="agent-row-cover absolute inset-0 rounded-md"
          aria-label={`Show details for ${namespace}/${name}`}
        />
      )}
      <div className="flex items-baseline gap-3">
        <Link
          href={`/${namespace}/${name}`}
          className={`font-mono font-medium hover:underline ${detailHref ? "relative z-10" : ""}`}
        >
          {namespace}/{name}
        </Link>
        <ModeBadges modes={modes} />
      </div>
      {summary && (
        <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
          {summary}
        </p>
      )}
    </li>
  );
}

// CodeBlock shows a copyable command. Static (no client JS) — the browser's
// own selection is the copy affordance, keeping the CSP script-free.
// `wrap` lets a single long command fold inside a narrow container (the
// browse pane) instead of scrolling; multi-line blocks keep scrolling so
// their alignment survives.
export function CodeBlock({ children, wrap = false }: { children: string; wrap?: boolean }) {
  return (
    <pre
      className={`${wrap ? "whitespace-pre-wrap break-all" : "overflow-x-auto"} rounded-md border px-3 py-2 text-sm`}
      style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
    >
      <code>{children}</code>
    </pre>
  );
}

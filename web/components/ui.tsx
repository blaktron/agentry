// Shared presentational components (§10). Server components by default —
// nothing here needs client-side JS, which keeps the CSP strict (§10.3).
import Link from "next/link";
import type { AgentKind, Severity, VersionStatus } from "@/lib/api";

export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-lg border p-4 ${className}`}
      style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
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
    ok: "color-mix(in srgb, var(--color-ok) 15%, transparent)",
    warn: "color-mix(in srgb, var(--color-sev-medium) 18%, transparent)",
    danger: "color-mix(in srgb, var(--color-sev-high) 18%, transparent)",
    accent: "color-mix(in srgb, var(--color-accent) 15%, transparent)",
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
      className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium"
      style={{ background: bg, color: fg, borderColor: "var(--color-border)" }}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  const tone = severity === "critical" || severity === "high" ? "danger" : severity === "medium" ? "warn" : "neutral";
  return (
    <Badge tone={tone}>
      {severity}
      {count !== undefined ? ` ${count}` : ""}
    </Badge>
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

export function KindBadge({ kind }: { kind: AgentKind }) {
  return <Badge tone="accent">{kind}</Badge>;
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

  if (items.length === 0) {
    return <Badge tone="ok">pure text — no capabilities declared</Badge>;
  }
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((i) => (
        <Badge key={i.label} tone={i.tone} title={`${i.detail} — declared by the author, not enforced by the registry`}>
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
export function AgentRow({
  namespace,
  name,
  summary,
  kind,
}: {
  namespace: string;
  name: string;
  summary: string;
  kind: AgentKind;
}) {
  return (
    <li className="border-b py-3 last:border-0" style={{ borderColor: "var(--color-border)" }}>
      <div className="flex items-baseline gap-3">
        <Link href={`/${namespace}/${name}`} className="font-medium hover:underline">
          {namespace}/{name}
        </Link>
        <KindBadge kind={kind} />
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
export function CodeBlock({ children }: { children: string }) {
  return (
    <pre
      className="overflow-x-auto rounded-md border px-3 py-2 text-sm"
      style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
    >
      <code>{children}</code>
    </pre>
  );
}

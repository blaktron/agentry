// Server-side API access (§10: the web app talks to agentryd's REST API;
// public pages are SSR). The base URL is server-only — the browser never
// calls the API directly, so private data and auth stay on the server.
import "server-only";

const API_BASE = (process.env.AGENTRY_API_BASE ?? "http://localhost:8080").replace(/\/$/, "");

// apiGet fetches a public JSON endpoint. Returns null on 404 so callers can
// render notFound(); throws on other errors so the error boundary shows.
export async function apiGet<T>(path: string, opts?: { revalidate?: number }): Promise<T | null> {
  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    headers: { Accept: "application/json" },
    next: { revalidate: opts?.revalidate ?? 30 },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`API ${path} → ${res.status}`);
  }
  return (await res.json()) as T;
}

// apiGetWellKnown fetches a /.well-known document (signing keys, registry
// descriptor) — these live outside /api/v1.
export async function apiGetWellKnown<T>(path: string, opts?: { revalidate?: number }): Promise<T | null> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/json" },
    next: { revalidate: opts?.revalidate ?? 300 },
  });
  if (!res.ok) return null;
  return (await res.json()) as T;
}

// apiGetText fetches a text/HTML endpoint (the sanitized README, §10.3).
export async function apiGetText(path: string, opts?: { revalidate?: number }): Promise<string | null> {
  const res = await fetch(`${API_BASE}/api/v1${path}`, { next: { revalidate: opts?.revalidate ?? 60 } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
  return await res.text();
}

// --- Wire types (a hand-maintained subset of the generated schema, kept
// small so pages are typed without pulling the whole generated client into
// the server bundle). ---

export type AgentKind = "skill" | "prompt-agent" | "mcp-server";
export type VersionStatus =
  | "submitted" | "scanning" | "needs_review" | "approved"
  | "published" | "rejected" | "yanked" | "quarantined" | "blocked";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Agent {
  id: string;
  namespace: string;
  name: string;
  kind: AgentKind;
  visibility: "public" | "private";
  summary: string;
  defaultBranch: string;
  gitHttpUrl: string;
  quarantineState: "none" | "quarantined" | "blocked";
  createdAt: string;
}

export interface AgentVersion {
  id: string;
  version: string;
  status: VersionStatus;
  statusReason?: string;
  channel: "stable" | "beta";
  source: "git-tag" | "cli-upload";
  commitSha?: string;
  archiveDigest?: string;
  archiveSize?: number;
  capabilities?: Record<string, unknown>;
  createdAt: string;
  publishedAt?: string;
  yankedAt?: string;
  yankReason?: string;
}

export interface ScanFinding {
  id?: string;
  scanner: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  title: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  excerpt?: string;
  verdict: "open" | "confirmed" | "dismissed_false_positive" | "dismissed_accepted_risk";
}

export interface ScanReport {
  scanRunId?: string;
  versionStatus: VersionStatus;
  rulesetVersion?: string;
  reportDigest?: string;
  judgeModel?: string;
  scanStatus?: string;
  findingCounts?: Record<string, number>;
  findings: ScanFinding[];
}

export interface Meta {
  version: string;
  apiVersion: string;
  features: Record<string, boolean>;
}

export interface Advisory {
  id: string;
  affectedVersions: string;
  severity: string;
  summary: string;
  detail?: string;
  publishedAt?: string;
}

// SearchResult mirrors the /search endpoint (added with the render/search
// backend work; the page degrades gracefully if the endpoint is absent).
export interface SearchResult {
  results: Agent[];
  facets?: Record<string, Record<string, number>>;
  nextCursor?: string;
}

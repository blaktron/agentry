// Server-side API access (§10: the web app talks to agentryd's REST API;
// public pages are SSR). The base URL is server-only — the browser never
// calls the API directly, so private data and auth stay on the server.
import "server-only";
import type { components } from "./api/schema.d.ts";

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

// SOCIAL_PROVIDERS is the §12.1 individual-login provider list. Each entry's
// start endpoint lives on the API under /api/v1, i.e. same-origin with this
// app in every deployment that fronts both (deploy/helm ingress `apiPaths`).
// google and microsoft have built-in OIDC endpoints; openai and claude need
// an operator-set issuer (§12.1). A provider this deployment has not
// configured answers 404 on its start endpoint, so no button shows for it.
export const SOCIAL_PROVIDERS: { id: string; label: string }[] = [
  { id: "google", label: "Google" },
  { id: "github", label: "GitHub" },
  { id: "microsoft", label: "Microsoft" },
  { id: "openai", label: "OpenAI" },
  { id: "claude", label: "Claude" },
];

// enabledSocialProviders asks the API which social providers this deployment
// actually offers.
//
// There is no discovery document for this: /meta's feature flags cover
// judge/signing/redis/s3 only. The honest probe is the endpoint itself — an
// unconfigured provider answers 404 by design (DEV-019), a configured one
// redirects. Anything else (5xx, or a 429 from the shared login limiter) is
// read as "do not offer", so a broken provider shows no button rather than a
// dead one. Cached for an hour because /auth/oidc/{p}/start shares the
// per-IP login rate-limit bucket with the sign-in form, and this whole tier
// is a single IP to the API.
export async function enabledSocialProviders(): Promise<string[]> {
  const results = await Promise.all(
    SOCIAL_PROVIDERS.map(async (p) => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/auth/oidc/${p.id}/start`, {
          redirect: "manual",
          next: { revalidate: 3600 },
        });
        return res.status >= 300 && res.status < 400 ? p.id : null;
      } catch {
        return null;
      }
    }),
  );
  return results.filter((id): id is string => id !== null);
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
  // Serialized only for callers with maintain (§6.3 toggle) — so its mere
  // presence is the API's own answer to "may this caller administer the
  // agent?", which is why the pages test for it rather than re-deriving the
  // role from the session.
  autoPublishTags?: boolean;
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
  // Why a reviewer dismissed or confirmed this finding. §8.5: a dismissed
  // finding stays on the public report WITH its rationale — a finding that
  // vanishes without explanation is what the report exists to prevent.
  verdictReason?: string;
}

export interface ScanReport {
  scanRunId?: string;
  versionStatus: VersionStatus;
  rulesetVersion?: string;
  reportDigest?: string;
  judgeModel?: string;
  scanStatus?: string;
  // When this scan run completed — the date the report describes (§10.2).
  finishedAt?: string;
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

// --- Types taken straight from the generated OpenAPI schema. `import type`
// is erased at compile time, so this costs nothing at runtime and cannot
// drift from schemas/openapi.yaml the way the hand-written interfaces above
// can. New surfaces should be added here, not duplicated by hand. ---

export type SearchHit = components["schemas"]["SearchHit"];
export type SearchResults = components["schemas"]["SearchResults"];
export type TagPage = components["schemas"]["TagPage"];
export type AgentStats = components["schemas"]["AgentStats"];
export type ActivityEvent = components["schemas"]["ActivityEvent"];
export type ActivityPage = components["schemas"]["ActivityPage"];
export type AgentGrant = components["schemas"]["AgentGrant"];
export type AgentRole = components["schemas"]["AgentRole"];
export type AuditEvent = components["schemas"]["AuditEvent"];
export type AuditPage = components["schemas"]["AuditPage"];
export type Org = components["schemas"]["Org"];
export type WebhookDelivery = components["schemas"]["WebhookDelivery"];

// --- Review + console types (§10.1 reviewer / staff surfaces) ---

export interface ReviewItem {
  id: string;
  queue: "platform" | "org";
  state: "pending" | "approved" | "rejected";
  version: string;
  agent: string;
  namespace: string;
  createdAt?: string;
}

export interface ReviewBundle {
  item: ReviewItem;
  findings: ScanFinding[];
  versionDetail?: AgentVersion;
  previous?: AgentVersion;
  manifest?: Record<string, unknown>;
  report?: ScanReport;
}

export interface ReviewFileEntry {
  path: string;
  size: number;
}

export interface ReviewFileContent {
  path: string;
  size: number;
  binary: boolean;
  truncated: boolean;
  content?: string;
}

export interface AbuseReport {
  id: string;
  namespace: string;
  agent: string;
  version?: string;
  category: string;
  detail: string;
  state: "open" | "triaged" | "actioned" | "dismissed";
  createdAt: string;
}

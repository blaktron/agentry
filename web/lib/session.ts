// Authenticated server-side API access (§10 authed/reviewer/staff pages).
// The browser talks only to this web tier; the web tier forwards the user's
// session cookie to the API and echoes the CSRF token on mutations. Auth
// material stays in httpOnly cookies end to end — no token ever reaches
// client-side JavaScript.
import "server-only";
import { cookies } from "next/headers";

const API_BASE = (process.env.AGENTRY_API_BASE ?? "http://localhost:8080").replace(/\/$/, "");

export const SESSION_COOKIE = "agentry_session";
export const CSRF_COOKIE = "agentry_csrf";

export interface SessionUser {
  id: string;
  handle: string;
  email: string;
  displayName?: string;
  emailVerified: boolean;
  totpEnabled: boolean;
  cookieAckAt?: string;
  platformStaff?: boolean;
  orgs?: { handle: string; role: string }[];
}

// reviewerOrgs returns the orgs where the user can work the review queue
// (§12.2: security_reviewer and above).
export function reviewerOrgs(u: SessionUser): { handle: string; role: string }[] {
  return (u.orgs ?? []).filter((o) => ["owner", "admin", "security_reviewer"].includes(o.role));
}

// adminOrgs returns the orgs where the user can administer settings.
export function adminOrgs(u: SessionUser): { handle: string; role: string }[] {
  return (u.orgs ?? []).filter((o) => ["owner", "admin"].includes(o.role));
}

// currentUser resolves the signed-in user, or null. Cached per-request by
// React's fetch dedupe (same URL + cookie header within one render).
export async function currentUser(): Promise<SessionUser | null> {
  const jar = await cookies();
  const sess = jar.get(SESSION_COOKIE)?.value;
  if (!sess) return null;
  const res = await fetch(`${API_BASE}/api/v1/user`, {
    headers: { Accept: "application/json", Cookie: `${SESSION_COOKIE}=${sess}` },
    cache: "no-store",
  });
  if (!res.ok) return null;
  return (await res.json()) as SessionUser;
}

// authedGet fetches a JSON endpoint as the signed-in user. Returns null on
// 404. On 401/403 it throws AccessError so pages can distinguish "not yours"
// from "does not exist".
export class AccessError extends Error {
  status: number;
  constructor(status: number, path: string) {
    super(`API ${path} → ${status}`);
    this.status = status;
  }
}

export async function authedGet<T>(path: string): Promise<T | null> {
  const jar = await cookies();
  const sess = jar.get(SESSION_COOKIE)?.value;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (sess) headers.Cookie = `${SESSION_COOKIE}=${sess}`;
  const res = await fetch(`${API_BASE}/api/v1${path}`, { headers, cache: "no-store" });
  if (res.status === 404) return null;
  if (res.status === 401 || res.status === 403) throw new AccessError(res.status, path);
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
  return (await res.json()) as T;
}

// authedGetText is authedGet for text endpoints (the rendered README).
export async function authedGetText(path: string): Promise<string | null> {
  const jar = await cookies();
  const sess = jar.get(SESSION_COOKIE)?.value;
  const headers: Record<string, string> = {};
  if (sess) headers.Cookie = `${SESSION_COOKIE}=${sess}`;
  const res = await fetch(`${API_BASE}/api/v1${path}`, { headers, cache: "no-store" });
  if (res.status === 404) return null;
  if (res.status === 401 || res.status === 403) throw new AccessError(res.status, path);
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
  return await res.text();
}

// apiSend performs a cookie-authenticated mutation from a route handler,
// echoing the CSRF token the API issued at login (§9.1). Returns the raw
// Response; callers map status onto a redirect.
export async function apiSend(method: string, path: string, body?: unknown): Promise<Response> {
  const jar = await cookies();
  const sess = jar.get(SESSION_COOKIE)?.value;
  const csrf = jar.get(CSRF_COOKIE)?.value;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (sess) headers.Cookie = `${SESSION_COOKIE}=${sess}`;
  if (csrf) headers["X-Agentry-CSRF"] = csrf;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  return fetch(`${API_BASE}/api/v1${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
}

// apiUpload performs a cookie-authenticated multipart POST (the Builder's
// archive upload). No Content-Type header: fetch derives the multipart
// boundary from the FormData body.
export async function apiUpload(path: string, form: FormData): Promise<Response> {
  const jar = await cookies();
  const sess = jar.get(SESSION_COOKIE)?.value;
  const csrf = jar.get(CSRF_COOKIE)?.value;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (sess) headers.Cookie = `${SESSION_COOKIE}=${sess}`;
  if (csrf) headers["X-Agentry-CSRF"] = csrf;
  return fetch(`${API_BASE}/api/v1${path}`, {
    method: "POST",
    headers,
    body: form,
    cache: "no-store",
  });
}

// problemDetail extracts a human-readable message from a problem+json body.
export async function problemDetail(res: Response): Promise<string> {
  try {
    const p = (await res.json()) as { detail?: string; title?: string };
    return p.detail || p.title || `request failed (${res.status})`;
  } catch {
    return `request failed (${res.status})`;
  }
}

export { API_BASE };

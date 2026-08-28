// Helpers for the plain-HTML form → route-handler → redirect mutation
// pattern (§10). No client JS: every mutation is a real POST, so the pages
// work under the strict CSP and are testable with curl.
import "server-only";
import { NextRequest, NextResponse } from "next/server";

// sameOrigin rejects cross-site form posts (belt over the SameSite=Lax
// cookie braces; the API's CSRF token is the third layer).
export function sameOrigin(req: NextRequest): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return true; // non-browser clients (curl) carry the cookie or fail at the API
  try {
    return new URL(origin).host === req.nextUrl.host;
  } catch {
    return false;
  }
}

// safeNext validates an in-app redirect target from form input.
export function safeNext(v: unknown, fallback: string): string {
  if (typeof v !== "string" || !v.startsWith("/") || v.startsWith("//")) return fallback;
  return v;
}

// redirectBack sends a 303 to path with an optional flash message in the
// query string (?ok= / ?error= — rendered by the page, never echoed as HTML).
export function redirectBack(
  req: NextRequest,
  path: string,
  flash?: { ok?: string; error?: string },
): NextResponse {
  const url = new URL(path, req.nextUrl.origin);
  if (flash?.ok) url.searchParams.set("ok", flash.ok);
  if (flash?.error) url.searchParams.set("error", flash.error);
  return NextResponse.redirect(url, 303);
}

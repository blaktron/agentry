// Helpers for the plain-HTML form → route-handler → redirect mutation
// pattern (§10). No client JS: every mutation is a real POST, so the pages
// work under the strict CSP and are testable with curl.
import "server-only";
import { NextRequest, NextResponse } from "next/server";
import { CSRF_COOKIE, SESSION_COOKIE } from "./session";

// safeNext lives in lib/urls.ts so pages (and the unit tests) can use the
// same validation without pulling in `server-only`. Re-exported here because
// every route handler already imports from this module.
export { safeNext } from "./urls";

// readForm parses a form POST, degrading a malformed or bodyless request to
// an empty FormData instead of throwing. req.formData() rejects when the body
// is absent or not form-encoded; unhandled, that surfaced as a 500 on a
// hand-crafted empty POST. An empty FormData routes through each handler's
// own field validation, which answers 400/redirect-with-error — the right
// code for bad input. Real browser form submissions are unaffected.
export async function readForm(req: NextRequest): Promise<FormData> {
  try {
    return await req.formData();
  } catch {
    return new FormData();
  }
}

// sameOrigin rejects cross-site form posts (belt over the SameSite=Lax
// cookie braces; the API's CSRF token is the third layer).
//
// Compare against the Host header the browser actually addressed, not
// req.nextUrl.host: in a standalone deployment Next normalizes nextUrl to
// the server's own localhost:<port>, so a site served under any other
// hostname (LAN, Tailscale, a real domain) rejected every legitimate form
// post. The Host header is what the same-origin policy keyed the Origin
// header to in the first place. x-forwarded-host wins when a proxy fronts
// the app (it is set by the proxy, not the client).
export function sameOrigin(req: NextRequest): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return true; // non-browser clients (curl) carry the cookie or fail at the API
  const host =
    req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? req.nextUrl.host;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

// establishSession mirrors a successful API sign-in onto the browser.
//
// The API's Set-Cookie is not forwarded verbatim: mixing a raw Set-Cookie
// append with Next's cookies API drops one of the two. Instead both cookies
// are re-set through one mechanism, copying the attributes the API chose
// (lifetime, HttpOnly, SameSite=Lax, Secure per deployment). Returns false
// if the API answered 200 without actually issuing a session, which is a
// server bug the caller should surface rather than paper over.
export function establishSession(apiRes: Response, csrfToken: string, out: NextResponse): boolean {
  const setCookies = apiRes.headers.getSetCookie();
  const sessionCookie = setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  const sessionValue = sessionCookie?.split(";")[0]?.split("=").slice(1).join("=");
  if (!sessionCookie || !sessionValue || !csrfToken) return false;

  const maxAge = /Max-Age=(\d+)/i.exec(sessionCookie)?.[1];
  const attrs = {
    httpOnly: true,
    sameSite: "lax" as const,
    path: "/",
    secure: /;\s*Secure/i.test(sessionCookie),
    ...(maxAge ? { maxAge: Number(maxAge) } : {}),
  };
  out.cookies.set(SESSION_COOKIE, sessionValue, attrs);
  out.cookies.set(CSRF_COOKIE, csrfToken, attrs);
  return true;
}

// requestOrigin is the origin the BROWSER addressed, for building absolute
// redirect URLs. req.nextUrl.origin is the server's own notion — in a
// standalone deployment that is http://0.0.0.0:<port> or localhost, and a
// browser told to redirect there off-box goes nowhere. The Host header (or
// x-forwarded-host/-proto when a proxy fronts the app) is what the client
// can actually reach.
export function requestOrigin(req: NextRequest): string {
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  if (!host) return req.nextUrl.origin;
  const proto =
    req.headers.get("x-forwarded-proto") ?? req.nextUrl.protocol.replace(":", "");
  return `${proto}://${host}`;
}

// redirectBack sends a 303 to path with an optional flash message in the
// query string (?ok= / ?error= — rendered by the page, never echoed as HTML).
export function redirectBack(
  req: NextRequest,
  path: string,
  flash?: { ok?: string; error?: string },
): NextResponse {
  const url = new URL(path, requestOrigin(req));
  if (flash?.ok) url.searchParams.set("ok", flash.ok);
  if (flash?.error) url.searchParams.set("error", flash.error);
  return NextResponse.redirect(url, 303);
}

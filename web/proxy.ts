// Per-request CSP with a script nonce (§10.3, DEV-012 / DEV-022).
//
// The static `script-src 'self'` this replaced was not a working policy: it
// blocked Next's own inline bootstrap (`self.__next_f.push(...)`), so no page
// ever hydrated — the flight payload arrived empty, every route logged React
// error #412, and <Refresher/> (live publish progress) never mounted. The
// documented fix is a per-request nonce: Next reads the CSP off the *request*
// headers, extracts the nonce, and stamps it on every script tag it emits.
//
// The policy therefore has to be built here rather than in next.config.mjs —
// a value in `headers()` is static by construction and cannot carry a nonce.
// All the other security headers stay in next.config.mjs, where they apply
// to every response including the static asset paths this file skips.
//
// Named `proxy.ts` rather than `middleware.ts`: Next 16 renamed the
// convention and warns on every build for the old name (DEV-022).
import { NextResponse, type NextRequest } from "next/server";

// Everything except script-src, which is assembled per request. Unchanged
// from the original policy: `style-src 'unsafe-inline'` remains the §10.3
// compromise (Tailwind + inline style attributes; no inline SCRIPT, which is
// the XSS vector that matters).
// form-action governs where a form may be SUBMITTED, and browsers apply it
// to the redirect chain too: a same-origin POST /logout that answers with a
// 303 to the directory service's end-session URL is blocked by
// `form-action 'self'` and the Sign out button appears dead (agentry#81).
// The IdP origin is therefore allowed when one is configured (DEV-057).
const BASE_DIRECTIVES = [
  "default-src 'self'",
  // Styles (DEV-041 → agentry#46): the rendered pages carry NO inline
  // <style> elements — Tailwind ships as one linked stylesheet — but ~150
  // inline style="" attributes (theme tokens on server components). CSP3
  // splits the two: style-src-elem is strict, style-src-attr keeps
  // 'unsafe-inline' for the attributes, and the plain style-src stays as
  // the fallback for browsers without the split (they see what they saw
  // before). An injected <style> element is therefore blocked in every
  // current browser while nothing visible changes.
  "style-src 'self' 'unsafe-inline'",
  "style-src-elem 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  `form-action 'self'${formActionExtras()}`,
];

function formActionExtras(): string {
  const raw = process.env.AGENTRY_IDP_LOGOUT_URL;
  if (!raw) return "";
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:" && u.protocol !== "http:") return "";
    return ` ${u.origin}`;
  } catch {
    return "";
  }
}

function newNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export default function proxy(req: NextRequest) {
  const nonce = newNonce();
  const csp = [`script-src 'self' 'nonce-${nonce}'`, ...BASE_DIRECTIVES].join("; ");

  // Next's app renderer reads the nonce from the request header; the browser
  // gets it from the response header. Both must carry the same policy.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("content-security-policy", csp);
  requestHeaders.set("x-nonce", nonce);
  // The layout marks the current primary-nav item from this (aria-current),
  // which keeps the header a server component with no client JS.
  requestHeaders.set("x-pathname", req.nextUrl.pathname);

  const res = NextResponse.next({ request: { headers: requestHeaders } });
  res.headers.set("Content-Security-Policy", csp);
  return res;
}

export const config = {
  // Build output under /_next/static is content-addressed, immutable, and
  // never a document; running this per asset would only cost latency. Those
  // paths still receive the static headers from next.config.mjs.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};

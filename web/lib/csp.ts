// The Content-Security-Policy every HTML response carries. It lives here,
// away from proxy.ts, so the per-path parts can be unit-tested (vitest does
// not load the Next proxy). script-src is assembled per request around a
// fresh nonce; everything else is fixed except form-action.
//
// form-action governs where a form may be SUBMITTED, and Chrome applies it
// to the redirect chain too: a same-origin POST that answers with a 303 to
// another origin is refused and the button looks dead. That bit Sign out
// (agentry#81: the 303 to the directory service's end-session URL) and then
// the desktop app's browser sign-in (agentry#172: the approve route's 303
// to the app's loopback listener at http://127.0.0.1:<port>/callback). The
// IdP origin is allowed everywhere when one is configured (DEV-057); the
// loopback origin only on the desktop authorize pages, which are the only
// forms that legitimately hand the browser to a local process.

/** Pages whose forms may redirect to a loopback listener (DEV-058). */
export const DESKTOP_AUTHORIZE_PREFIX = "/settings/tokens/desktop";

/** Any port: the app binds 127.0.0.1:0 and tells the page which one. */
export const LOOPBACK_FORM_ACTION = "http://127.0.0.1:*";

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
];

/** The origin of the configured IdP logout URL, or null when none/invalid. */
export function idpFormActionOrigin(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    return u.origin;
  } catch {
    return null;
  }
}

/** The form-action sources for a page at `pathname`. */
export function formActionSources(pathname: string, idpLogoutUrl: string | undefined): string[] {
  const sources = ["'self'"];
  const idp = idpFormActionOrigin(idpLogoutUrl);
  if (idp) sources.push(idp);
  if (pathname === DESKTOP_AUTHORIZE_PREFIX || pathname.startsWith(DESKTOP_AUTHORIZE_PREFIX + "/")) {
    sources.push(LOOPBACK_FORM_ACTION);
  }
  return sources;
}

/** The complete policy for one response. */
export function buildCSP(nonce: string, pathname: string, idpLogoutUrl = process.env.AGENTRY_IDP_LOGOUT_URL): string {
  return [
    `script-src 'self' 'nonce-${nonce}'`,
    ...BASE_DIRECTIVES,
    `form-action ${formActionSources(pathname, idpLogoutUrl).join(" ")}`,
  ].join("; ");
}

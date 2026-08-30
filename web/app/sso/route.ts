// GET /sso?org=<handle> — the "sign in with your company account" entry
// point (§12.4).
//
// The landing itself is `GET /sso/{org}` on the API, mounted at the ROOT
// rather than under /api/v1 (DEV-019). That path is not in the deployed
// ingress' apiPaths list, so a browser hitting it on the web host would
// reach this app, not agentryd. Rather than depend on a routing change this
// workstream does not own, the handoff is done here: the web tier asks the
// API where the org's SSO starts and hands the browser the same answer.
//
// It is a hand-off, not a proxy of the login itself — the response body is
// never forwarded, only the redirect target and any cookies the landing
// chose to set, so the browser is what actually talks to the IdP (or to
// /api/v1/orgs/{org}/sso/oidc/start, which is same-origin and reachable).
import { NextRequest, NextResponse } from "next/server";
import { API_BASE } from "@/lib/session";
import { redirectBack, requestOrigin} from "@/lib/forms";

export async function GET(req: NextRequest) {
  const org = (req.nextUrl.searchParams.get("org") ?? "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{0,37}$/.test(org)) {
    return redirectBack(req, "/login", { error: "enter your organization's handle" });
  }

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/sso/${encodeURIComponent(org)}`, {
      redirect: "manual",
      cache: "no-store",
      headers: { Accept: "text/html" },
    });
  } catch {
    return redirectBack(req, "/login", { error: "the registry is not reachable right now" });
  }

  const location = res.headers.get("location");
  if (res.status < 300 || res.status >= 400 || !location) {
    // The API answers 404 for both "no such org" and "no enabled connection"
    // on purpose, so that the landing cannot enumerate which orgs have SSO.
    // Repeat that ambiguity rather than resolving it here.
    return redirectBack(req, "/login", {
      error: `no single sign-on is available for “${org}” — check the handle with your administrator`,
    });
  }

  const out = NextResponse.redirect(new URL(location, requestOrigin(req)), 303);
  // Forward anything the landing set (today: nothing; a future SAML relay
  // cookie would break silently otherwise).
  for (const c of res.headers.getSetCookie()) out.headers.append("set-cookie", c);
  return out;
}

// POST /logout — revoke the API session and clear both cookies.
import { NextRequest, NextResponse } from "next/server";
import { sameOrigin, requestOrigin} from "@/lib/forms";
import { apiSend, CSRF_COOKIE, SESSION_COOKIE } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) {
    return new NextResponse("cross-origin form post rejected", { status: 403 });
  }
  // Best-effort server-side revocation; cookies are cleared regardless.
  // A session established through an org's SAML connection answers 200
  // with the IdP's Single Logout URL (§12.4, agentry#62).
  let samlLogout: string | undefined;
  try {
    const res = await apiSend("POST", "/auth/logout");
    if (res.status === 200) {
      const body = (await res.json()) as { idpLogoutUrl?: string };
      if (body.idpLogoutUrl && /^https?:\/\//.test(body.idpLogoutUrl)) samlLogout = body.idpLogoutUrl;
    }
  } catch {
    /* cookies are cleared below regardless */
  }
  // DEV-057: when a directory service owns credentials, ending only the
  // app session would silently re-authenticate the next sign-in. Send the
  // browser through the IdP's end-session URL when one is configured.
  const idpLogout = samlLogout ?? process.env.AGENTRY_IDP_LOGOUT_URL;
  const out = NextResponse.redirect(idpLogout || new URL("/", requestOrigin(req)), 303);
  out.cookies.set(SESSION_COOKIE, "", { httpOnly: true, sameSite: "lax", path: "/", maxAge: 0 });
  out.cookies.set(CSRF_COOKIE, "", { httpOnly: true, sameSite: "lax", path: "/", maxAge: 0 });
  return out;
}

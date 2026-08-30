// POST /logout — revoke the API session and clear both cookies.
import { NextRequest, NextResponse } from "next/server";
import { sameOrigin, requestOrigin} from "@/lib/forms";
import { apiSend, CSRF_COOKIE, SESSION_COOKIE } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) {
    return new NextResponse("cross-origin form post rejected", { status: 403 });
  }
  // Best-effort server-side revocation; cookies are cleared regardless.
  await apiSend("POST", "/auth/logout").catch(() => undefined);
  const out = NextResponse.redirect(new URL("/", requestOrigin(req)), 303);
  out.cookies.set(SESSION_COOKIE, "", { httpOnly: true, sameSite: "lax", path: "/", maxAge: 0 });
  out.cookies.set(CSRF_COOKIE, "", { httpOnly: true, sameSite: "lax", path: "/", maxAge: 0 });
  return out;
}

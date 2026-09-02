// POST /cookies/ack — dismiss the cookie notice. A one-year cookie for this
// browser; signed-in users additionally get the acknowledgement recorded on
// their account (PATCH /user cookieAck), which is what keeps the banner
// dismissed on their other devices.
import { NextRequest, NextResponse } from "next/server";
import { COOKIE_ACK_COOKIE } from "@/components/cookie-banner";
import { readForm, requestOrigin, safeNext, sameOrigin } from "@/lib/forms";
import { apiSend, currentUser } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const next = safeNext(String(form.get("next") ?? ""), "/");

  if (await currentUser()) {
    // Best effort: the cookie below is the fallback if the API call fails.
    await apiSend("PATCH", "/user", { cookieAck: true }).catch(() => null);
  }

  // Redirect relative to the PUBLIC origin (x-forwarded-host/proto from the
  // edge), never req.url: behind the proxy that is the server's own bind
  // address (https://0.0.0.0:3000), which the browser cannot follow — the
  // OK button then appears to do nothing (agentry#80).
  const res = NextResponse.redirect(new URL(next, requestOrigin(req)), 303);
  res.cookies.set(COOKIE_ACK_COOKIE, "1", {
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.AGENTRY_COOKIE_SECURE !== "false",
  });
  return res;
}

// POST /settings/tokens/desktop/approve — record a one-time grant for the
// desktop app and hand its loopback listener the exchange CODE (DEV-058,
// hardened per agentry#19). No PAT is minted here: the app exchanges the
// code at POST /api/v1/auth/desktop/exchange from its own process, so the
// token never rides a URL or lands in browser history. The redirect target
// is pinned to 127.0.0.1 with a validated port: this route can hand a code
// to a process on the user's own machine and nowhere else.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

const PORT_MIN = 1024;
const PORT_MAX = 65535;
const STATE_RE = /^[A-Za-z0-9_-]{8,128}$/;

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const port = Number.parseInt(String(form.get("port") ?? ""), 10);
  const state = String(form.get("state") ?? "");
  if (!Number.isInteger(port) || port < PORT_MIN || port > PORT_MAX || !STATE_RE.test(state)) {
    return new NextResponse("invalid desktop callback parameters", { status: 400 });
  }

  // The scope set is fixed server-side (the desktop set; no review:act, no
  // org scopes) — see internal/api/handlers_desktop_grant.go.
  const res = await apiSend("POST", "/user/tokens/desktop-grant", { state });
  if (!res.ok) return redirectBack(req, "/settings/authentication", { error: await problemDetail(res) });
  const grant = (await res.json()) as { code: string };

  const cb = new URL(`http://127.0.0.1:${port}/callback`);
  cb.searchParams.set("state", state);
  cb.searchParams.set("code", grant.code);
  return NextResponse.redirect(cb, 303);
}

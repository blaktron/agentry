// POST /settings/tokens/desktop/approve — mint a PAT for the desktop app
// and deliver it to the app's loopback listener (DEV-058). The redirect
// target is pinned to 127.0.0.1 with a validated port: this route can hand
// a token to a process on the user's own machine and nowhere else.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

const PORT_MIN = 1024;
const PORT_MAX = 65535;
const STATE_RE = /^[A-Za-z0-9_-]{8,128}$/;

// The scope set the desktop app's surfaces use: browse/install (agent:read,
// repo:read), Build → publish (agent:publish, repo:write), identity
// (user:profile). Deliberately no review:act or org scopes.
const SCOPES = ["agent:read", "agent:publish", "repo:read", "repo:write", "user:profile"];

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const port = Number.parseInt(String(form.get("port") ?? ""), 10);
  const state = String(form.get("state") ?? "");
  if (!Number.isInteger(port) || port < PORT_MIN || port > PORT_MAX || !STATE_RE.test(state)) {
    return new NextResponse("invalid desktop callback parameters", { status: 400 });
  }

  const name = `Agentry Desktop (${new Date().toISOString().slice(0, 10)})`;
  const res = await apiSend("POST", "/user/tokens", { name, scopes: SCOPES });
  if (!res.ok) return redirectBack(req, "/settings", { error: await problemDetail(res) });
  const created = (await res.json()) as { token: string };

  const cb = new URL(`http://127.0.0.1:${port}/callback`);
  cb.searchParams.set("state", state);
  cb.searchParams.set("token", created.token);
  return NextResponse.redirect(cb, 303);
}

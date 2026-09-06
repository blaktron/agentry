// POST /settings/directory — directory-held account settings that Agentry
// manages on the user's behalf (agentry#164): today, removing one of the
// caller's enrolled authenticators. The API does the work through its
// directory admin access; the user never sees the directory's own panel.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const action = String(form.get("action") ?? "");
  if (action !== "remove-device") return redirectBack(req, "/settings/authentication", { error: "unknown action" });
  const kind = String(form.get("kind") ?? "").trim();
  const id = String(form.get("deviceId") ?? "").trim();
  if (!kind || !id) return redirectBack(req, "/settings/authentication", { error: "no authenticator selected" });
  const res = await apiSend("DELETE", `/user/directory/devices/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`);
  if (res.status === 404) return redirectBack(req, "/settings/authentication", { error: "that authenticator is no longer on your account" });
  if (!res.ok) return redirectBack(req, "/settings/authentication", { error: await problemDetail(res) });
  return redirectBack(req, "/settings/authentication", { ok: "authenticator removed." });
}

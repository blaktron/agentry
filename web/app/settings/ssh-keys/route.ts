// POST /settings/ssh-keys — add or remove an SSH public key (agentry#70).
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const action = String(form.get("action") ?? "add");

  if (action === "remove") {
    const id = String(form.get("keyId") ?? "");
    const res = await apiSend("DELETE", `/user/ssh-keys/${encodeURIComponent(id)}`);
    if (!res.ok) return redirectBack(req, "/settings/authentication", { error: await problemDetail(res) });
    return redirectBack(req, "/settings/authentication", { ok: "SSH key removed." });
  }

  const title = String(form.get("title") ?? "").trim();
  const publicKey = String(form.get("publicKey") ?? "").trim();
  if (!title) return redirectBack(req, "/settings/authentication", { error: "title required" });
  if (!publicKey) return redirectBack(req, "/settings/authentication", { error: "public key required" });
  const res = await apiSend("POST", "/user/ssh-keys", { title, publicKey });
  if (!res.ok) return redirectBack(req, "/settings/authentication", { error: await problemDetail(res) });
  return redirectBack(req, "/settings/authentication", { ok: `SSH key "${title}" added.` });
}

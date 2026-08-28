// POST /settings/tokens — create (shown once) or revoke a PAT.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";
import { showOnce } from "@/lib/show-once";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await req.formData();
  const action = String(form.get("action") ?? "create");

  if (action === "revoke") {
    const id = String(form.get("tokenId") ?? "");
    const res = await apiSend("DELETE", `/user/tokens/${encodeURIComponent(id)}`);
    if (!res.ok) return redirectBack(req, "/settings", { error: await problemDetail(res) });
    return redirectBack(req, "/settings", { ok: "token revoked." });
  }

  const name = String(form.get("name") ?? "").trim();
  const scopes = form.getAll("scopes").map(String);
  if (!name) return redirectBack(req, "/settings", { error: "token name required" });
  if (scopes.length === 0) return redirectBack(req, "/settings", { error: "pick at least one scope" });
  const res = await apiSend("POST", "/user/tokens", { name, scopes });
  if (!res.ok) return redirectBack(req, "/settings", { error: await problemDetail(res) });
  const created = (await res.json()) as { token: string };
  return showOnce({
    title: "Token created",
    lines: [
      [`Personal access token "${name}"`, created.token],
      ["Scopes", scopes.join(" ")],
    ],
    backHref: "/settings",
  });
}

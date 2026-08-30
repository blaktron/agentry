// POST /{ns}/{name}/settings/grants — set or remove a per-agent grant
// (§12.2). PUT is an upsert, so "add" and "change role" are the same call.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

const ROLES = new Set(["read", "write", "maintain", "publish"]);

export async function POST(req: NextRequest, ctx: { params: Promise<{ ns: string; name: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { ns, name } = await ctx.params;
  const n = encodeURIComponent(ns);
  const a = encodeURIComponent(name);
  const back = `/${n}/${a}/settings`;
  const form = await readForm(req);

  const kind = String(form.get("kind") ?? "");
  const grantee = String(form.get("grantee") ?? "").trim().toLowerCase();
  const action = String(form.get("action") ?? "set");
  if (kind !== "user" && kind !== "team") {
    return redirectBack(req, back, { error: "grant kind must be user or team" });
  }
  if (!/^[a-z0-9][a-z0-9-]*$/.test(grantee)) {
    return redirectBack(req, back, { error: "invalid handle or team slug" });
  }

  const path = `/agents/${n}/${a}/grants/${kind}/${encodeURIComponent(grantee)}`;
  let res: Response;
  if (action === "remove") {
    res = await apiSend("DELETE", path);
  } else {
    const role = String(form.get("role") ?? "read");
    if (!ROLES.has(role)) return redirectBack(req, back, { error: "unknown role" });
    res = await apiSend("PUT", path, { role });
  }
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, {
    ok: action === "remove" ? `${grantee}'s grant removed.` : `${grantee} updated.`,
  });
}

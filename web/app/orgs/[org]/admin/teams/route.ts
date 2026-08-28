// POST /orgs/{org}/admin/teams — create or delete a team.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { org } = await ctx.params;
  const back = `/orgs/${org}/admin`;
  const form = await req.formData();
  const slug = String(form.get("slug") ?? "").trim();
  const action = String(form.get("action") ?? "create");
  if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) return redirectBack(req, back, { error: "invalid team slug" });

  const res =
    action === "delete"
      ? await apiSend("DELETE", `/orgs/${org}/teams/${encodeURIComponent(slug)}`)
      : await apiSend("POST", `/orgs/${org}/teams`, { slug });
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, { ok: `team ${slug} ${action === "delete" ? "deleted" : "created"}.` });
}

// POST /orgs/{org}/admin/policy — save the org policy (tighten-only, §8.6).
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { org } = await ctx.params;
  const back = `/orgs/${org}/admin`;
  const form = await req.formData();
  let doc: unknown;
  try {
    doc = JSON.parse(String(form.get("policy") ?? ""));
  } catch {
    return redirectBack(req, back, { error: "policy must be valid JSON" });
  }
  const res = await apiSend("PUT", `/orgs/${org}/policy`, doc);
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, { ok: "policy saved." });
}

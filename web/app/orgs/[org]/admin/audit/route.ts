// POST /orgs/{org}/admin/audit — start an async audit export (§12.6).
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { org } = await ctx.params;
  const back = `/orgs/${org}/admin`;
  const res = await apiSend("POST", `/orgs/${org}/audit/exports`, {});
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  const created = (await res.json()) as { id: string };
  return redirectBack(req, `${back}?export=${created.id}`, {
    ok: "export started — this panel shows its status.",
  });
}

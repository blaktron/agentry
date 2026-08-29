// POST /review/{id}/decide — forward an approve/reject decision to the API.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { id } = await ctx.params;
  const i = encodeURIComponent(id);
  const form = await req.formData();
  const decision = String(form.get("decision") ?? "");
  const rationale = String(form.get("rationale") ?? "");
  if (decision !== "approve" && decision !== "reject") {
    return redirectBack(req, `/review/${i}`, { error: "decision must be approve or reject" });
  }
  const res = await apiSend("POST", `/review-items/${i}/decision`, { decision, rationale });
  if (!res.ok) {
    return redirectBack(req, `/review/${i}`, { error: await problemDetail(res) });
  }
  return redirectBack(req, `/review/${i}`, {
    ok: decision === "approve" ? "Approved — the version is publishing and signing now." : "Rejected.",
  });
}

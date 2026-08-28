// POST /review/{id}/finding/{fid}/verdict — record a finding verdict (§8.5).
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

const VERDICTS = new Set(["confirmed", "dismissed_false_positive", "dismissed_accepted_risk"]);

export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string; fid: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { id, fid } = await ctx.params;
  const form = await req.formData();
  const verdict = String(form.get("verdict") ?? "");
  const reason = String(form.get("reason") ?? "");
  if (!VERDICTS.has(verdict)) {
    return redirectBack(req, `/review/${id}`, { error: "unknown verdict" });
  }
  const res = await apiSend("POST", `/findings/${fid}/verdict`, { verdict, reason });
  if (!res.ok) {
    return redirectBack(req, `/review/${id}`, { error: await problemDetail(res) });
  }
  return redirectBack(req, `/review/${id}`, { ok: `Finding marked ${verdict.replace(/_/g, " ")}.` });
}

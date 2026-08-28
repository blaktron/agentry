// POST /staff/abuse/{id}/triage — record an abuse-report triage outcome.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

const STATES = new Set(["triaged", "actioned", "dismissed"]);

export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { id } = await ctx.params;
  const form = await req.formData();
  const state = String(form.get("state") ?? "");
  const resolution = String(form.get("resolution") ?? "");
  if (!STATES.has(state)) {
    return redirectBack(req, "/staff", { error: "unknown triage state" });
  }
  const res = await apiSend("POST", `/platform/abuse-reports/${id}`, { state, resolution });
  if (!res.ok) {
    return redirectBack(req, "/staff", { error: await problemDetail(res) });
  }
  return redirectBack(req, "/staff", { ok: `Report marked ${state}.` });
}

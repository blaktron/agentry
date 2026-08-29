// POST /{ns}/{name}/star — star or unstar an agent (§9.2).
//
// A plain form, like every other mutation here: PUT/DELETE /user/stars/…
// are both idempotent 204s, so a double-submit is harmless and the page can
// simply re-render with the new count.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ ns: string; name: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { ns, name } = await ctx.params;
  const n = encodeURIComponent(ns);
  const a = encodeURIComponent(name);
  const back = `/${n}/${a}`;
  const form = await req.formData();
  const starred = String(form.get("starred") ?? "") === "1";

  const res = await apiSend(starred ? "DELETE" : "PUT", `/user/stars/${n}/${a}`);
  if (res.status === 401) {
    return NextResponse.redirect(
      new URL(`/login?next=${encodeURIComponent(back)}`, req.nextUrl.origin),
      303,
    );
  }
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, { ok: starred ? "Star removed." : "Starred." });
}

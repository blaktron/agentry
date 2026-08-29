// POST /{ns}/{name}/settings/delete — delete an agent that was never
// published (§9.2).
//
// The API refuses (409) as soon as any version row exists, and that refusal
// is the interesting case: it is not a transient error but a rule (§4.3
// forbids deleting version rows at all), so it is surfaced as its own
// message rather than as a raw problem detail.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ ns: string; name: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { ns, name } = await ctx.params;
  const n = encodeURIComponent(ns);
  const a = encodeURIComponent(name);
  const back = `/${n}/${a}/settings`;
  const form = await req.formData();

  if (String(form.get("confirm") ?? "").trim() !== name) {
    return redirectBack(req, back, { error: `type "${name}" exactly to confirm deletion` });
  }

  const res = await apiSend("DELETE", `/agents/${n}/${a}`);
  if (res.status === 409) {
    const detail = await problemDetail(res);
    return redirectBack(req, back, {
      error: `${detail} — published or in-flight versions, advisories and abuse reports are records that outlive the agent, so it can be yanked or blocked but not deleted.`,
    });
  }
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, "/dashboard", { ok: `${ns}/${name} deleted, along with its repository.` });
}

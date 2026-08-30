// POST /{ns}/{name}/settings/delete — delete an agent that was never
// published (§9.2).
//
// The API refuses (409) as soon as any version row exists, and that refusal
// is the interesting case: it is not a transient error but a rule (§4.3
// forbids deleting version rows at all), so it is surfaced as its own
// message rather than as a raw problem detail.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ ns: string; name: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { ns, name } = await ctx.params;
  const n = encodeURIComponent(ns);
  const a = encodeURIComponent(name);
  const back = `/${n}/${a}/settings`;
  const form = await readForm(req);

  if (String(form.get("confirm") ?? "").trim() !== name) {
    return redirectBack(req, back, { error: `type "${name}" exactly to confirm deletion` });
  }

  // A 409 here is not a transient failure but the rule itself (§4.3 forbids
  // deleting version rows), and the API's problem detail already states it
  // and names the alternative. Passing it through unembellished is the
  // honest rendering; the page has already said the same thing next to the
  // form, which is where the explanation belongs.
  const res = await apiSend("DELETE", `/agents/${n}/${a}`);
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, "/dashboard", { ok: `${ns}/${name} deleted, along with its repository.` });
}

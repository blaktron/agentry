// POST /{ns}/{name}/publish/submit — submit a git tag to the pipeline.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ ns: string; name: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { ns, name } = await ctx.params;
  const back = `/${ns}/${name}/publish`;
  const form = await req.formData();
  const tag = String(form.get("tag") ?? "").trim();
  if (!/^v.+/.test(tag)) return redirectBack(req, back, { error: "tag must look like v1.2.3" });

  const res = await apiSend("POST", `/agents/${ns}/${name}/versions`, { tag });
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  const v = (await res.json()) as { version: string };
  return redirectBack(req, `/${ns}/${name}/versions/${encodeURIComponent(v.version)}/progress`, {
    ok: `tag ${tag} submitted — watching the pipeline.`,
  });
}

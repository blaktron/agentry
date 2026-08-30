// POST /{ns}/{name}/settings/save — PATCH the agent's settings (§9.2).
//
// Two form shapes land here: the summary/visibility form and the
// auto-publish toggle. They are one endpoint because they are one API call;
// the `action` field says which fields to send, so a toggle never silently
// resubmits a stale summary.
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
  const action = String(form.get("action") ?? "profile");

  let body: Record<string, unknown>;
  let ok: string;
  if (action === "autopublish") {
    const enable = String(form.get("autoPublishTags") ?? "") === "true";
    body = { autoPublishTags: enable };
    ok = enable
      ? "publish on tag push enabled — pushed v* tags now enter the pipeline."
      : "publish on tag push disabled.";
  } else {
    const visibility = String(form.get("visibility") ?? "");
    if (visibility !== "public" && visibility !== "private") {
      return redirectBack(req, back, { error: "visibility must be public or private" });
    }
    body = { summary: String(form.get("summary") ?? "").trim(), visibility };
    ok = "settings saved.";
  }

  const res = await apiSend("PATCH", `/agents/${n}/${a}`, body);
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, { ok });
}

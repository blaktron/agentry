// POST /new/create — create the agent and land on its publish page.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const namespace = String(form.get("namespace") ?? "");
  const name = String(form.get("name") ?? "").trim();
  const kind = String(form.get("kind") ?? "skill");
  const visibility = String(form.get("visibility") ?? "public");
  const summary = String(form.get("summary") ?? "").trim();
  if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) return redirectBack(req, "/new", { error: "invalid agent name" });

  const res = await apiSend("POST", "/agents", { namespace, name, kind, visibility, summary });
  if (!res.ok) return redirectBack(req, "/new", { error: await problemDetail(res) });
  return redirectBack(req, `/${namespace}/${name}/publish`, {
    ok: "agent created — push content to its repo, then submit a tag here.",
  });
}

// POST /new/create — create the agent and land on its publish page.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const namespace = String(form.get("namespace") ?? "");
  const name = String(form.get("name") ?? "").trim();
  // Run modes (DEV-088): checkboxes named "modes"; autonomous when none is ticked.
  const modes = form.getAll("modes").map(String).filter((m) => m === "autonomous" || m === "interactive");
  if (modes.length === 0) modes.push("autonomous");
  const visibility = String(form.get("visibility") ?? "public");
  const summary = String(form.get("summary") ?? "").trim();
  if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) return redirectBack(req, "/new", { error: "invalid agent name" });

  const res = await apiSend("POST", "/agents", { namespace, name, modes, visibility, summary });
  if (!res.ok) return redirectBack(req, "/new", { error: await problemDetail(res) });
  return redirectBack(req, `/${namespace}/${name}/publish`, {
    ok: "agent created. Push content to its repo, then submit a tag here.",
  });
}

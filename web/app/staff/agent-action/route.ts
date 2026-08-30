// POST /staff/agent-action — quarantine / block / reinstate an agent (§7).
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

const ACTIONS = new Set(["quarantine", "block", "reinstate"]);

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const ref = String(form.get("ref") ?? "");
  const action = String(form.get("action") ?? "");
  const reason = String(form.get("reason") ?? "");
  const m = /^([^/\s]+)\/([^/\s]+)$/.exec(ref.trim());
  if (!m) return redirectBack(req, "/staff", { error: "agent must be namespace/name" });
  if (!ACTIONS.has(action)) return redirectBack(req, "/staff", { error: "unknown action" });
  const res = await apiSend(
    "POST",
    `/platform/agents/${encodeURIComponent(m[1])}/${encodeURIComponent(m[2])}/${action}`,
    { reason },
  );
  if (!res.ok) {
    return redirectBack(req, "/staff", { error: await problemDetail(res) });
  }
  return redirectBack(req, "/staff", { ok: `${ref}: ${action} recorded.` });
}

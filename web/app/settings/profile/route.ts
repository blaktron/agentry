// POST /settings/profile — update the display name.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const displayName = String(form.get("displayName") ?? "").trim();
  const res = await apiSend("PATCH", "/user", { displayName });
  if (!res.ok) return redirectBack(req, "/settings", { error: await problemDetail(res) });
  return redirectBack(req, "/settings", { ok: "profile saved." });
}

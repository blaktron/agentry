// POST /orgs/{org}/admin/members — set a member's role or remove them.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { org } = await ctx.params;
  // Every interpolated API path segment is escaped: `org` is route
  // input, and a handle-shaped value is a convention, not a guarantee.
  const o = encodeURIComponent(org);
  const back = `/orgs/${o}/admin`;
  const form = await req.formData();
  const handle = String(form.get("handle") ?? "").trim();
  const action = String(form.get("action") ?? "");
  if (!/^[a-z0-9][a-z0-9-]*$/i.test(handle)) return redirectBack(req, back, { error: "invalid handle" });

  let res: Response;
  if (action === "remove") {
    res = await apiSend("DELETE", `/orgs/${o}/members/${encodeURIComponent(handle)}`);
  } else {
    const role = String(form.get("role") ?? "member");
    res = await apiSend("PUT", `/orgs/${o}/members/${encodeURIComponent(handle)}`, { role });
  }
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, { ok: action === "remove" ? `${handle} removed.` : `${handle} updated.` });
}

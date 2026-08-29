// POST /orgs/{org}/admin/scim — create (shown once) or revoke a SCIM token.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";
import { showOnce } from "@/lib/show-once";

export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { org } = await ctx.params;
  // Every interpolated API path segment is escaped: `org` is route
  // input, and a handle-shaped value is a convention, not a guarantee.
  const o = encodeURIComponent(org);
  const back = `/orgs/${o}/admin`;
  const form = await req.formData();
  const action = String(form.get("action") ?? "create");

  if (action === "revoke") {
    const id = String(form.get("tokenId") ?? "");
    const res = await apiSend("DELETE", `/orgs/${o}/scim/tokens/${encodeURIComponent(id)}`);
    if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
    return redirectBack(req, back, { ok: "SCIM token revoked — provisioned access stops immediately." });
  }

  const res = await apiSend("POST", `/orgs/${o}/scim/tokens`, {});
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  const created = (await res.json()) as { token: string };
  return showOnce({
    title: "SCIM token created",
    lines: [
      ["Bearer token for your IdP's SCIM provisioning", created.token],
      ["SCIM base URL", "/scim/v2"],
    ],
    backHref: back,
  });
}

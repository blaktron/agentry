// POST /orgs/{org}/admin/domains — claim a domain or trigger verification.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const { org } = await ctx.params;
  // Every interpolated API path segment is escaped: `org` is route
  // input, and a handle-shaped value is a convention, not a guarantee.
  const o = encodeURIComponent(org);
  const back = `/orgs/${o}/admin`;
  const form = await readForm(req);
  const domain = String(form.get("domain") ?? "").trim().toLowerCase();
  const action = String(form.get("action") ?? "claim");
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return redirectBack(req, back, { error: "invalid domain" });

  const res =
    action === "verify"
      ? await apiSend("POST", `/orgs/${o}/domain-claims/verify`, { domain })
      : await apiSend("POST", `/orgs/${o}/domain-claims`, { domain });
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, {
    ok: action === "verify" ? `${domain} verified.` : `${domain} claimed — publish the TXT record shown below it.`,
  });
}

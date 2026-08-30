// POST /orgs/{org}/admin/sso — configure or delete an SSO connection.
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
  const kind = String(form.get("kind") ?? "");
  const action = String(form.get("action") ?? "put");
  if (kind !== "saml" && kind !== "oidc") return redirectBack(req, back, { error: "unknown SSO kind" });

  if (action === "delete") {
    const res = await apiSend("DELETE", `/orgs/${o}/sso/connections/${kind}`);
    if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
    return redirectBack(req, back, { ok: `${kind} connection deleted.` });
  }

  const enabled = form.get("enabled") === "true";
  const config: Record<string, string> = {};
  if (kind === "saml") {
    config.idpMetadataXml = String(form.get("idpMetadataXml") ?? "");
  } else {
    config.issuer = String(form.get("issuer") ?? "");
    config.clientId = String(form.get("clientId") ?? "");
    const secret = String(form.get("clientSecret") ?? "");
    if (secret) config.clientSecret = secret;
  }
  const res = await apiSend("PUT", `/orgs/${o}/sso/connections/${kind}`, { enabled, config });
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  return redirectBack(req, back, { ok: `${kind} connection saved.` });
}

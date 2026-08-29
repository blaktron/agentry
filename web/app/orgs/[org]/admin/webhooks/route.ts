// POST /orgs/{org}/admin/webhooks — create or delete a webhook endpoint.
// Creation returns the HMAC secret exactly once: rendered as a page, never
// put in a URL.
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

  if (action === "delete") {
    const id = String(form.get("id") ?? "");
    const res = await apiSend("DELETE", `/orgs/${o}/webhooks/${encodeURIComponent(id)}`);
    if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
    return redirectBack(req, back, { ok: "webhook deleted." });
  }

  // A test delivery is enqueued, not sent inline (202), so the useful landing
  // is the delivery list for that endpoint rather than a claim of success.
  if (action === "ping") {
    const id = String(form.get("id") ?? "");
    const res = await apiSend("POST", `/orgs/${o}/webhooks/${encodeURIComponent(id)}/ping`);
    if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
    return redirectBack(req, `${back}?deliveries=${encodeURIComponent(id)}`, {
      ok: "test delivery enqueued — its attempt appears in the delivery list below.",
    });
  }

  const url = String(form.get("url") ?? "");
  const events = form.getAll("events").map(String);
  if (events.length === 0) return redirectBack(req, back, { error: "pick at least one event" });
  const res = await apiSend("POST", `/orgs/${o}/webhooks`, { url, events });
  if (!res.ok) return redirectBack(req, back, { error: await problemDetail(res) });
  const created = (await res.json()) as { id: string; secret?: string };
  return showOnce({
    title: "Webhook created",
    lines: [
      ["Endpoint", url],
      ["Signing secret (shown once — deliveries carry X-Agentry-Signature)", created.secret ?? "(not returned)"],
    ],
    backHref: back,
  });
}

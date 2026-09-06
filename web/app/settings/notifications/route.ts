// POST /settings/notifications — replace the caller's notification settings
// (agentry#190). Checkboxes: a box that is unchecked is absent from the form,
// which is the "off" the API expects; the API takes the whole set every time.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const on = (name: string) => form.get(name) === "on";
  const res = await apiSend("PUT", "/user/notifications", {
    email: {
      dependencyAlerts: on("email.dependencyAlerts"),
      quarantine: on("email.quarantine"),
      reviewDecisions: on("email.reviewDecisions"),
      advisories: on("email.advisories"),
      orgInvites: on("email.orgInvites"),
    },
    web: { dependencyAlerts: on("web.dependencyAlerts") },
  });
  if (!res.ok) return redirectBack(req, "/settings", { error: await problemDetail(res) });
  return redirectBack(req, "/settings", { ok: "notification settings saved." });
}

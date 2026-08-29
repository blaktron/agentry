// POST /settings/sessions — revoke one session, or every other session.
//
// Written against the contract agreed with the API workstream this wave:
//   DELETE /user/sessions/{id}  -> 204
//   DELETE /user/sessions       -> 204 (every session but the caller's)
// A server that has not shipped it answers 404; the message says that rather
// than reporting a generic failure, because "not built yet" and "refused"
// are different things to the person pressing the button.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await req.formData();
  const action = String(form.get("action") ?? "revoke");

  let res: Response;
  let ok: string;
  if (action === "revoke-others") {
    res = await apiSend("DELETE", "/user/sessions");
    ok = "every other session signed out.";
  } else {
    const id = String(form.get("sessionId") ?? "").trim();
    if (!id) return redirectBack(req, "/settings", { error: "no session selected" });
    res = await apiSend("DELETE", `/user/sessions/${encodeURIComponent(id)}`);
    ok = "session revoked.";
  }

  if (res.status === 404) {
    return redirectBack(req, "/settings", {
      error: "this registry build does not serve session management",
    });
  }
  if (!res.ok) return redirectBack(req, "/settings", { error: await problemDetail(res) });
  return redirectBack(req, "/settings", { ok });
}

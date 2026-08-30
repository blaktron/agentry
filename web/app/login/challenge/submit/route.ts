// POST /login/challenge/submit — complete a pending 2FA challenge (§12.1).
//
// Social login is a browser redirect, and a redirect has nowhere to carry a
// TOTP code, so the API withholds the session behind a sealed five-minute
// challenge and asks for the code at POST /auth/2fa/totp/challenge. That
// call is the same shape as a password login: on success it Set-Cookies a
// session and returns a csrfToken, so it mirrors through the same helper.
import { NextRequest, NextResponse } from "next/server";
import { API_BASE } from "@/lib/session";
import { establishSession, redirectBack, safeNext, sameOrigin, requestOrigin} from "@/lib/forms";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) {
    return new NextResponse("cross-origin form post rejected", { status: 403 });
  }
  const form = await req.formData();
  const next = safeNext(form.get("next"), "/dashboard");
  const challenge = String(form.get("challenge") ?? "").trim();
  const code = String(form.get("code") ?? "").trim();
  if (!challenge) {
    return redirectBack(req, "/login/challenge", { error: "paste the challenge value first" });
  }

  const res = await fetch(`${API_BASE}/api/v1/auth/2fa/totp/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ challenge, code }),
    cache: "no-store",
  });

  if (!res.ok) {
    let detail = "the challenge could not be completed";
    try {
      const p = (await res.json()) as { detail?: string; title?: string };
      detail = p.detail || p.title || detail;
    } catch {
      // fall through with the generic message
    }
    return redirectBack(req, "/login/challenge", { error: detail });
  }

  const { csrfToken } = (await res.json()) as { csrfToken: string };
  const out = NextResponse.redirect(new URL(next, requestOrigin(req)), 303);
  if (!establishSession(res, csrfToken, out)) {
    return redirectBack(req, "/login", { error: "the code was accepted but no session was issued" });
  }
  return out;
}

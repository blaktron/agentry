// POST /login/submit — exchange credentials for a session at the API and
// mirror its cookie to the browser (see establishSession in lib/forms.ts).
// The CSRF token rides a second httpOnly cookie that only this web tier
// ever reads.
import { NextRequest, NextResponse } from "next/server";
import { API_BASE, browserHeaders } from "@/lib/session";
import { establishSession, redirectBack, safeNext, sameOrigin, requestOrigin, readForm } from "@/lib/forms";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) {
    return new NextResponse("cross-origin form post rejected", { status: 403 });
  }
  const form = await readForm(req);
  const next = safeNext(form.get("next"), "/dashboard");
  const login = String(form.get("login") ?? "");
  const password = String(form.get("password") ?? "");
  const totpCode = String(form.get("totpCode") ?? "");

  const body: Record<string, string> = { login, password };
  if (totpCode) body.totpCode = totpCode;

  const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json", ...(await browserHeaders()) },
    body: JSON.stringify(body),
    cache: "no-store",
  });

  if (!res.ok) {
    let type = "";
    let detail = "sign-in failed";
    try {
      const p = (await res.json()) as { type?: string; detail?: string; title?: string };
      type = p.type ?? "";
      detail = p.detail || p.title || detail;
    } catch {
      // fall through with the generic message
    }
    const back = new URL("/login", requestOrigin(req));
    back.searchParams.set("next", next);
    if (type.endsWith("totp-required")) {
      back.searchParams.set("totp", "1");
      back.searchParams.set("error", "Enter your two-factor code.");
    } else {
      back.searchParams.set("error", detail);
    }
    return NextResponse.redirect(back, 303);
  }

  const { csrfToken } = (await res.json()) as { csrfToken: string };
  const out = NextResponse.redirect(new URL(next, requestOrigin(req)), 303);
  if (!establishSession(res, csrfToken, out)) {
    return redirectBack(req, "/login", { error: "sign-in succeeded but no session was issued" });
  }
  return out;
}

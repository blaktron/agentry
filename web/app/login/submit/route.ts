// POST /login/submit — exchange credentials for a session at the API and
// mirror its cookie to the browser. The API's Set-Cookie is forwarded
// verbatim (same attributes it chose: httpOnly, SameSite=Lax, Secure per
// deployment); the CSRF token rides a second httpOnly cookie that only this
// web tier ever reads.
import { NextRequest, NextResponse } from "next/server";
import { API_BASE, CSRF_COOKIE, SESSION_COOKIE } from "@/lib/session";
import { redirectBack, safeNext, sameOrigin } from "@/lib/forms";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) {
    return new NextResponse("cross-origin form post rejected", { status: 403 });
  }
  const form = await req.formData();
  const next = safeNext(form.get("next"), "/dashboard");
  const login = String(form.get("login") ?? "");
  const password = String(form.get("password") ?? "");
  const totpCode = String(form.get("totpCode") ?? "");

  const body: Record<string, string> = { login, password };
  if (totpCode) body.totpCode = totpCode;

  const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
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
    const back = new URL("/login", req.nextUrl.origin);
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
  const setCookies = res.headers.getSetCookie();
  const sessionCookie = setCookies.find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  const sessionValue = sessionCookie?.split(";")[0]?.split("=").slice(1).join("=");
  if (!sessionCookie || !sessionValue || !csrfToken) {
    return redirectBack(req, "/login", { error: "sign-in succeeded but no session was issued" });
  }

  // Re-set both cookies through one mechanism (mixing raw Set-Cookie appends
  // with the cookies API loses one of them), mirroring the attributes the
  // API chose: lifetime, HttpOnly, SameSite=Lax, and Secure per deployment.
  const maxAge = /Max-Age=(\d+)/i.exec(sessionCookie)?.[1];
  const secure = /;\s*Secure/i.test(sessionCookie);
  const attrs = {
    httpOnly: true,
    sameSite: "lax" as const,
    path: "/",
    secure,
    ...(maxAge ? { maxAge: Number(maxAge) } : {}),
  };
  const out = NextResponse.redirect(new URL(next, req.nextUrl.origin), 303);
  out.cookies.set(SESSION_COOKIE, sessionValue, attrs);
  out.cookies.set(CSRF_COOKIE, csrfToken, attrs);
  return out;
}

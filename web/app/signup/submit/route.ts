// POST /signup/submit — create the account at the API's /auth/register and
// send the caller back to the sign-in page. Registration does not issue a
// session: the verification email is the next step (§12.1), and social
// sign-in covers the password-free path.
import { NextRequest, NextResponse } from "next/server";
import { API_BASE, browserHeaders } from "@/lib/session";
import { readForm, requestOrigin, sameOrigin } from "@/lib/forms";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) {
    return new NextResponse("cross-origin form post rejected", { status: 403 });
  }
  const form = await readForm(req);
  const body: Record<string, string> = {
    handle: String(form.get("handle") ?? ""),
    email: String(form.get("email") ?? ""),
    password: String(form.get("password") ?? ""),
  };
  const displayName = String(form.get("displayName") ?? "").trim();
  if (displayName) body.displayName = displayName;

  const res = await fetch(`${API_BASE}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json", ...(await browserHeaders()) },
    body: JSON.stringify(body),
    cache: "no-store",
  });

  const back = new URL("/login", requestOrigin(req));
  if (!res.ok) {
    let detail = "registration failed";
    try {
      const p = (await res.json()) as { detail?: string; title?: string };
      detail = p.detail || p.title || detail;
    } catch {
      // fall through with the generic message
    }
    back.searchParams.set("error", detail);
    // Return to the sign-up section; the flip honours the fragment after
    // hydration.
    back.hash = "#sign-up";
    return NextResponse.redirect(back, 303);
  }

  back.searchParams.set(
    "ok",
    "Account created. Check your email for the verification link, then sign in.",
  );
  return NextResponse.redirect(back, 303);
}

// POST /settings/totp — TOTP setup (secret shown once) and verification.
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";
import { showOnce } from "@/lib/show-once";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const action = String(form.get("action") ?? "setup");

  if (action === "verify") {
    const code = String(form.get("code") ?? "").trim();
    const res = await apiSend("POST", "/auth/2fa/totp/verify", { code });
    if (!res.ok) {
      return redirectBack(req, "/settings/authentication?totp=verify", { error: await problemDetail(res) });
    }
    return redirectBack(req, "/settings/authentication", { ok: "two-factor authentication enabled." });
  }

  const res = await apiSend("POST", "/auth/2fa/totp/setup");
  if (!res.ok) return redirectBack(req, "/settings/authentication", { error: await problemDetail(res) });
  const setup = (await res.json()) as { secret: string; otpauthUrl: string };
  return showOnce({
    title: "Add this secret to your authenticator",
    lines: [
      ["Secret (Base32)", setup.secret],
      ["otpauth URL (paste into your authenticator app)", setup.otpauthUrl],
      ["Next step", "Return to Settings and enter the 6-digit code to enable 2FA."],
    ],
    backHref: "/settings/authentication?totp=verify",
  });
}

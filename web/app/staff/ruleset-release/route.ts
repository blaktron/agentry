// POST /staff/ruleset-release — register a ruleset release (platform staff, agentry#63).
import { NextRequest, NextResponse } from "next/server";
import { redirectBack, sameOrigin, readForm } from "@/lib/forms";
import { apiSend, problemDetail } from "@/lib/session";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return new NextResponse("cross-origin form post rejected", { status: 403 });
  const form = await readForm(req);
  const semver = String(form.get("semver") ?? "").trim();
  const bundleDigest = String(form.get("bundleDigest") ?? "").trim();
  const notes = String(form.get("notes") ?? "").trim();
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?$/.test(semver)) return redirectBack(req, "/staff", { error: "semver must be MAJOR.MINOR.PATCH" });
  if (!/^sha256:[0-9a-f]{64}$/.test(bundleDigest)) return redirectBack(req, "/staff", { error: "bundle digest must be sha256:<64 hex>" });
  const body: Record<string, string> = { semver, bundleDigest };
  if (notes) body.notes = notes;
  const res = await apiSend("POST", "/platform/ruleset-releases", body);
  if (!res.ok) return redirectBack(req, "/staff", { error: await problemDetail(res) });
  return redirectBack(req, "/staff", { ok: res.status === 201 ? `ruleset ${semver} registered; the rescan sweep will run.` : `ruleset ${semver} was already registered.` });
}

import { describe, expect, it } from "vitest";
import type { NextRequest } from "next/server";
import { sameOrigin } from "../forms";

// sameOrigin is the app's cross-site-form-post guard. The regression it now
// carries a test for: `Referrer-Policy: no-referrer` (next.config.mjs) makes
// a browser serialize the Origin of every non-CORS POST as the string
// `null` (Fetch, "append a request `Origin` header"). The Origin comparison
// refuses that, so before the Sec-Fetch-Site branch existed every plain-HTML
// form post in the authed surface 403'd in a real browser — while curl,
// which applies no referrer policy, passed. No browser-driven test covered
// it (DEV-031: the M5 Playwright flows were never built).
function request(headers: Record<string, string>, nextUrlHost = "localhost:3000"): NextRequest {
  return {
    headers: new Headers(headers),
    nextUrl: { host: nextUrlHost },
  } as unknown as NextRequest;
}

describe("sameOrigin", () => {
  it("accepts a browser form post with Origin suppressed by no-referrer", () => {
    // What Chrome and Firefox actually send from http://agentry:3000/login.
    expect(
      sameOrigin(request({ origin: "null", host: "agentry:3000", "sec-fetch-site": "same-origin" })),
    ).toBe(true);
  });

  it("rejects a cross-site post even when its Origin header looks right", () => {
    expect(
      sameOrigin(request({ origin: "http://agentry:3000", host: "agentry:3000", "sec-fetch-site": "cross-site" })),
    ).toBe(false);
  });

  it("rejects a sibling subdomain", () => {
    expect(sameOrigin(request({ host: "agentry:3000", "sec-fetch-site": "same-site" }))).toBe(false);
  });

  it("accepts a user-initiated navigation", () => {
    expect(sameOrigin(request({ host: "agentry:3000", "sec-fetch-site": "none" }))).toBe(true);
  });

  it("falls back to Origin vs Host when Sec-Fetch-Site is absent", () => {
    expect(sameOrigin(request({ origin: "http://agentry:3000", host: "agentry:3000" }))).toBe(true);
    expect(sameOrigin(request({ origin: "http://elsewhere:3000", host: "agentry:3000" }))).toBe(false);
    // An opaque origin with no Sec-Fetch-Site to vouch for it stays refused.
    expect(sameOrigin(request({ origin: "null", host: "agentry:3000" }))).toBe(false);
  });

  it("honours x-forwarded-host over host when a proxy fronts the app", () => {
    expect(
      sameOrigin(request({ origin: "https://registry.example", "x-forwarded-host": "registry.example", host: "localhost:3000" })),
    ).toBe(true);
  });

  it("lets a non-browser client through to the API's own gates", () => {
    expect(sameOrigin(request({ host: "agentry:3000" }))).toBe(true);
  });
});

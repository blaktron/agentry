import { describe, expect, it } from "vitest";
import { buildCSP, formActionSources, idpFormActionOrigin, LOOPBACK_FORM_ACTION } from "../csp";

// Chrome applies form-action to the redirect chain of a form submission, so
// every off-origin 303 a form can legitimately trigger must be listed, and
// nothing else (agentry#81 for the IdP end-session URL, agentry#172 for the
// desktop app's loopback callback).
describe("form-action", () => {
  it("is 'self' alone on an ordinary page with no IdP", () => {
    expect(formActionSources("/settings", undefined)).toEqual(["'self'"]);
    expect(formActionSources("/", "")).toEqual(["'self'"]);
  });

  it("allows the IdP origin everywhere when a logout URL is configured", () => {
    const idp = "https://auth.example.test/application/o/agentry/end-session/";
    expect(formActionSources("/settings", idp)).toEqual(["'self'", "https://auth.example.test"]);
    expect(formActionSources("/dashboard", idp)).toEqual(["'self'", "https://auth.example.test"]);
  });

  it("ignores a malformed or non-http logout URL", () => {
    expect(idpFormActionOrigin("javascript:alert(1)")).toBeNull();
    expect(idpFormActionOrigin("not a url")).toBeNull();
    expect(formActionSources("/settings", "not a url")).toEqual(["'self'"]);
  });

  it("allows the loopback listener only on the desktop authorize pages", () => {
    expect(formActionSources("/settings/tokens/desktop", undefined)).toEqual(["'self'", LOOPBACK_FORM_ACTION]);
    expect(formActionSources("/settings/tokens/desktop/approve", undefined)).toEqual(["'self'", LOOPBACK_FORM_ACTION]);
    // Neighbours and look-alikes stay strict.
    expect(formActionSources("/settings/tokens", undefined)).toEqual(["'self'"]);
    expect(formActionSources("/settings/tokens/desktopx", undefined)).toEqual(["'self'"]);
    expect(formActionSources("/settings", undefined)).toEqual(["'self'"]);
  });

  it("orders the sources so the IdP comes before the loopback origin", () => {
    const idp = "https://auth.example.test/x";
    expect(formActionSources("/settings/tokens/desktop", idp)).toEqual([
      "'self'",
      "https://auth.example.test",
      LOOPBACK_FORM_ACTION,
    ]);
  });
});

describe("buildCSP", () => {
  it("carries the nonce in script-src and the per-path form-action", () => {
    const csp = buildCSP("abc123", "/settings/tokens/desktop", undefined);
    expect(csp.startsWith("script-src 'self' 'nonce-abc123'; ")).toBe(true);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp.endsWith("form-action 'self' http://127.0.0.1:*")).toBe(true);
  });

  it("keeps ordinary pages at form-action 'self'", () => {
    const csp = buildCSP("n", "/settings", undefined);
    expect(csp.endsWith("form-action 'self'")).toBe(true);
    expect(csp).not.toContain("127.0.0.1");
  });
});

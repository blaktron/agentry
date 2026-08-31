// The browser smoke (DEV-031): a real Chromium driving the five public
// flows' load-bearing pages plus the one thing curl can never assert — a
// same-origin form post under real browser semantics. The forms outage of
// 2026-08-31 (Referrer-Policy: no-referrer ⇒ `Origin: null`, no
// Sec-Fetch-* over plain http) shipped precisely because nothing in CI
// implemented those semantics; the sign-out test here is the regression
// pin, driven with a session seeded through the API so it works whether
// credentials are native or the directory service's (DEV-057).
import { test, expect, request } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:8199";
const USER = process.env.E2E_USER;
const PASS = process.env.E2E_PASS;

test("home renders the product shell", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: "BriefAgent Builder" })).toBeVisible();
  // Scoped to the nav: the footer carries the same link (strict mode).
  await expect(page.getByRole("navigation").getByRole("link", { name: "Trust & security" })).toBeVisible();
  await expect(page.locator("body")).toContainText("SecureAgentry");
});

test("trust page links the advisory feed", async ({ page }) => {
  await page.goto("/trust");
  await expect(page.getByRole("link", { name: "advisory feed" })).toBeVisible();
});

test("search renders (empty results are fine)", async ({ page }) => {
  await page.goto("/search?q=smoke");
  await expect(page.locator("h1")).toBeVisible();
  await expect(page.locator("body")).not.toContainText("Internal server error");
});

test.describe("authed flows", () => {
  test.skip(!USER || !PASS, "E2E_USER / E2E_PASS not provided by the boot script");

  // Establish the session at the API and mirror both cookies onto the web
  // origin — the same pair /login/submit would set. This keeps the test
  // independent of HOW sign-in happens (password today, IdP redirect under
  // AGENTRY_AUTH_EXTERNAL_ONLY) while still exercising everything after.
  async function signIn(page: import("@playwright/test").Page, baseURL: string) {
    const api = await request.newContext();
    const res = await api.post(`${API}/api/v1/auth/login`, {
      data: { login: USER, password: PASS },
    });
    expect(res.ok(), `api login: ${res.status()}`).toBeTruthy();
    const csrf = (await res.json()).csrfToken as string;
    const setCookie = res.headersArray().find((h) => h.name.toLowerCase() === "set-cookie");
    const session = /agentry_session=([^;]+)/.exec(setCookie?.value ?? "")?.[1];
    expect(session, "api login issued no session cookie").toBeTruthy();
    const u = new URL(baseURL);
    await page.context().addCookies([
      { name: "agentry_session", value: session!, domain: u.hostname, path: "/", httpOnly: true, sameSite: "Lax" },
      { name: "agentry_csrf", value: csrf, domain: u.hostname, path: "/", httpOnly: true, sameSite: "Lax" },
    ]);
    await api.dispose();
  }

  test("dashboard server-renders for a signed-in browser", async ({ page, baseURL }) => {
    await signIn(page, baseURL!);
    await page.goto("/dashboard");
    await expect(page.getByRole("button", { name: `Sign out (${USER})` })).toBeVisible();
  });

  test("the Builder page renders its form", async ({ page, baseURL }) => {
    await signIn(page, baseURL!);
    await page.goto("/build");
    await expect(page.getByRole("button", { name: "Create & submit" })).toBeVisible();
    await expect(page.locator("textarea[name=instructions]")).toBeVisible();
  });

  test("a plain HTML form posts same-origin from a real browser (sign-out)", async ({ page, baseURL }) => {
    await signIn(page, baseURL!);
    await page.goto("/dashboard");
    await page.getByRole("button", { name: `Sign out (${USER})` }).click();
    // The regression: this used to answer 403 "cross-origin form post
    // rejected" for every real browser while curl sailed through.
    await expect(page.locator("body")).not.toContainText("cross-origin form post rejected");
    await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
  });
});

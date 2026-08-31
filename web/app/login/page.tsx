import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { enabledSocialProviders, SOCIAL_PROVIDERS } from "@/lib/api";
import { safeNext } from "@/lib/urls";
import { currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Sign in" };

// Auth landing (§10 authed surface).
//
// DEV-057: credentials and the account directory now live in the
// deployment's own directory service (Authentik), consumed through the
// standard social-OIDC path. This page therefore offers provider buttons
// only; the native password sign-in, sign-up, and org-SSO forms are
// COMMENTED OUT below — deliberately preserved, not removed — and their
// API endpoints answer 410 Gone while auth.externalOnly is set.
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; next?: string; totp?: string; ok?: string }>;
}) {
  const params = await searchParams;
  // safeNext, not startsWith("/"): "//evil.example" is path-absolute to a
  // naive check and scheme-relative to a browser.
  const next = safeNext(params.next, "/dashboard");
  if (await currentUser()) redirect(next);

  const social = await enabledSocialProviders();
  const providers = SOCIAL_PROVIDERS.filter((p) => social.includes(p.id));

  // DEV-057: when the directory service is the only way in, this page is a
  // stop nobody needs — every "Sign in" link forwards straight into the IdP
  // flow. It still renders when there is something to say (an error or ok
  // flash, e.g. from a failed callback: bouncing that back to the IdP would
  // loop without ever showing the message) or when the deployment offers a
  // choice of providers.
  if (!params.error && !params.ok && providers.length === 1 && providers[0].id === "authentik") {
    redirect("/api/v1/auth/oidc/authentik/start");
  }

  return (
    <div className="mx-auto max-w-md">
      <h1 className="mb-4 text-xl font-semibold">Sign in</h1>

      {params.ok && (
        <p
          role="status"
          className="mb-4 rounded-md border px-3 py-2 text-sm"
          style={{ borderColor: "var(--color-ok)", color: "var(--color-ok)" }}
        >
          {params.ok}
        </p>
      )}
      {params.error && (
        <p
          role="alert"
          className="mb-4 rounded-md border px-3 py-2 text-sm"
          style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}
        >
          {params.error}
        </p>
      )}

      <Card>
        {providers.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            No identity provider is configured on this deployment. An operator
            needs to point the registry at its directory service
            (docs/self-hosting.md, DEV-057).
          </p>
        ) : (
          <div className="flex flex-col gap-2">
            {providers.map((p) => (
              <a
                key={p.id}
                href={`/api/v1/auth/oidc/${p.id}/start`}
                rel="nofollow"
                className="rounded-md border px-3 py-2 text-center text-sm font-medium"
                style={
                  p.id === "authentik"
                    ? { background: "var(--color-accent)", color: "var(--color-accent-fg)" }
                    : { borderColor: "var(--color-border)" }
                }
              >
                Continue with {p.label}
              </a>
            ))}
          </div>
        )}
        <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
          Accounts, passwords, and multi-factor are managed by this
          deployment&apos;s directory service; signing in creates or links your
          registry account automatically. Provider sign-in never grants
          organization membership.
        </p>
      </Card>
    </div>
  );
}

/* ── DEV-057: native credential UI, commented out, not removed ────────────
   The password sign-in / sign-up / org-SSO landing this page used to
   render (three FlipSections views; forms posting to /login/submit,
   /signup/submit and /sso). Restore by reverting this file and clearing
   auth.externalOnly. Kept verbatim for that day:

  // imports this block needs back:
  // import Link from "next/link";
  // import FlipSections from "@/components/flip-sections";

  const inputClass = "mt-1 w-full rounded-md border px-3 py-1.5";
  const inputStyle = { borderColor: "var(--color-border)", background: "var(--color-surface)" };

  const socialBlock = (heading: string) =>
    providers.length === 0 ? null : (
      <Card className="mt-4">
        <h2 className="mb-2 text-sm font-semibold">{heading}</h2>
        <div className="flex flex-wrap gap-2">
          {providers.map((p) => (
            <a key={p.id} href={`/api/v1/auth/oidc/${p.id}/start`} rel="nofollow"
              className="rounded-md border px-3 py-1.5 text-sm font-medium"
              style={{ borderColor: "var(--color-border)" }}>
              Continue with {p.label}
            </a>
          ))}
        </div>
        <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
          Provider sign-in creates or links an individual account only. It never grants
          organization membership. Two-factor still applies:{" "}
          <Link href="/login/challenge" className="underline">finish a pending challenge</Link>.
        </p>
      </Card>
    );

  <FlipSections
    views={[
      {
        id: "sign-in",
        label: "Sign in",
        content: (
          <section id="sign-in">
            <Card>
              <form method="post" action="/login/submit" className="flex flex-col gap-3">
                <input type="hidden" name="next" value={params.next ?? ""} />
                <label className="text-sm">
                  Handle or email
                  <input name="login" required autoComplete="username"
                    className={inputClass} style={inputStyle} />
                </label>
                <label className="text-sm">
                  Password
                  <input name="password" type="password" required
                    autoComplete="current-password" className={inputClass} style={inputStyle} />
                </label>
                {params.totp === "1" && (
                  <label className="text-sm">
                    Two-factor code
                    <input name="totpCode" inputMode="numeric" autoComplete="one-time-code"
                      required className={inputClass} style={inputStyle} />
                  </label>
                )}
                <button type="submit" className="mt-2 rounded-md px-3 py-1.5 text-sm font-medium"
                  style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}>
                  Sign in
                </button>
              </form>
            </Card>
            {socialBlock("Or use a provider account")}
          </section>
        ),
      },
      {
        id: "sign-up",
        label: "Sign up",
        content: (
          <section id="sign-up">
            <Card>
              <form method="post" action="/signup/submit" className="flex flex-col gap-3">
                <label className="text-sm">
                  Handle
                  <input name="handle" required pattern="[a-z0-9][a-z0-9-]*[a-z0-9]|[a-z0-9]"
                    title="Lowercase letters, digits, and hyphens; up to 39 characters."
                    autoComplete="username" className={inputClass} style={inputStyle} />
                </label>
                <label className="text-sm">
                  Email
                  <input name="email" type="email" required autoComplete="email"
                    className={inputClass} style={inputStyle} />
                </label>
                <label className="text-sm">
                  Password
                  <input name="password" type="password" required minLength={10} maxLength={256}
                    autoComplete="new-password" className={inputClass} style={inputStyle} />
                </label>
                <label className="text-sm">
                  Display name (optional)
                  <input name="displayName" maxLength={120} autoComplete="name"
                    className={inputClass} style={inputStyle} />
                </label>
                <button type="submit" className="mt-2 rounded-md px-3 py-1.5 text-sm font-medium"
                  style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}>
                  Create account
                </button>
              </form>
              <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
                Passwords are at least 10 characters. Registration emails a verification
                link; the account is usable once the address is verified.
              </p>
            </Card>
            {socialBlock("Or start with a provider account")}
          </section>
        ),
      },
      {
        id: "sso",
        label: "Single sign-on",
        content: (
          <section id="sso">
            <Card>
              <h2 className="mb-2 text-sm font-semibold">Sign in with your company account</h2>
              <form method="get" action="/sso" className="flex items-end gap-2 text-sm">
                <label className="grow">
                  Organization handle
                  <input name="org" required pattern="[a-z0-9][a-z0-9-]*" placeholder="acme"
                    className={inputClass} style={inputStyle} />
                </label>
                <button type="submit" className="rounded-md border px-3 py-1.5 font-medium"
                  style={{ borderColor: "var(--color-border)" }}>
                  Continue
                </button>
              </form>
              <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
                Sends you to <code>/sso/&lt;org&gt;</code>. That starts whichever SAML or OIDC
                connection the organization has enabled (§12.4).
              </p>
            </Card>
          </section>
        ),
      },
    ]}
  />
──────────────────────────────────────────────────────────────────────── */

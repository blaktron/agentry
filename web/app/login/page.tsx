import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { enabledSocialProviders, SOCIAL_PROVIDERS } from "@/lib/api";
import { safeNext } from "@/lib/urls";
import { currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Sign in" };

// Sign-in (§10 authed surface). A plain form posting to /login/submit. The
// web tier forwards credentials to the API once and stores only the session
// cookie the API minted. TOTP is a single optional field: the API answers
// totp-required and the page re-renders asking for the code.
//
// Two other entry points sit below it: social login (§12.1, individual
// accounts) and the org SSO landing (§12.4, "sign in with your company
// account"). Both are ordinary links/forms to endpoints the API serves on
// this same origin; no client JS is involved in either.
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; next?: string; totp?: string }>;
}) {
  const params = await searchParams;
  // safeNext, not startsWith("/"): "//evil.example" is path-absolute to a
  // naive check and scheme-relative to a browser.
  const next = safeNext(params.next, "/dashboard");
  if (await currentUser()) redirect(next);

  const social = await enabledSocialProviders();

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="mb-4 text-xl font-semibold">Sign in</h1>
      <Card>
        {params.error && (
          <p role="alert" className="mb-3 text-sm" style={{ color: "var(--color-sev-high)" }}>
            {params.error}
          </p>
        )}
        <form method="post" action="/login/submit" className="flex flex-col gap-3">
          <input type="hidden" name="next" value={params.next ?? ""} />
          <label className="text-sm">
            Handle or email
            <input
              name="login"
              required
              autoComplete="username"
              className="mt-1 w-full rounded-md border px-3 py-1.5"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <label className="text-sm">
            Password
            <input
              name="password"
              type="password"
              required
              autoComplete="current-password"
              className="mt-1 w-full rounded-md border px-3 py-1.5"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          {params.totp === "1" && (
            <label className="text-sm">
              Two-factor code
              <input
                name="totpCode"
                inputMode="numeric"
                autoComplete="one-time-code"
                required
                className="mt-1 w-full rounded-md border px-3 py-1.5"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </label>
          )}
          <button
            type="submit"
            className="mt-2 rounded-md px-3 py-1.5 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            Sign in
          </button>
        </form>
      </Card>

      {social.length > 0 && (
        <Card className="mt-4">
          <h2 className="mb-2 text-sm font-semibold">Or use a provider account</h2>
          <div className="flex flex-wrap gap-2">
            {SOCIAL_PROVIDERS.filter((p) => social.includes(p.id)).map((p) => (
              // A plain link, not a form: the API's start endpoint is a GET
              // that sets a sealed state cookie and 302s to the provider.
              <a
                key={p.id}
                href={`/api/v1/auth/oidc/${p.id}/start`}
                rel="nofollow"
                className="rounded-md border px-3 py-1.5 text-sm font-medium"
                style={{ borderColor: "var(--color-border)" }}
              >
                Continue with {p.label}
              </a>
            ))}
          </div>
          <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
            Provider sign-in creates or links an individual account only. It never grants
            organization membership. Two-factor still applies:{" "}
            <Link href="/login/challenge" className="underline">
              finish a pending challenge
            </Link>
            .
          </p>
        </Card>
      )}

      <Card className="mt-4">
        <h2 className="mb-2 text-sm font-semibold">Sign in with your company account</h2>
        <form method="get" action="/sso" className="flex items-end gap-2 text-sm">
          <label className="grow">
            Organization handle
            <input
              name="org"
              required
              pattern="[a-z0-9][a-z0-9-]*"
              placeholder="acme"
              className="mt-1 w-full rounded-md border px-3 py-1.5"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <button
            type="submit"
            className="rounded-md border px-3 py-1.5 font-medium"
            style={{ borderColor: "var(--color-border)" }}
          >
            Continue
          </button>
        </form>
        <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
          Sends you to <code>/sso/&lt;org&gt;</code>. That starts whichever SAML or OIDC
          connection the organization has enabled (§12.4).
        </p>
      </Card>

      <p className="mt-4 text-sm" style={{ color: "var(--color-muted)" }}>
        Accounts are created with the CLI or API today (<code>agentry login</code> after registering);
        this console signs in with the same credentials.
      </p>
    </div>
  );
}

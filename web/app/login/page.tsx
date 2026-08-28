import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Sign in" };

// Sign-in (§10 authed surface). A plain form posting to /login/submit — the
// web tier forwards credentials to the API once and stores only the session
// cookie the API minted. TOTP is a single optional field: the API answers
// totp-required and the page re-renders asking for the code.
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; next?: string; totp?: string }>;
}) {
  const params = await searchParams;
  if (await currentUser()) redirect(params.next && params.next.startsWith("/") ? params.next : "/dashboard");
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
            style={{ background: "var(--color-accent)", color: "white" }}
          >
            Sign in
          </button>
        </form>
      </Card>
      <p className="mt-4 text-sm" style={{ color: "var(--color-muted)" }}>
        Accounts are created with the CLI or API today (<code>agentry login</code> after registering);
        this console signs in with the same credentials.
      </p>
    </div>
  );
}

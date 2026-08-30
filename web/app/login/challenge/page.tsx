import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { safeNext } from "@/lib/urls";
import { currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Two-factor challenge" };

// Completion page for a pending 2FA challenge (§12.1, DEV-023).
//
// A social-login callback lands on the API, not here, and answers with JSON:
// either a session or `{totpRequired:true, challenge:"…"}`. Until the API
// redirects the browser back to this page with ?challenge=…, an account with
// 2FA has to bring the value over by hand, so the field accepts a paste and
// the copy says plainly where the value comes from.
export default async function ChallengePage({
  searchParams,
}: {
  searchParams: Promise<{ challenge?: string; next?: string; error?: string }>;
}) {
  const params = await searchParams;
  const next = safeNext(params.next, "/dashboard");
  if (await currentUser()) redirect(next);

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="mb-4 text-xl font-semibold">Finish signing in</h1>
      <Card>
        {params.error && (
          <p role="alert" className="mb-3 text-sm" style={{ color: "var(--color-sev-high)" }}>
            {params.error}
          </p>
        )}
        <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
          This account has two-factor authentication enabled, so the provider sign-in issued a
          five-minute challenge instead of a session. Enter the code from your authenticator to
          complete it.
        </p>
        <form method="post" action="/login/challenge/submit" className="flex flex-col gap-3">
          <input type="hidden" name="next" value={next} />
          <label className="text-sm">
            Challenge
            <input
              name="challenge"
              required
              defaultValue={params.challenge ?? ""}
              autoComplete="off"
              spellCheck={false}
              className="mt-1 w-full rounded-md border px-3 py-1.5 font-mono text-xs"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
            <span className="mt-1 block text-xs" style={{ color: "var(--color-muted)" }}>
              The <code>challenge</code> value from the sign-in response.
            </span>
          </label>
          <label className="text-sm">
            Two-factor code
            <input
              name="code"
              required
              inputMode="numeric"
              autoComplete="one-time-code"
              className="mt-1 w-full rounded-md border px-3 py-1.5"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <button
            type="submit"
            className="mt-2 rounded-md px-3 py-1.5 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            Complete sign-in
          </button>
        </form>
      </Card>
      <p className="mt-4 text-sm" style={{ color: "var(--color-muted)" }}>
        Challenges expire five minutes after the provider sign-in.{" "}
        <Link href="/login" className="underline">
          Start again
        </Link>
        .
      </p>
    </div>
  );
}

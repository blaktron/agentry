"use client";

// Route error boundary (§10). lib/api.ts throws on any non-404 API failure
// specifically so this renders — before this file existed, that promise was
// unkept and a 5xx from agentryd produced Next's unstyled default page.
//
// The copy is deliberately narrow: we say the page could not be loaded, not
// that anything is safe, fine, or retried. `digest` is the hash Next puts in
// the server log next to the real stack, so quoting it back is what makes a
// user report actionable without leaking the error text.
import Link from "next/link";

export default function RouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="mx-auto max-w-xl space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">This page could not be loaded</h1>
      <div
        className="rounded-lg border p-4"
        style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
      >
        <p className="text-sm">
          Something failed between this console and the registry API. Nothing was changed by the
          request that failed.
        </p>
        {error.digest && (
          <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
            Reference <code className="font-mono">{error.digest}</code>. Quote it if you report
            this; the matching stack trace is in the server log.
          </p>
        )}
        <div className="mt-4 flex flex-wrap gap-3 text-sm">
          <button
            type="button"
            onClick={reset}
            className="rounded-md px-3 py-1.5 font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
          >
            Try again
          </button>
          <Link
            href="/"
            className="rounded-md border px-3 py-1.5 font-medium"
            style={{ borderColor: "var(--color-border)" }}
          >
            Go to the home page
          </Link>
        </div>
      </div>
    </div>
  );
}

import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { currentUser, reviewerOrgs } from "@/lib/session";

export const metadata: Metadata = {
  title: { default: "Agentry", template: "%s · Agentry" },
  description:
    "A registry and git host for single-purpose AI agents, with mandatory pre-publication security scanning and signed provenance.",
};

// AccountNav renders the signed-in identity area of the header. Reading the
// session cookie makes routes render dynamically — the fetch cache still
// serves the public-page API data, so this costs a render, not the backend.
async function AccountNav() {
  const user = await currentUser();
  if (!user) {
    return (
      <Link href="/login" className="text-sm font-medium hover:underline">
        Sign in
      </Link>
    );
  }
  const showReview = user.platformStaff || reviewerOrgs(user).length > 0;
  return (
    <div className="flex items-center gap-3 text-sm">
      <Link href="/dashboard" className="hover:underline">
        Dashboard
      </Link>
      {showReview && (
        <Link href="/review" className="hover:underline">
          Review
        </Link>
      )}
      {user.platformStaff && (
        <Link href="/staff" className="hover:underline">
          Staff
        </Link>
      )}
      <form method="post" action="/logout">
        <button
          type="submit"
          className="rounded-md border px-2 py-1 text-xs"
          style={{ borderColor: "var(--color-border)", color: "var(--color-muted)" }}
          title={`Signed in as ${user.handle}`}
        >
          Sign out ({user.handle})
        </button>
      </form>
    </div>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b" style={{ borderColor: "var(--color-border)" }}>
          <div className="mx-auto flex max-w-6xl items-center gap-6 px-4 py-3">
            <Link href="/" className="text-lg font-semibold tracking-tight">
              Agentry
            </Link>
            <nav className="flex gap-4 text-sm" style={{ color: "var(--color-muted)" }}>
              <Link href="/search">Browse</Link>
              <Link href="/trust">Trust &amp; security</Link>
              <Link href="/advisories">Advisories</Link>
              <Link href="/docs">Docs</Link>
            </nav>
            <form action="/search" className="ml-auto">
              <input
                type="search"
                name="q"
                placeholder="Search agents…"
                aria-label="Search agents"
                className="w-56 rounded-md border px-3 py-1.5 text-sm"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </form>
            <AccountNav />
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
        <footer
          className="mt-16 border-t py-8 text-sm"
          style={{ borderColor: "var(--color-border)", color: "var(--color-muted)" }}
        >
          <div className="mx-auto max-w-6xl px-4">
            <p>
              Agentry scans every published version and records signed provenance. Scanning reduces
              risk; it does not prove an agent safe — read the{" "}
              <Link href="/trust" className="underline">
                security model
              </Link>
              .
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}

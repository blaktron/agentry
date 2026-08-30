import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { currentUser, reviewerOrgs } from "@/lib/session";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: { default: SITE.brand, template: `%s · ${SITE.brand}` },
  description: SITE.tagline,
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

// The primary nav. Docs and Developers live on separate deployments
// (docs./developers.), so those are absolute links; the rest are in-app.
function PrimaryNav() {
  const linkClass = "hover:underline whitespace-nowrap";
  return (
    <nav className="flex flex-wrap gap-4 text-sm" style={{ color: "var(--color-muted)" }}>
      <Link href="/search" className={linkClass}>
        Browse
      </Link>
      <Link href="/trust" className={linkClass}>
        Trust &amp; security
      </Link>
      <Link href="/agent-template" className={linkClass}>
        BriefAgent Template
      </Link>
      <Link href="/advisories" className={linkClass}>
        Advisories
      </Link>
      <Link href="/download" className={linkClass}>
        Download
      </Link>
      <a href={SITE.docsUrl} className={linkClass}>
        Docs
      </a>
    </nav>
  );
}

function FooterColumn({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <div
        className="text-xs font-semibold uppercase tracking-wide"
        style={{ color: "var(--color-fg)" }}
      >
        {title}
      </div>
      <ul className="flex flex-col gap-1.5">{children}</ul>
    </div>
  );
}

function FooterLink({ href, children }: { href: string; children: React.ReactNode }) {
  const external = href.startsWith("http");
  const cls = "hover:underline";
  return (
    <li>
      {external ? (
        <a href={href} className={cls}>
          {children}
        </a>
      ) : (
        <Link href={href} className={cls}>
          {children}
        </Link>
      )}
    </li>
  );
}

function SiteFooter() {
  return (
    <footer
      className="mt-16 border-t py-10 text-sm"
      style={{ borderColor: "var(--color-border)", color: "var(--color-muted)" }}
    >
      <div className="mx-auto max-w-6xl px-4">
        <div className="grid grid-cols-2 gap-8 sm:grid-cols-4">
          <FooterColumn title="Product">
            <FooterLink href="/search">Browse BriefAgents</FooterLink>
            <FooterLink href="/download">Download</FooterLink>
            <FooterLink href="/agent-template">BriefAgent Template</FooterLink>
            <FooterLink href="/advisories">Advisories</FooterLink>
          </FooterColumn>
          <FooterColumn title="Developers">
            <FooterLink href={SITE.docsUrl}>Documentation</FooterLink>
            <FooterLink href={SITE.developersUrl}>API reference</FooterLink>
            <FooterLink href="/trust">Trust &amp; security</FooterLink>
          </FooterColumn>
          <FooterColumn title="Company">
            <FooterLink href="/about">About</FooterLink>
            <FooterLink href="/contact">Contact</FooterLink>
          </FooterColumn>
          <FooterColumn title="Legal">
            <FooterLink href="/privacy">Privacy</FooterLink>
            <FooterLink href="/terms">Terms</FooterLink>
          </FooterColumn>
        </div>
        <div
          className="mt-8 flex flex-col gap-2 border-t pt-6 sm:flex-row sm:items-center sm:justify-between"
          style={{ borderColor: "var(--color-border)" }}
        >
          <p>
            © {SITE.copyrightYear} {SITE.brand}. Scanning reduces risk; it does not prove a
            BriefAgent safe. Read the{" "}
            <Link href="/trust" className="underline">
              security model
            </Link>
            .
          </p>
          <p style={{ color: "var(--color-muted)" }}>Built on the open-source Agentry framework.</p>
        </div>
      </div>
    </footer>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b" style={{ borderColor: "var(--color-border)" }}>
          <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
            <Link href="/" className="text-lg font-semibold tracking-tight">
              {SITE.brand}
            </Link>
            <PrimaryNav />
            <form action="/search" className="ml-auto">
              <input
                type="search"
                name="q"
                placeholder="Search BriefAgents…"
                aria-label="Search BriefAgents"
                className="w-56 rounded-md border px-3 py-1.5 text-sm"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </form>
            <AccountNav />
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}

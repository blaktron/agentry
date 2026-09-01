import type { Metadata } from "next";
import Link from "next/link";
import { headers } from "next/headers";
import "./globals.css";
import { plexMono, plexSans } from "./fonts";
import { Mark, Wordmark } from "@/components/brand";
import { CookieBanner, COOKIE_ACK_COOKIE } from "@/components/cookie-banner";
import { cookies } from "next/headers";
import { currentUser, reviewerOrgs } from "@/lib/session";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: { default: SITE.brand, template: `%s · ${SITE.brand}` },
  description: SITE.tagline,
};

// The primary nav: five items, short labels. Docs lives on a separate
// deployment (docs.), so that one is an absolute link. `match` is the path
// prefix that counts as "here" for the current-page mark — Browse owns the
// search, tag, and agent pages, which is where browsing actually happens.
const NAV: { href: string; label: string; match?: RegExp; external?: boolean }[] = [
  { href: "/search", label: "Browse", match: /^\/(search|tags\/|[^/]+\/[^/]+(\/|$))/ },
  { href: "/build", label: "Build", match: /^\/(build|agent-template)(\/|$)/ },
  { href: "/trust", label: "Trust & security", match: /^\/(trust|advisories)(\/|$)/ },
  { href: "/download", label: "Download", match: /^\/download(\/|$)/ },
  { href: SITE.docsUrl, label: "Docs", external: true },
];

// Pages the nav must NOT claim for Browse even though they are /<a>/<b>.
const NOT_BROWSE = /^\/(settings|orgs|review|staff|dashboard|login|logout|new|about|contact|privacy|terms|docs)(\/|$)/;

function isCurrent(item: (typeof NAV)[number], pathname: string): boolean {
  if (!item.match) return false;
  if (item.label === "Browse" && NOT_BROWSE.test(pathname)) return false;
  return item.match.test(pathname);
}

// AccountNav renders the signed-in identity area of the header. Reading the
// session cookie makes routes render dynamically — the fetch cache still
// serves the public-page API data, so this costs a render, not the backend.
async function AccountNav({ stacked = false }: { stacked?: boolean }) {
  const user = await currentUser();
  if (!user) {
    return (
      <Link
        href="/login"
        className="rounded-md px-3 py-1.5 text-sm font-medium"
        style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}
      >
        Sign in
      </Link>
    );
  }
  const showReview = user.platformStaff || reviewerOrgs(user).length > 0;
  return (
    <div className={`flex ${stacked ? "flex-col items-start gap-2" : "items-center gap-3"} text-sm`}>
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

function NavLinks({ pathname, stacked = false }: { pathname: string; stacked?: boolean }) {
  return (
    <nav
      aria-label="Primary"
      className={stacked ? "flex flex-col gap-1 text-base" : "flex items-center gap-5 text-sm"}
    >
      {NAV.map((item) => {
        const current = isCurrent(item, pathname);
        const cls = stacked
          ? "rounded-md px-2 py-1.5"
          : "whitespace-nowrap border-b-2 py-1 hover:underline";
        const style = {
          color: current ? "var(--color-fg)" : "var(--color-muted)",
          borderColor: current ? "var(--color-accent)" : "transparent",
          background: stacked && current ? "var(--color-surface)" : undefined,
          fontWeight: current ? 500 : undefined,
        };
        return item.external ? (
          <a key={item.href} href={item.href} className={cls} style={style}>
            {item.label}
          </a>
        ) : (
          <Link
            key={item.href}
            href={item.href}
            className={cls}
            style={style}
            aria-current={current ? "page" : undefined}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

function SearchForm({ className = "" }: { className?: string }) {
  return (
    <form action="/search" className={className} role="search">
      <input
        type="search"
        name="q"
        placeholder="Search BriefAgents…"
        aria-label="Search BriefAgents"
        className="w-full rounded-md border px-3 py-1.5 text-sm md:w-56"
        style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
      />
    </form>
  );
}

// SiteHeader: brand, nav, search, account. Below `md` the nav, search, and
// account collapse into a native <details> disclosure — keyboard-accessible,
// no client JS, so the strict CSP is untouched. The panel is positioned
// under the header bar rather than inline so opening it never reflows the
// page.
async function SiteHeader() {
  const pathname = (await headers()).get("x-pathname") ?? "/";
  return (
    <header className="relative border-b" style={{ borderColor: "var(--color-border)" }}>
      <div className="mx-auto flex max-w-6xl items-center gap-x-6 px-4 py-3">
        <Link href="/" className="shrink-0" aria-label={`${SITE.brand} home`}>
          <Wordmark brand={SITE.brand} />
        </Link>
        <div className="hidden md:block">
          <NavLinks pathname={pathname} />
        </div>
        <SearchForm className="ml-auto hidden md:block" />
        <div className="hidden md:block">
          <AccountNav />
        </div>

        <details className="group ml-auto md:hidden">
          <summary
            className="cursor-pointer list-none rounded-md border px-3 py-1.5 text-sm font-medium select-none"
            style={{ borderColor: "var(--color-border)" }}
          >
            Menu
          </summary>
          <div
            className="absolute inset-x-0 top-full z-20 flex flex-col gap-4 border-b px-4 pb-5 pt-3"
            style={{ background: "var(--color-bg)", borderColor: "var(--color-border)" }}
          >
            <SearchForm />
            <NavLinks pathname={pathname} stacked />
            <div className="border-t pt-3" style={{ borderColor: "var(--color-border)" }}>
              <AccountNav stacked />
            </div>
          </div>
        </details>
      </div>
    </header>
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
            <FooterLink href="/build">BriefAgent Builder</FooterLink>
            <FooterLink href="/agent-template">BriefAgent Template</FooterLink>
            <FooterLink href="/download">Download</FooterLink>
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
          <p className="flex items-center gap-2">
            <Mark size={16} />
            <span>
              © {SITE.copyrightYear} {SITE.brand}. Scanning reduces risk; it does not prove a
              BriefAgent safe. Read the{" "}
              <Link href="/trust" className="underline">
                security model
              </Link>
              .
            </span>
          </p>
          <p>Open source, MIT licensed.</p>
        </div>
      </div>
    </footer>
  );
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const [user, jar] = await Promise.all([currentUser(), cookies()]);
  const cookieAcked = Boolean(jar.get(COOKIE_ACK_COOKIE)?.value);
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body>
        <SiteHeader />
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
        <SiteFooter />
        <CookieBanner user={user} acked={cookieAcked} />
      </body>
    </html>
  );
}

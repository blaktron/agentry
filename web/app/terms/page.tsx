import type { Metadata } from "next";
import Link from "next/link";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: `The terms governing use of ${SITE.brand}.`,
};

// Terms of service (§10 legal surface). A standard set for a site with
// accounts and user-published content, kept in the product's plain register:
// each section says one thing a user actually needs to know.
const UPDATED = "September 1, 2026";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="font-medium">{title}</h2>
      <div className="mt-1 space-y-2 text-sm leading-relaxed" style={{ color: "var(--color-muted)" }}>
        {children}
      </div>
    </section>
  );
}

export default function TermsPage() {
  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">Terms of Service</h1>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Last updated {UPDATED}. Using this {SITE.brand} registry means you accept these terms; if
          you do not, do not use it.
        </p>
      </header>

      <Section title="Your account">
        <p>
          Keep your sign-in credentials to yourself, give us a working email address, and tell us
          promptly if you believe your account is compromised. You are responsible for what happens
          under your account. You must be legally able to enter this agreement.
        </p>
      </Section>

      <Section title="Acceptable use">
        <p>
          Publish and install BriefAgents in good faith. The following get accounts suspended and
          content removed: publishing malicious content or content designed to exfiltrate data or
          harvest credentials; attempting to evade or defeat the scanning gate, quarantine, or
          review; impersonating people or organizations; probing, disrupting, or overloading the
          service; and anything unlawful.
        </p>
      </Section>

      <Section title="Your content">
        <p>
          You own what you publish and warrant that you have the right to distribute it under the
          license you declare. By publishing you grant us the license we need to operate: to host,
          scan, sign, display, and distribute your content, and to retain published versions
          immutably so installed copies keep verifying. Public content is public; withdrawing a
          version (yanking) stops new installs but does not reach into existing ones.
        </p>
      </Section>

      <Section title="Scanning is not a warranty">
        <p>
          Every published version is scanned and signed. Scanning reduces risk; it does not and
          cannot prove any BriefAgent safe, and we make no such promise. Read the security report
          and the declared capabilities; installing and running anything from the registry is your
          decision and your responsibility.
        </p>
      </Section>

      <Section title="Enforcement">
        <p>
          We may quarantine, block, or remove content and suspend or terminate accounts to protect
          users and the service — including on reports from third parties. Trust-and-safety records
          (advisories, abuse reports) outlive the content they concern. Where practical we say what
          happened rather than making content vanish silently.
        </p>
      </Section>

      <Section title="The service itself">
        <p>
          The service is provided <em>as is</em> and <em>as available</em>, without warranties of
          any kind, express or implied. To the maximum extent the law allows, we are not liable for
          indirect, incidental, special, or consequential damages, or for loss of data, profits, or
          business, arising from your use of the service — including from any BriefAgent you
          install or run. We may change or discontinue features; for material changes to these
          terms we will post notice on the site before they take effect.
        </p>
      </Section>

      <Section title="Termination">
        <p>
          You can delete your account at any time (see the{" "}
          <Link href="/privacy" className="underline">
            Privacy Policy
          </Link>{" "}
          for what deletion does to published content). We can suspend or terminate accounts that
          violate these terms. Sections that by their nature survive — content licenses for
          published versions, disclaimers, liability limits — survive.
        </p>
      </Section>

      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        © {SITE.copyrightYear} {SITE.brand}. Questions? Email{" "}
        <a href={`mailto:${SITE.contactEmail}`} className="underline">
          {SITE.contactEmail}
        </a>
        .
      </p>
    </div>
  );
}

import type { Metadata } from "next";
import Link from "next/link";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: `How ${SITE.brand} handles your data.`,
};

// Privacy policy (§10 legal surface). Minimalist on purpose: this registry
// collects personal information exactly once — at sign-up — and the policy's
// job is to say that plainly, plus the small print that keeps it honest
// (operational logs, the email provider, what deletion really does).
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

export default function PrivacyPage() {
  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">Privacy Policy</h1>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Last updated {UPDATED}. The operator of this {SITE.brand} registry is the data
          controller; reach them at{" "}
          <a href={`mailto:${SITE.contactEmail}`} className="underline">
            {SITE.contactEmail}
          </a>
          .
        </p>
      </header>

      <Section title="What we collect, and when">
        <p>
          The only personal information we collect and store is what you give us <strong>when you
          sign up</strong>: a username, a display name, an email address, and a password. The
          password is held by the account directory as a hash; we never see or store it in plain
          text. Nothing else you do on the site adds personal information to your account — no
          profiling, no enrichment, no purchase of data about you.
        </p>
        <p>
          Like any web service, our servers keep short-lived <strong>operational logs</strong>{" "}
          (including IP addresses) for security, abuse prevention, and rate limiting. They are used
          for nothing else and age out on a fixed schedule.
        </p>
      </Section>

      <Section title="What we use it for">
        <p>
          To operate your account: signing you in, confirming your email address, resetting your
          password, and sending the messages the service requires — email confirmation, password
          reset, and security or review notices about content you published. We do not send
          marketing email.
        </p>
      </Section>

      <Section title="What is public by design">
        <p>
          BriefAgents you publish publicly — their content, security reports, version history, and
          your username as the publisher — are public. That is the product. Publishing is always an
          explicit act; nothing becomes public as a side effect.
        </p>
      </Section>

      <Section title="Cookies">
        <p>
          We use only strictly necessary cookies: your session, a CSRF token, the short-lived state
          of a sign-in in progress, and the one that remembers you dismissed the cookie notice.
          There are no advertising, analytics, or cross-site tracking cookies of any kind.
        </p>
      </Section>

      <Section title="Who else touches your data">
        <p>
          Our email delivery provider processes your email address to deliver the messages above —
          that is the only personal data that leaves our infrastructure, and only for that purpose.
          We do not sell or share personal data with anyone else, and we disclose it only if the
          law compels us to.
        </p>
      </Section>

      <Section title="Your rights">
        <p>
          You can access and correct your account details in Settings, and delete your account at
          any time. Deletion removes your personal information from the registry and deletes your
          sign-in account in our directory service in the same step; if you published public BriefAgents,
          you choose whether they are withdrawn or transferred, and the published records are
          pseudonymized rather than erased — installed copies depend on their integrity. Depending
          on where you live you may have additional rights (access, portability, erasure,
          complaint to a supervisory authority); write to us and we will honour them.
        </p>
      </Section>

      <Section title="Retention">
        <p>
          Account information lives as long as your account. Operational logs and audit records are
          kept for a bounded period for security, then purged. Published public content persists,
          pseudonymized, for the reasons above.
        </p>
      </Section>

      <Section title="Changes">
        <p>
          If this policy changes in a way that matters, we will say so on the site before it takes
          effect. The date at the top is the honest record.
        </p>
      </Section>

      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        See also the{" "}
        <Link href="/terms" className="underline">
          Terms of Service
        </Link>
        .
      </p>
    </div>
  );
}

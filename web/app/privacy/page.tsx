import type { Metadata } from "next";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: `How ${SITE.brand} handles your data.`,
};

const SECTIONS = [
  ["Information we collect", "Account details you provide, the agents and versions you publish, and operational logs needed to run the service securely."],
  ["How we use it", "To operate the registry, scan and sign published versions, prevent abuse, and communicate with you about your account."],
  ["Sharing", "We do not sell personal data. Public agents and their security reports are, by design, public."],
  ["Your rights", "You may access, correct, export, or delete your account data; account deletion pseudonymizes your records while preserving the immutability that installed consumers rely on."],
  ["Retention", "Operational and audit records are retained for a limited period and then archived or purged."],
];

export default function PrivacyPage() {
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">Privacy Policy</h1>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Draft — this summary will be replaced by the full policy before general availability.
        </p>
      </header>
      <div className="flex flex-col gap-5">
        {SECTIONS.map(([h, b]) => (
          <section key={h}>
            <h2 className="font-medium">{h}</h2>
            <p className="mt-1 text-sm leading-relaxed" style={{ color: "var(--color-muted)" }}>
              {b}
            </p>
          </section>
        ))}
      </div>
      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        Questions about privacy? Email{" "}
        <a href={`mailto:${SITE.contactEmail}`} className="underline">
          {SITE.contactEmail}
        </a>
        .
      </p>
    </div>
  );
}

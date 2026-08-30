import type { Metadata } from "next";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: `The terms governing use of ${SITE.brand}.`,
};

const SECTIONS = [
  ["Acceptable use", "Publish and install BriefAgents in good faith. Malicious BriefAgents, attempts to evade the scanning gate, and abuse of the platform are prohibited."],
  ["Your content", "You retain ownership of what you publish and are responsible for having the rights to distribute it under the license you declare."],
  ["Security scanning", "Every published version is scanned and signed. Scanning reduces risk but does not warrant that any BriefAgent is safe; you install at your own discretion."],
  ["Availability", "The service is provided on an as-is basis. We work to keep it available and secure but do not guarantee uninterrupted operation."],
  ["Changes", "These terms will evolve as the product matures; material changes will be announced."],
];

export default function TermsPage() {
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">Terms of Service</h1>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          Draft — this summary will be replaced by the full terms before general availability.
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
        © {SITE.copyrightYear} {SITE.brand}. Questions? Email{" "}
        <a href={`mailto:${SITE.contactEmail}`} className="underline">
          {SITE.contactEmail}
        </a>
        .
      </p>
    </div>
  );
}

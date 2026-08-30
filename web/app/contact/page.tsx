import type { Metadata } from "next";
import { Card } from "@/components/ui";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: "Contact",
  description: `Get in touch with the ${SITE.brand} team.`,
};

const CHANNELS = [
  {
    title: "General enquiries",
    body: "Questions about the product, partnerships, or press.",
    email: SITE.contactEmail,
  },
  {
    title: "Security",
    body: "Report a vulnerability in the platform, or abuse of a hosted BriefAgent. Please do not open a public issue for a security report.",
    email: SITE.securityEmail,
  },
];

export default function ContactPage() {
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <header>
        <h1 className="text-3xl font-semibold tracking-tight">Contact us</h1>
        <p className="mt-3 text-lg" style={{ color: "var(--color-muted)" }}>
          We would like to hear from you. Reach the right team below.
        </p>
      </header>
      <div className="grid gap-4 sm:grid-cols-2">
        {CHANNELS.map((c) => (
          <Card key={c.title}>
            <div className="font-medium">{c.title}</div>
            <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
              {c.body}
            </p>
            <a href={`mailto:${c.email}`} className="mt-3 inline-block text-sm underline">
              {c.email}
            </a>
          </Card>
        ))}
      </div>
      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        A contact form and support portal are on the way. In the meantime, email is the fastest way
        to reach us.
      </p>
    </div>
  );
}

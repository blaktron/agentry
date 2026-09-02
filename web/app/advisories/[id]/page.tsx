import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Badge, Card } from "@/components/ui";
import { apiGet, type Advisory } from "@/lib/api";
import { fmtUTCDate } from "@/lib/format";

// One advisory's permalink (agentry#24). The API only resolves advisories
// against public agents, so a private agent's advisory is a 404 here too.
export const metadata: Metadata = { title: "Advisory" };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function AdvisoryPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const adv = await apiGet<Advisory>(`/advisories/${id}`, { revalidate: 60 }).catch(() => null);
  if (!adv) notFound();
  const agent = adv.agent ?? "";
  return (
    <div className="max-w-3xl space-y-6">
      <header>
        <p className="text-sm">
          <Link href="/advisories" className="underline" style={{ color: "var(--color-accent)" }}>
            Advisories
          </Link>
        </p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">
          <Badge tone="danger">{adv.severity}</Badge> {adv.summary}
        </h1>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          {agent && (
            <>
              Affects{" "}
              <Link href={`/${agent}`} className="font-mono underline">
                {agent}
              </Link>{" "}
              versions <span className="font-mono">{adv.affectedVersions}</span>
            </>
          )}
          {adv.publishedAt && <> · published {fmtUTCDate(adv.publishedAt)}</>}
        </p>
      </header>
      {adv.detail && (
        <Card>
          <p className="whitespace-pre-wrap text-sm">{adv.detail}</p>
        </Card>
      )}
      <Card tone="secondary">
        <p className="text-sm" style={{ color: "var(--color-muted)" }}>
          A quarantined version stops resolving for new installs and warns on direct download; a copy
          already installed stays where it is. Check the BriefAgent page for the current state and its
          security report.
        </p>
      </Card>
    </div>
  );
}

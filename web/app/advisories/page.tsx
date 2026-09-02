import Link from "next/link";
import type { Metadata } from "next";
import { Badge, Card } from "@/components/ui";
import { apiGet, type Advisory } from "@/lib/api";
import { fmtUTCDate } from "@/lib/format";

export const metadata: Metadata = {
  title: "Advisories",
  description: "Security advisories published against BriefAgents on this registry.",
};

export const dynamic = "force-dynamic";

// Advisories index (§10.1): the global feed — every published advisory
// against a public BriefAgent, newest first (agentry#24; DEV-038 recorded
// the gap) — followed by the explainer.
export default async function AdvisoriesPage() {
  const feed = (await apiGet<Advisory[]>("/advisories?limit=50", { revalidate: 60 }).catch(() => null)) ?? [];
  return (
    <div className="max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Advisories</h1>
        <p className="mt-2" style={{ color: "var(--color-muted)" }}>
          When a rescan or a valid abuse report surfaces a new high-severity
          finding on a published version, that version is quarantined and an
          advisory is raised against it. This is every advisory published
          against a public BriefAgent, newest first.
        </p>
      </header>

      <Card>
        <h2 className="font-medium">Published advisories</h2>
        {feed.length === 0 ? (
          <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
            None so far. When one is published it appears here and on the affected BriefAgent&apos;s
            page.
          </p>
        ) : (
          <ul className="mt-3 divide-y" style={{ borderColor: "var(--color-border)" }}>
            {feed.map((adv) => (
              <li key={adv.id} className="py-3 text-sm">
                <div className="flex flex-wrap items-baseline gap-2">
                  <Badge tone="danger">{adv.severity}</Badge>
                  <Link href={`/advisories/${adv.id}`} className="font-medium hover:underline">
                    {adv.summary}
                  </Link>
                </div>
                <div className="mt-1 text-xs" style={{ color: "var(--color-muted)" }}>
                  {adv.agent && (
                    <>
                      <Link href={`/${adv.agent}`} className="font-mono underline">
                        {adv.agent}
                      </Link>{" "}
                      · affects {adv.affectedVersions}
                    </>
                  )}
                  {adv.publishedAt && <> · {fmtUTCDate(adv.publishedAt)}</>}
                </div>
              </li>
            ))}
          </ul>
        )}
        {feed.length >= 50 && (
          <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
            Showing the latest 50. The API pages further:{" "}
            <code>GET /api/v1/advisories?cursor=…</code>.
          </p>
        )}
      </Card>

      <Card>
        <h2 className="font-medium">How you find out</h2>
        <ul className="mt-2 space-y-2 text-sm" style={{ color: "var(--color-muted)" }}>
          <li>
            <strong>On the BriefAgent page.</strong> Advisories appear on the affected BriefAgent, alongside its
            security report. Check there before installing or upgrading.
          </li>
          <li>
            <strong>By webhook.</strong> Organizations can subscribe to{" "}
            <code>advisory.published</code> and <code>agent.quarantined</code> and route them wherever
            they already watch for supply-chain events.
          </li>
          <li>
            <strong>By API.</strong> <code>GET /api/v1/advisories</code> is this feed (keyset-paged);{" "}
            <code>?affecting=namespace/name</code> narrows it to one BriefAgent.
          </li>
        </ul>
      </Card>

      <Card>
        <h2 className="font-medium">What we cannot do</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          We cannot reach into an installation. A quarantined version stops resolving for new
          installs and warns on direct download, but a copy already on your disk stays there. That
          is why advisories and webhooks exist, and why pinning versions in a lockfile you review is
          worth the trouble.
        </p>
      </Card>

      <p className="text-sm">
        <Link href="/trust" className="underline" style={{ color: "var(--color-accent)" }}>
          How rescanning and quarantine work
        </Link>
      </p>
    </div>
  );
}

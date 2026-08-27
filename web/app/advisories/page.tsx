import Link from "next/link";
import type { Metadata } from "next";
import { Card } from "@/components/ui";

export const metadata: Metadata = {
  title: "Advisories",
  description: "Security advisories published against agents on this registry.",
};

// Advisories index (§10.1). Advisories are queried per agent by the API, so
// this page explains the model and routes people to the agent they care
// about rather than pretending to be a global feed we do not yet serve.
export default function AdvisoriesPage() {
  return (
    <div className="max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Advisories</h1>
        <p className="mt-2" style={{ color: "var(--color-muted)" }}>
          When a rescan or a valid abuse report surfaces a new high-severity
          finding on a version that is already published, that version is
          quarantined and an advisory is raised against it.
        </p>
      </header>

      <Card>
        <h2 className="font-medium">How you find out</h2>
        <ul className="mt-2 space-y-2 text-sm" style={{ color: "var(--color-muted)" }}>
          <li>
            <strong>On the agent page.</strong> Advisories appear on the affected agent, alongside its
            security report. Check there before installing or upgrading.
          </li>
          <li>
            <strong>By webhook.</strong> Organizations can subscribe to{" "}
            <code>advisory.published</code> and <code>agent.quarantined</code> and route them wherever
            they already watch for supply-chain events.
          </li>
          <li>
            <strong>By API.</strong>{" "}
            <code>GET /api/v1/advisories?affecting=namespace/name</code>
          </li>
        </ul>
      </Card>

      <Card>
        <h2 className="font-medium">What we cannot do</h2>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
          We cannot reach into an installation. A quarantined version stops resolving for new
          installs and warns on direct download, but a copy already on your disk stays there — which
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

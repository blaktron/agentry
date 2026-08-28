import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Badge, Card, KindBadge } from "@/components/ui";
import type { Agent, ReviewItem } from "@/lib/api";
import { authedGet, currentUser, reviewerOrgs } from "@/lib/session";

export const metadata: Metadata = { title: "Dashboard" };

// Authed dashboard (§10.1): my agents across namespaces and the review work
// assigned to me. Publishing and settings stay with the CLI/API; the page
// links out to the public views which carry the full report cards.
export default async function DashboardPage() {
  const user = await currentUser();
  if (!user) redirect("/login?next=/dashboard");

  const namespaces = [user.handle, ...(user.orgs ?? []).map((o) => o.handle)];
  const agentLists = await Promise.all(
    namespaces.map((ns) =>
      authedGet<Agent[]>(`/agents?namespace=${encodeURIComponent(ns)}`)
        .then((a) => ({ ns, agents: a ?? [] }))
        .catch(() => ({ ns, agents: [] as Agent[] })),
    ),
  );

  const revOrgs = reviewerOrgs(user);
  const queues = await Promise.all([
    ...(user.platformStaff
      ? [
          authedGet<ReviewItem[]>("/review-queue?queue=platform&limit=100")
            .then((items) => ({ label: "platform", items: items ?? [] }))
            .catch(() => ({ label: "platform", items: [] as ReviewItem[] })),
        ]
      : []),
    ...revOrgs.map((o) =>
      authedGet<ReviewItem[]>(`/review-queue?queue=org&org=${encodeURIComponent(o.handle)}&limit=100`)
        .then((items) => ({ label: o.handle, items: items ?? [] }))
        .catch(() => ({ label: o.handle, items: [] as ReviewItem[] })),
    ),
  ]);
  const pendingReview = queues.reduce((n, q) => n + q.items.length, 0);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Dashboard</h1>
        <p className="text-sm" style={{ color: "var(--color-muted)" }}>
          signed in as <strong>{user.handle}</strong>
          {user.emailVerified ? "" : " · email not verified"}
        </p>
      </div>

      {(user.platformStaff || revOrgs.length > 0) && (
        <Card>
          <h2 className="mb-1 font-semibold">Review work</h2>
          {pendingReview === 0 ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              No versions are waiting on you.
            </p>
          ) : (
            <ul className="text-sm">
              {queues
                .filter((q) => q.items.length > 0)
                .map((q) => (
                  <li key={q.label}>
                    <Link
                      href={q.label === "platform" ? "/review?queue=platform" : `/review?queue=org&org=${encodeURIComponent(q.label)}`}
                      className="underline"
                    >
                      {q.label}: {q.items.length} pending
                    </Link>
                  </li>
                ))}
            </ul>
          )}
        </Card>
      )}

      {agentLists.map(({ ns, agents }) => (
        <Card key={ns}>
          <h2 className="mb-2 font-semibold">
            <Link href={`/${ns}`} className="hover:underline">
              {ns}
            </Link>{" "}
            <span className="text-sm font-normal" style={{ color: "var(--color-muted)" }}>
              {agents.length} agent{agents.length === 1 ? "" : "s"}
            </span>
          </h2>
          {agents.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              No agents yet — create one with <code>agentry init</code> and{" "}
              <code>agentry publish</code>.
            </p>
          ) : (
            <ul className="flex flex-col gap-2 text-sm">
              {agents.map((a) => (
                <li key={a.id} className="flex flex-wrap items-center gap-2">
                  <Link href={`/${a.namespace}/${a.name}`} className="font-medium hover:underline">
                    {a.namespace}/{a.name}
                  </Link>
                  <KindBadge kind={a.kind} />
                  {a.visibility === "private" && <Badge>private</Badge>}
                  {a.quarantineState !== "none" && <Badge tone="danger">{a.quarantineState}</Badge>}
                  <span className="truncate" style={{ color: "var(--color-muted)" }}>
                    {a.summary}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      ))}
    </div>
  );
}

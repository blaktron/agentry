import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Badge, Card, KindBadge } from "@/components/ui";
import type { ActivityPage, Agent, ReviewItem } from "@/lib/api";
import { fmtUTC } from "@/lib/format";
import { adminOrgs, authedGet, currentUser, reviewerOrgs } from "@/lib/session";

export const metadata: Metadata = { title: "Dashboard" };

// A namespace's agents, or the reason we could not say. An empty list and a
// failed request look identical once both become `[]`, and "No BriefAgents yet"
// is a much worse lie than "we could not read this".
type NamespaceAgents = { ns: string; agents: Agent[]; failed: boolean };

// ACTION_LABEL turns the audit action ids (internal/audit/actions.go) into
// something readable. Unknown ids fall through to the raw id rather than
// being dropped: an activity feed that silently omits events it does not
// recognise is worse than one that shows a name you have to look up.
const ACTION_LABEL: Record<string, string> = {
  "agent.create": "created",
  "agent.update": "settings changed",
  "agent.grant_set": "grant set",
  "agent.grant_remove": "grant removed",
  "agent.quarantine": "quarantined",
  "agent.block": "blocked",
  "agent.reinstate": "reinstated",
  "agent.delete": "deleted",
  "agent.transfer": "transferred",
  "repo.push": "pushed to repo",
  "version.submit": "submitted",
  "version.transition": "changed state",
  "version.yank": "yanked",
  "review.decision": "review decided",
  "finding.verdict": "finding verdict recorded",
  "advisory.publish": "advisory published",
  "abuse.report": "reported for abuse",
  "abuse.triage": "abuse report triaged",
};

// Authed dashboard (§10.1): my agents across namespaces, recent activity on
// them, and the review work assigned to me.
export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ ok?: string; error?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/dashboard");
  const q = await searchParams;

  const namespaces = [user.handle, ...(user.orgs ?? []).map((o) => o.handle)];
  const agentLists: NamespaceAgents[] = await Promise.all(
    namespaces.map((ns) =>
      authedGet<Agent[]>(`/agents?namespace=${encodeURIComponent(ns)}`)
        .then((a) => ({ ns, agents: a ?? [], failed: false }))
        .catch(() => ({ ns, agents: [] as Agent[], failed: true })),
    ),
  );

  // Recent activity, one API round per agent, capped: the §9.2 activity
  // endpoint is per-agent, and a dashboard is not worth an unbounded fan-out.
  // The cap is on the number of agents queried, not on what is shown.
  const recentAgents = agentLists
    .flatMap((l) => l.agents)
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
    .slice(0, 6);
  const activity = (
    await Promise.all(
      recentAgents.map((a) =>
        authedGet<ActivityPage>(
          `/agents/${encodeURIComponent(a.namespace)}/${encodeURIComponent(a.name)}/activity?limit=5`,
        )
          .then((p) => (p?.events ?? []).map((e) => ({ ...e, agent: `${a.namespace}/${a.name}` })))
          .catch(() => []),
      ),
    )
  )
    .flat()
    .sort((x, y) => (x.occurredAt < y.occurredAt ? 1 : -1))
    .slice(0, 12);

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
  const pendingReview = queues.reduce((n, qu) => n + qu.items.length, 0);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Dashboard</h1>
        <div className="flex items-baseline gap-3 text-sm">
          <Link href="/new" className="underline">
            New BriefAgent
          </Link>
          <Link href="/settings" className="underline">
            Settings
          </Link>
          <span style={{ color: "var(--color-muted)" }}>
            signed in as <strong>{user.handle}</strong>
            {user.emailVerified ? "" : " · email not verified"}
          </span>
        </div>
      </div>

      {q.ok && (
        <p role="status" className="rounded-md border px-3 py-2 text-sm" style={{ borderColor: "var(--color-ok)", color: "var(--color-ok)" }}>
          {q.ok}
        </p>
      )}
      {q.error && (
        <p role="alert" className="rounded-md border px-3 py-2 text-sm" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
          {q.error}
        </p>
      )}

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
                .filter((qu) => qu.items.length > 0)
                .map((qu) => (
                  <li key={qu.label}>
                    <Link
                      href={qu.label === "platform" ? "/review?queue=platform" : `/review?queue=org&org=${encodeURIComponent(qu.label)}`}
                      className="underline"
                    >
                      {qu.label}: {qu.items.length} pending
                    </Link>
                  </li>
                ))}
            </ul>
          )}
        </Card>
      )}

      {activity.length > 0 && (
        <Card>
          <h2 className="mb-2 font-semibold">Recent activity</h2>
          <ul className="flex flex-col gap-1 text-sm">
            {activity.map((e) => (
              <li key={e.id} className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-xs whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                  {fmtUTC(e.occurredAt)}
                </span>
                <Link href={`/${e.agent}`} className="font-medium hover:underline">
                  {e.agent}
                </Link>
                <span>{ACTION_LABEL[e.action] ?? e.action}</span>
                {e.version && <Badge>{e.version}</Badge>}
                {e.actorHandle && (
                  <span className="text-xs" style={{ color: "var(--color-muted)" }}>
                    by {e.actorHandle}
                  </span>
                )}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
            Drawn from the audit log for your most recently created agents.
          </p>
        </Card>
      )}

      {agentLists.map(({ ns, agents, failed }) => (
        <Card key={ns}>
          <h2 className="mb-2 font-semibold">
            <Link href={`/${ns}`} className="hover:underline">
              {ns}
            </Link>{" "}
            <span className="text-sm font-normal" style={{ color: "var(--color-muted)" }}>
              {failed ? "unavailable" : `${agents.length} agent${agents.length === 1 ? "" : "s"}`}
            </span>
            {adminOrgs(user).some((o) => o.handle === ns) && (
              <>
                {" · "}
                <Link href={`/orgs/${ns}/admin`} className="text-sm font-normal underline">
                  admin
                </Link>
              </>
            )}
          </h2>
          {failed ? (
            <p className="text-sm" style={{ color: "var(--color-sev-medium)" }}>
              The registry did not answer for this namespace, so we cannot say what is in it. This is
              not the same as it being empty. Reload to try again.
            </p>
          ) : agents.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              No BriefAgents yet. Create one with <code>agentry init</code> and{" "}
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
                  <Link href={`/${a.namespace}/${a.name}/publish`} className="text-xs underline">
                    publish
                  </Link>
                  <Link href={`/${a.namespace}/${a.name}/settings`} className="text-xs underline">
                    settings
                  </Link>
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

import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Badge, Card } from "@/components/ui";
import type { ReviewItem } from "@/lib/api";
import { AccessError, authedGet, currentUser, reviewerOrgs } from "@/lib/session";

export const metadata: Metadata = { title: "Review queue" };

// Review queue (§10.1 Reviewer row): pending versions gated to human review.
// Platform staff see the platform queue; org security reviewers see their
// orgs' queues. Selection via ?queue=platform|org&org=<handle>.
export default async function ReviewQueuePage({
  searchParams,
}: {
  searchParams: Promise<{ queue?: string; org?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/review");
  const orgs = reviewerOrgs(user);
  const canPlatform = user.platformStaff === true;
  if (!canPlatform && orgs.length === 0) {
    return (
      <Card>
        <p>
          Reviewing requires the <strong>security_reviewer</strong> role in an organization, or
          platform staff. Your account has neither.
        </p>
      </Card>
    );
  }

  const params = await searchParams;
  const queue = params.queue === "org" || !canPlatform ? "org" : "platform";
  const org = queue === "org" ? (params.org ?? orgs[0]?.handle) : undefined;

  let items: ReviewItem[] = [];
  let denied = false;
  try {
    const qs = queue === "org" ? `queue=org&org=${encodeURIComponent(org ?? "")}` : "queue=platform";
    items = (await authedGet<ReviewItem[]>(`/review-queue?${qs}&limit=100`)) ?? [];
  } catch (e) {
    if (e instanceof AccessError) denied = true;
    else throw e;
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Review queue</h1>
        <nav className="flex gap-2 text-sm" aria-label="Queues">
          {canPlatform && (
            <Link
              href="/review?queue=platform"
              className={`rounded-md border px-2 py-1 ${queue === "platform" ? "font-semibold" : ""}`}
              style={{ borderColor: "var(--color-border)" }}
            >
              Platform
            </Link>
          )}
          {orgs.map((o) => (
            <Link
              key={o.handle}
              href={`/review?queue=org&org=${encodeURIComponent(o.handle)}`}
              className={`rounded-md border px-2 py-1 ${queue === "org" && org === o.handle ? "font-semibold" : ""}`}
              style={{ borderColor: "var(--color-border)" }}
            >
              {o.handle}
            </Link>
          ))}
        </nav>
      </div>

      {denied ? (
        <Card>
          <p>You do not have access to this queue.</p>
        </Card>
      ) : items.length === 0 ? (
        <Card>
          <p style={{ color: "var(--color-muted)" }}>
            Queue is empty — nothing is waiting for human review.
          </p>
        </Card>
      ) : (
        <Card className="p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
                <th className="px-4 py-2 font-medium">Version</th>
                <th className="px-4 py-2 font-medium">Queue</th>
                <th className="px-4 py-2 font-medium">Submitted</th>
                <th className="px-4 py-2 font-medium" aria-label="actions"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.id} className="border-b last:border-0" style={{ borderColor: "var(--color-border)" }}>
                  <td className="px-4 py-2 font-medium">
                    <Link href={`/review/${it.id}`} className="hover:underline">
                      {`${it.namespace}/${it.agent}@${it.version}`}
                    </Link>
                  </td>
                  <td className="px-4 py-2">
                    <Badge tone={it.queue === "platform" ? "accent" : "neutral"}>{it.queue}</Badge>
                  </td>
                  <td className="px-4 py-2" style={{ color: "var(--color-muted)" }}>
                    {it.createdAt ? new Date(it.createdAt).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <Link href={`/review/${it.id}`} className="underline">
                      Open
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        A pending item blocks its version from publishing until a reviewer decides (§7 — the gate
        fails closed). Authors can never decide their own versions.
      </p>
    </div>
  );
}

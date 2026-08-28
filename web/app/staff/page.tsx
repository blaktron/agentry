import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Badge, Card } from "@/components/ui";
import type { AbuseReport, ReviewItem } from "@/lib/api";
import { RevealText } from "@/lib/reveal";
import { AccessError, authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Trust & safety" };

const STATES = ["open", "triaged", "actioned", "dismissed"] as const;

// Platform T&S console (§10.1 Platform staff row): the platform review
// queue, abuse-report triage, and the quarantine console. Staff-only — the
// API enforces it; this page just renders the refusal honestly.
export default async function StaffPage({
  searchParams,
}: {
  searchParams: Promise<{ state?: string; ok?: string; error?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/staff");
  const q = await searchParams;
  const state = (STATES as readonly string[]).includes(q.state ?? "") ? q.state! : "open";

  let queue: ReviewItem[] = [];
  let reports: AbuseReport[] = [];
  try {
    [queue, reports] = await Promise.all([
      authedGet<ReviewItem[]>("/review-queue?queue=platform&limit=100").then((r) => r ?? []),
      authedGet<AbuseReport[]>(`/platform/abuse-reports?state=${state}&limit=100`).then((r) => r ?? []),
    ]);
  } catch (e) {
    if (e instanceof AccessError) {
      return (
        <Card>
          <p>The trust &amp; safety console is platform-staff only.</p>
        </Card>
      );
    }
    throw e;
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">Trust &amp; safety</h1>

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

      <Card>
        <h2 className="mb-1 font-semibold">Platform review queue</h2>
        <p className="text-sm">
          {queue.length === 0 ? (
            <span style={{ color: "var(--color-muted)" }}>Empty — nothing awaiting platform review.</span>
          ) : (
            <>
              <strong>{queue.length}</strong> version{queue.length === 1 ? "" : "s"} waiting.{" "}
              <Link href="/review?queue=platform" className="underline">
                Work the queue
              </Link>
            </>
          )}
        </p>
      </Card>

      <Card>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="font-semibold">Abuse reports</h2>
          <nav className="flex gap-2 text-sm" aria-label="Report states">
            {STATES.map((s) => (
              <Link
                key={s}
                href={`/staff?state=${s}`}
                className={`rounded-md border px-2 py-1 ${state === s ? "font-semibold" : ""}`}
                style={{ borderColor: "var(--color-border)" }}
              >
                {s}
              </Link>
            ))}
          </nav>
        </div>
        {reports.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            No {state} reports.
          </p>
        ) : (
          <ul className="flex flex-col gap-4">
            {reports.map((rep) => (
              <li key={rep.id} className="border-b pb-4 last:border-0 last:pb-0" style={{ borderColor: "var(--color-border)" }}>
                <div className="flex flex-wrap items-center gap-2">
                  <Link href={`/${rep.namespace}/${rep.agent}`} className="font-medium hover:underline">
                    {rep.namespace}/{rep.agent}
                  </Link>
                  {rep.version && <Badge>{rep.version}</Badge>}
                  <Badge tone="warn">{rep.category}</Badge>
                  <Badge>{rep.state}</Badge>
                  <span className="text-xs" style={{ color: "var(--color-muted)" }}>
                    {new Date(rep.createdAt).toLocaleString()}
                  </span>
                </div>
                <p className="excerpt mt-1 text-sm">
                  <RevealText text={rep.detail} />
                </p>
                {rep.state === "open" && (
                  <form
                    method="post"
                    action={`/staff/abuse/${rep.id}/triage`}
                    className="mt-2 flex flex-wrap items-end gap-2 text-sm"
                  >
                    <label className="grow">
                      <span className="sr-only">Resolution</span>
                      <input
                        name="resolution"
                        required
                        placeholder="Resolution (required, audited)"
                        className="w-full rounded-md border px-2 py-1 text-xs"
                        style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
                      />
                    </label>
                    <button type="submit" name="state" value="triaged" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                      Triaged
                    </button>
                    <button type="submit" name="state" value="actioned" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                      Actioned
                    </button>
                    <button type="submit" name="state" value="dismissed" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                      Dismiss
                    </button>
                  </form>
                )}
              </li>
            ))}
          </ul>
        )}
        <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
          Triage records the outcome. Enforcement (quarantine/block) is a separate action below so
          its audit trail names the agent (§8.7).
        </p>
      </Card>

      <Card>
        <h2 className="mb-2 font-semibold">Agent enforcement</h2>
        <form method="post" action="/staff/agent-action" className="flex flex-wrap items-end gap-2 text-sm">
          <label>
            Agent
            <input
              name="ref"
              required
              placeholder="namespace/name"
              pattern="[^/]+/[^/]+"
              className="mt-1 rounded-md border px-2 py-1 font-mono text-xs"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <label className="grow">
            Reason (audited, shown on the public page)
            <input
              name="reason"
              required
              className="mt-1 w-full rounded-md border px-2 py-1 text-xs"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <button type="submit" name="action" value="quarantine" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-sev-medium)", color: "var(--color-sev-medium)" }}>
            Quarantine
          </button>
          <button type="submit" name="action" value="block" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
            Block
          </button>
          <button type="submit" name="action" value="reinstate" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-ok)", color: "var(--color-ok)" }}>
            Reinstate
          </button>
        </form>
        <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
          Quarantine hides the agent from search/resolve and quarantines its published versions;
          block additionally refuses downloads. Reinstate returns it to normal (§7). Mass-incident
          procedure: docs/ops/runbooks.md.
        </p>
      </Card>
    </div>
  );
}

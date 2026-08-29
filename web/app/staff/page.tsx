import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Badge, Card, RefusalCard } from "@/components/ui";
import type { AbuseReport, AuditPage, ReviewItem } from "@/lib/api";
import { fmtUTC } from "@/lib/format";
import { RevealText } from "@/lib/reveal";
import { AccessError, authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Trust & safety" };

const STATES = ["open", "triaged", "actioned", "dismissed"] as const;
const VIEWS = [
  { id: "triage", label: "Triage" },
  { id: "audit", label: "Cross-org audit" },
] as const;

// Platform T&S console (§10.1 Platform staff row): the platform review
// queue, abuse-report triage, the quarantine console, and the cross-org
// audit view (§12.6). Staff-only — the API enforces it; this page just
// renders the refusal honestly.
export default async function StaffPage({
  searchParams,
}: {
  searchParams: Promise<{
    state?: string;
    view?: string;
    action?: string;
    org?: string;
    cursor?: string;
    ok?: string;
    error?: string;
  }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/staff");
  const q = await searchParams;
  const state = (STATES as readonly string[]).includes(q.state ?? "") ? q.state! : "open";
  const view = VIEWS.some((v) => v.id === q.view) ? q.view! : "triage";

  let queue: ReviewItem[] = [];
  let reports: AbuseReport[] = [];
  try {
    [queue, reports] = await Promise.all([
      authedGet<ReviewItem[]>("/review-queue?queue=platform&limit=100").then((r) => r ?? []),
      authedGet<AbuseReport[]>(`/platform/abuse-reports?state=${state}&limit=100`).then((r) => r ?? []),
    ]);
  } catch (e) {
    if (e instanceof AccessError) {
      return <RefusalCard>The trust &amp; safety console is platform-staff only.</RefusalCard>;
    }
    throw e;
  }

  // The audit slice is fetched only when its tab is open: §12.6 records one
  // audit.platform_read event per call, so browsing another tab must not
  // write "staff read the audit log" into the log.
  const auditFilter = new URLSearchParams({ limit: "100" });
  const actionFilter = (q.action ?? "").trim().slice(0, 64);
  const orgFilter = (q.org ?? "").trim().toLowerCase().slice(0, 40);
  if (actionFilter) auditFilter.set("action", actionFilter);
  if (orgFilter) auditFilter.set("org", orgFilter);
  if (q.cursor) auditFilter.set("cursor", q.cursor);
  const audit =
    view === "audit"
      ? await authedGet<AuditPage>(`/platform/audit?${auditFilter.toString()}`).catch(() => null)
      : null;

  const viewHref = (id: string) => (id === "triage" ? "/staff" : `/staff?view=${id}`);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h1 className="text-xl font-semibold">Trust &amp; safety</h1>
        <nav className="flex gap-2 text-sm" aria-label="Console views">
          {VIEWS.map((v) => (
            <Link
              key={v.id}
              href={viewHref(v.id)}
              aria-current={view === v.id ? "page" : undefined}
              className={`rounded-md border px-2 py-1 ${view === v.id ? "font-semibold" : ""}`}
              style={{ borderColor: view === v.id ? "var(--color-accent)" : "var(--color-border)" }}
            >
              {v.label}
            </Link>
          ))}
        </nav>
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

      {view === "audit" ? (
        <Card>
          <h2 className="mb-2 font-semibold">Audit events across every organization</h2>
          <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
            Newest first. Reading this log is itself audited (§12.6): one{" "}
            <code className="text-xs">audit.platform_read</code> event is written per page you load
            here.
          </p>
          <form action="/staff" className="mb-3 flex flex-wrap items-end gap-2 text-sm">
            <input type="hidden" name="view" value="audit" />
            <label>
              Action
              <input
                name="action"
                defaultValue={actionFilter}
                placeholder="version.transition"
                className="mt-1 rounded-md border px-2 py-1 font-mono text-xs"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </label>
            <label>
              Organization
              <input
                name="org"
                defaultValue={orgFilter}
                placeholder="acme"
                className="mt-1 rounded-md border px-2 py-1 text-xs"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </label>
            <button type="submit" className="rounded-md border px-3 py-1.5 text-xs" style={{ borderColor: "var(--color-border)" }}>
              Filter
            </button>
            {(actionFilter || orgFilter) && (
              <Link href="/staff?view=audit" className="text-xs underline">
                clear
              </Link>
            )}
          </form>
          {audit === null ? (
            <p className="text-sm" style={{ color: "var(--color-sev-medium)" }}>
              The platform audit log could not be read.
            </p>
          ) : (audit.events ?? []).length === 0 ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              No events match this filter.
            </p>
          ) : (
            <>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
                    <th className="py-1 pr-4 font-medium">When</th>
                    <th className="py-1 pr-4 font-medium">Actor</th>
                    <th className="py-1 pr-4 font-medium">Action</th>
                    <th className="py-1 font-medium">Target</th>
                  </tr>
                </thead>
                <tbody>
                  {(audit.events ?? []).map((ev) => (
                    <tr key={ev.id} className="border-b last:border-0" style={{ borderColor: "var(--color-border)" }}>
                      <td className="py-1 pr-4 whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                        {fmtUTC(ev.occurredAt)}
                      </td>
                      <td className="py-1 pr-4">
                        {ev.actorHandle ?? <span style={{ color: "var(--color-muted)" }}>{ev.actorKind}</span>}
                      </td>
                      <td className="py-1 pr-4 font-mono text-xs">{ev.action}</td>
                      <td className="py-1 font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                        {ev.targetKind ?? ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {audit.nextCursor && (
                <p className="mt-3 text-sm">
                  <Link
                    href={`/staff?view=audit&cursor=${encodeURIComponent(audit.nextCursor)}${
                      actionFilter ? `&action=${encodeURIComponent(actionFilter)}` : ""
                    }${orgFilter ? `&org=${encodeURIComponent(orgFilter)}` : ""}`}
                    className="underline"
                  >
                    Older events →
                  </Link>
                </p>
              )}
            </>
          )}
        </Card>
      ) : (
        <>
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
                    aria-current={state === s ? "page" : undefined}
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
                        {fmtUTC(rep.createdAt)}
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
            {/* Checked against the handlers rather than repeated from memory:
                the agent flag alone changes nothing a consumer can observe, so
                each action also walks the §7 version state machine. */}
            <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
              Quarantine hides the agent from search and resolution and moves its latest published
              version to <code>quarantined</code> — downloads of it answer 409. Block marks the agent{" "}
              <code>blocked</code> and moves its live versions with it: every download for the agent
              then answers <strong>410 Gone</strong>. Reinstate walks both steps back —{" "}
              <code>blocked</code> to <code>quarantined</code> to <code>published</code> — so a
              blocked agent returns to normal in one action (§7). Mass-incident procedure:
              docs/ops/runbooks.md.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}

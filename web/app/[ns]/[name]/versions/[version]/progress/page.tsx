import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { Card, SeverityBadge, StatusBadge } from "@/components/ui";
import { Refresher } from "@/components/refresher";
import type { AgentVersion, ScanReport } from "@/lib/api";
import { authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Pipeline progress" };

// Live pipeline progress (§10.1 publish flow): the page re-renders itself
// every few seconds while the version is submitted/scanning, then lands on
// the verdict. The §7 states are the truth — this view never invents
// intermediate progress the pipeline didn't report.
const STEPS: { key: string; label: string }[] = [
  { key: "submitted", label: "Submitted" },
  { key: "scanning", label: "Scanning (S1–S10)" },
  { key: "verdict", label: "Verdict" },
];

export default async function ProgressPage({
  params,
  searchParams,
}: {
  params: Promise<{ ns: string; name: string; version: string }>;
  searchParams: Promise<{ ok?: string }>;
}) {
  const { ns, name, version } = await params;
  if (!(await currentUser())) redirect(`/login?next=/${ns}/${name}/versions/${version}/progress`);
  const q = await searchParams;

  const v = await authedGet<AgentVersion>(`/agents/${ns}/${name}/versions/${version}`);
  if (!v) notFound();
  const report = await authedGet<ScanReport>(`/agents/${ns}/${name}/versions/${version}/report`);

  const inFlight = v.status === "submitted" || v.status === "scanning";
  const stepState = (key: string): "done" | "active" | "todo" => {
    if (key === "submitted") return v.status === "submitted" ? "active" : "done";
    if (key === "scanning") {
      if (v.status === "submitted") return "todo";
      return v.status === "scanning" ? "active" : "done";
    }
    return inFlight ? "todo" : "active";
  };

  const counts = report?.findingCounts ?? {};
  const severities = ["critical", "high", "medium", "low", "info"] as const;

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      {inFlight && <Refresher />}
      <h1 className="text-xl font-semibold">
        <Link href={`/${ns}/${name}`} className="hover:underline">
          {`${ns}/${name}`}
        </Link>
        {`@${version}`} — pipeline
      </h1>

      {q.ok && (
        <p role="status" className="rounded-md border px-3 py-2 text-sm" style={{ borderColor: "var(--color-ok)", color: "var(--color-ok)" }}>
          {q.ok}
        </p>
      )}

      <Card>
        <ol className="flex flex-col gap-2">
          {STEPS.map((s) => {
            const st = stepState(s.key);
            return (
              <li key={s.key} className="flex items-center gap-3 text-sm">
                <span
                  aria-hidden
                  className="inline-block h-2.5 w-2.5 rounded-full"
                  style={{
                    background:
                      st === "done" ? "var(--color-ok)" : st === "active" ? "var(--color-accent)" : "var(--color-border)",
                  }}
                />
                <span className={st === "active" ? "font-semibold" : ""}>{s.label}</span>
                {s.key === "verdict" && !inFlight && <StatusBadge status={v.status} />}
              </li>
            );
          })}
        </ol>
        {inFlight ? (
          <p className="mt-3 text-sm" style={{ color: "var(--color-muted)" }}>
            Updating automatically… (or <Link href={`/${ns}/${name}/versions/${version}/progress`} className="underline">refresh</Link>)
          </p>
        ) : (
          <div className="mt-3 flex flex-col gap-2 text-sm">
            {v.statusReason && <p style={{ color: "var(--color-muted)" }}>{v.statusReason}</p>}
            {Object.keys(counts).length > 0 && (
              <p className="flex gap-2">
                {severities
                  .filter((s) => counts[s])
                  .map((s) => (
                    <SeverityBadge key={s} severity={s} count={counts[s]} />
                  ))}
              </p>
            )}
            <p>
              <Link href={`/${ns}/${name}/versions/${version}`} className="underline">
                Full report and provenance
              </Link>
              {v.status === "needs_review" && (
                <span style={{ color: "var(--color-muted)" }}>
                  {" "}
                  — a human reviewer decides next; the version publishes only on approval (§7).
                </span>
              )}
            </p>
          </div>
        )}
      </Card>
    </div>
  );
}

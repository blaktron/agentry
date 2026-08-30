// Security report card + full findings view (§10.2, §10.3). Language is
// deliberately "scanned, N findings, signed" — never "safe" (§1.6.3).
import Link from "next/link";
import type { ScanReport, Severity } from "@/lib/api";
import { fmtUTC } from "@/lib/format";
import { RevealText } from "@/lib/reveal";
import { Badge, Card, SeverityBadge } from "./ui";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function ReportCard({
  report,
  reportHref,
}: {
  report: ScanReport | null;
  reportHref: string;
}) {
  if (!report) {
    return (
      <Card>
        <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
          Security report
        </h2>
        <p className="mt-2 text-sm">No scan on record for this version yet.</p>
      </Card>
    );
  }

  const counts = report.findingCounts ?? {};
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <Card>
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="text-sm font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
          Security report
        </h2>
        <Link href={reportHref} className="text-sm underline" style={{ color: "var(--color-accent)" }}>
          view full report
        </Link>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {total === 0 ? (
          <Badge tone="ok">scanned — 0 findings</Badge>
        ) : (
          present.map((s) => <SeverityBadge key={s} severity={s} count={counts[s]} />)
        )}
      </div>

      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs" style={{ color: "var(--color-muted)" }}>
        {/* The scan date. The page copy has always claimed agent pages show
            "the findings, the ruleset version, and the scan date" — this is
            the third of those, and it is what tells a reader whether the
            report predates the ruleset they care about. */}
        <dt>Scanned</dt>
        <dd>{report.finishedAt ? fmtUTC(report.finishedAt) : "date not recorded"}</dd>
        {report.rulesetVersion && (
          <>
            <dt>Ruleset</dt>
            <dd>{report.rulesetVersion}</dd>
          </>
        )}
        {report.judgeModel && (
          <>
            <dt>Adjudication</dt>
            <dd>{report.judgeModel}</dd>
          </>
        )}
        {report.scanStatus && (
          <>
            <dt>Scan status</dt>
            <dd>{report.scanStatus}</dd>
          </>
        )}
      </dl>

      <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
        Static scanning reduces risk; it cannot prove a BriefAgent safe. Review the declared capabilities
        and the findings before installing.
      </p>
    </Card>
  );
}

// FindingsList renders the full report (§10.1 version page). Excerpts arrive
// pre-escaped from the API with invisible characters rendered visible (§10.3),
// and are displayed as text — never as HTML.
export function FindingsList({ report }: { report: ScanReport }) {
  if (report.findings.length === 0) {
    return (
      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        No findings were recorded for this version.
      </p>
    );
  }
  const ordered = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  return (
    <ul className="space-y-3">
      {ordered.map((f, i) => (
        <li key={f.id ?? `${f.scanner}-${i}`}>
          <Card>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={f.severity} />
              <Badge>{f.confidence} confidence</Badge>
              <code className="text-xs" style={{ color: "var(--color-muted)" }}>
                {f.scanner}
              </code>
              {f.verdict !== "open" && <Badge tone="neutral">{f.verdict.replace(/_/g, " ")}</Badge>}
            </div>
            <p className="mt-2 font-medium">{f.title}</p>
            {/* §8.5: a dismissed finding stays on the public report WITH the
                reviewer's rationale. Rendering the verdict without the reason
                is the same disappearance the rule exists to prevent, so the
                absence is stated rather than hidden. */}
            {f.verdict !== "open" && (
              <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
                Reviewer&apos;s rationale:{" "}
                {f.verdictReason ? <RevealText text={f.verdictReason} /> : <em>none recorded</em>}
              </p>
            )}
            {f.filePath && (
              <p className="mt-1 text-xs" style={{ color: "var(--color-muted)" }}>
                {f.filePath}
                {f.lineStart ? `:${f.lineStart}` : ""}
              </p>
            )}
            {f.excerpt && (
              <pre
                className="excerpt mt-2 overflow-x-auto rounded border px-2 py-1 text-xs"
                style={{ borderColor: "var(--color-border)", background: "var(--color-bg)" }}
              >
                <code>{f.excerpt}</code>
              </pre>
            )}
          </Card>
        </li>
      ))}
    </ul>
  );
}

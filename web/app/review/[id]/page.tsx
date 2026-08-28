import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { Badge, Card, SeverityBadge, StatusBadge } from "@/components/ui";
import type { ReviewBundle, ReviewFileContent, ReviewFileEntry, ScanFinding } from "@/lib/api";
import { RevealText } from "@/lib/reveal";
import { AccessError, authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Review" };

// Review detail (§10.1 Reviewer row): findings with excerpt highlighting,
// the archive file viewer with invisible-character visualization, the
// capability diff against the previous published version, and the decision
// panel. Everything is server-rendered; every mutation is a plain form.

function capLeaves(v: unknown, prefix: string, out: Map<string, string>) {
  if (v === null || v === undefined) return;
  if (typeof v !== "object" || Array.isArray(v)) {
    out.set(prefix, JSON.stringify(v));
    return;
  }
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    capLeaves(val, prefix ? `${prefix}.${k}` : k, out);
  }
}

// diffCaps flattens two capability objects to dotted leaves and marks changes.
function diffCaps(prev: Record<string, unknown> | undefined, curr: Record<string, unknown> | undefined) {
  const a = new Map<string, string>();
  const b = new Map<string, string>();
  capLeaves(prev ?? {}, "", a);
  capLeaves(curr ?? {}, "", b);
  const keys = [...new Set([...a.keys(), ...b.keys()])].sort();
  return keys.map((k) => ({
    key: k,
    before: a.get(k),
    after: b.get(k),
    change: !a.has(k) ? "added" : !b.has(k) ? "removed" : a.get(k) !== b.get(k) ? "changed" : "same",
  }));
}

function findingAnchor(f: ScanFinding, itemID: string): string | null {
  if (!f.filePath) return null;
  const line = f.lineStart ? `#L${f.lineStart}` : "";
  return `/review/${itemID}?file=${encodeURIComponent(f.filePath)}${line}`;
}

export default async function ReviewDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ file?: string; ok?: string; error?: string }>;
}) {
  const { id } = await params;
  if (!(await currentUser())) redirect(`/login?next=/review/${id}`);
  const q = await searchParams;

  let bundle: ReviewBundle | null = null;
  try {
    bundle = await authedGet<ReviewBundle>(`/review-items/${id}`);
  } catch (e) {
    if (e instanceof AccessError) {
      return (
        <Card>
          <p>You do not have access to this review item.</p>
        </Card>
      );
    }
    throw e;
  }
  if (!bundle) notFound();
  const { item, findings } = bundle;

  let files: ReviewFileEntry[] = [];
  try {
    files = (await authedGet<{ files: ReviewFileEntry[] }>(`/review-items/${id}/files`))?.files ?? [];
  } catch {
    // Archive may be missing (conflict) — the page still shows findings.
  }
  const selected = q.file && files.some((f) => f.path === q.file) ? q.file : undefined;
  let content: ReviewFileContent | null = null;
  if (selected) {
    content = await authedGet<ReviewFileContent>(
      `/review-items/${id}/file?path=${encodeURIComponent(selected)}`,
    );
  }

  const fileFindings = selected ? findings.filter((f) => f.filePath === selected) : [];
  const flagged = new Set<number>();
  for (const f of fileFindings) {
    if (f.lineStart) {
      for (let n = f.lineStart; n <= (f.lineEnd ?? f.lineStart); n++) flagged.add(n);
    }
  }
  const findingsByFile = new Map<string, number>();
  for (const f of findings) {
    if (f.filePath) findingsByFile.set(f.filePath, (findingsByFile.get(f.filePath) ?? 0) + 1);
  }

  const caps = diffCaps(
    bundle.previous?.capabilities,
    bundle.versionDetail?.capabilities,
  ).filter((r) => r.change !== "same" || bundle.previous === undefined);
  const capChanges = caps.filter((r) => r.change !== "same");
  const pending = item.state === "pending";

  return (
    <div className="flex flex-col gap-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold">
            <Link href={`/${item.namespace}/${item.agent}`} className="hover:underline">
              {`${item.namespace}/${item.agent}`}
            </Link>
            {`@${item.version}`}
          </h1>
          {bundle.versionDetail && <StatusBadge status={bundle.versionDetail.status} />}
          <Badge tone={item.queue === "platform" ? "accent" : "neutral"}>{item.queue} queue</Badge>
          {bundle.report?.rulesetVersion && <Badge>ruleset {bundle.report.rulesetVersion}</Badge>}
          {bundle.versionDetail?.source && <Badge>{bundle.versionDetail.source}</Badge>}
        </div>
        <p className="mt-1 text-sm" style={{ color: "var(--color-muted)" }}>
          {item.createdAt ? `queued ${new Date(item.createdAt).toLocaleString()}` : ""}
          {bundle.versionDetail?.archiveDigest ? ` · ${bundle.versionDetail.archiveDigest.slice(0, 23)}…` : ""}
        </p>
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

      {/* Decision panel */}
      <Card>
        <h2 className="mb-2 font-semibold">Decision</h2>
        {pending ? (
          <form method="post" action={`/review/${item.id}/decide`} className="flex flex-col gap-3">
            <label className="text-sm">
              Rationale (recorded in the audit log and shown to the author)
              <textarea
                name="rationale"
                required
                minLength={3}
                maxLength={1000}
                rows={2}
                className="mt-1 w-full rounded-md border px-3 py-1.5"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </label>
            <div className="flex gap-3">
              <button
                type="submit"
                name="decision"
                value="approve"
                className="rounded-md px-3 py-1.5 text-sm font-medium"
                style={{ background: "var(--color-ok)", color: "white" }}
              >
                Approve &amp; publish
              </button>
              <button
                type="submit"
                name="decision"
                value="reject"
                className="rounded-md px-3 py-1.5 text-sm font-medium"
                style={{ background: "var(--color-sev-high)", color: "white" }}
              >
                Reject
              </button>
            </div>
            <p className="text-xs" style={{ color: "var(--color-muted)" }}>
              Approving publishes and signs this version. Authors cannot decide their own
              submissions (§12.2) — the server enforces this.
            </p>
          </form>
        ) : (
          <p className="text-sm">
            Already decided: <Badge tone={item.state === "approved" ? "ok" : "danger"}>{item.state}</Badge>
          </p>
        )}
      </Card>

      {/* Capability contract + diff */}
      <Card>
        <h2 className="mb-2 font-semibold">
          Capability contract{" "}
          {bundle.previous ? (
            <span className="text-sm font-normal" style={{ color: "var(--color-muted)" }}>
              vs {bundle.previous.version} (previous published)
            </span>
          ) : (
            <span className="text-sm font-normal" style={{ color: "var(--color-muted)" }}>
              — first published version, no baseline
            </span>
          )}
        </h2>
        {bundle.previous && capChanges.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-ok)" }}>
            No capability changes against the previous version.
          </p>
        ) : caps.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            No capabilities declared — pure text agent.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
                <th className="py-1 pr-4 font-medium">Capability</th>
                <th className="py-1 pr-4 font-medium">Previous</th>
                <th className="py-1 pr-4 font-medium">Submitted</th>
                <th className="py-1 font-medium">Change</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {caps.map((r) => (
                <tr key={r.key} className="border-b last:border-0 align-top" style={{ borderColor: "var(--color-border)" }}>
                  <td className="py-1 pr-4">{r.key}</td>
                  <td className="py-1 pr-4" style={{ color: "var(--color-muted)" }}>
                    {r.before ?? "—"}
                  </td>
                  <td className="py-1 pr-4">{r.after ?? "—"}</td>
                  <td className="py-1">
                    {r.change === "added" && <Badge tone="danger">added</Badge>}
                    {r.change === "removed" && <Badge tone="ok">removed</Badge>}
                    {r.change === "changed" && <Badge tone="warn">changed</Badge>}
                    {r.change === "same" && <Badge>declared</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* Findings */}
      <Card>
        <h2 className="mb-2 font-semibold">Findings ({findings.length})</h2>
        {findings.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            No findings — this version gated to review by policy (e.g. first publish or capability
            change), not by scanner output.
          </p>
        ) : (
          <ul className="flex flex-col gap-4">
            {findings.map((f, i) => {
              const anchor = findingAnchor(f, item.id);
              return (
                <li key={f.id ?? i} className="border-b pb-4 last:border-0 last:pb-0" style={{ borderColor: "var(--color-border)" }}>
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <Badge>{f.scanner}</Badge>
                    <Badge tone="neutral">{f.confidence} confidence</Badge>
                    <span className="font-medium">{f.title}</span>
                    {f.verdict !== "open" && (
                      <Badge tone={f.verdict === "confirmed" ? "danger" : "ok"}>{f.verdict.replace(/_/g, " ")}</Badge>
                    )}
                  </div>
                  {f.filePath && (
                    <p className="mt-1 text-sm">
                      {anchor ? (
                        <Link href={anchor} className="font-mono text-xs underline">
                          {f.filePath}
                          {f.lineStart ? `:${f.lineStart}` : ""}
                        </Link>
                      ) : (
                        <span className="font-mono text-xs">{f.filePath}</span>
                      )}
                    </p>
                  )}
                  {f.excerpt && (
                    <pre
                      className="excerpt mt-2 overflow-x-auto rounded-md border px-3 py-2 text-xs"
                      style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
                    >
                      <RevealText text={f.excerpt} />
                    </pre>
                  )}
                  {pending && f.id && f.verdict === "open" && (
                    <form
                      method="post"
                      action={`/review/${item.id}/finding/${f.id}/verdict`}
                      className="mt-2 flex flex-wrap items-end gap-2 text-sm"
                    >
                      <label className="grow">
                        <span className="sr-only">Verdict reason</span>
                        <input
                          name="reason"
                          required
                          placeholder="Reason (required, audited)"
                          className="w-full rounded-md border px-2 py-1 text-xs"
                          style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
                        />
                      </label>
                      <button type="submit" name="verdict" value="confirmed" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                        Confirm
                      </button>
                      <button type="submit" name="verdict" value="dismissed_false_positive" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                        False positive
                      </button>
                      <button type="submit" name="verdict" value="dismissed_accepted_risk" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                        Accept risk
                      </button>
                    </form>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {/* File browser */}
      <Card>
        <h2 className="mb-2 font-semibold">Archive contents</h2>
        {files.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            No archive available for this version.
          </p>
        ) : (
          <div className="flex flex-col gap-4 md:flex-row">
            <nav className="md:w-64 md:shrink-0" aria-label="Files">
              <ul className="flex flex-col gap-1 text-sm">
                {files.map((f) => (
                  <li key={f.path}>
                    <Link
                      href={`/review/${item.id}?file=${encodeURIComponent(f.path)}`}
                      className={`flex items-center justify-between gap-2 rounded px-2 py-1 font-mono text-xs hover:underline ${selected === f.path ? "font-semibold" : ""}`}
                      style={selected === f.path ? { background: "var(--color-surface)" } : undefined}
                    >
                      <span className="truncate">{f.path}</span>
                      <span className="flex items-center gap-1">
                        {findingsByFile.get(f.path) ? (
                          <Badge tone="danger">{findingsByFile.get(f.path)}</Badge>
                        ) : null}
                        <span style={{ color: "var(--color-muted)" }}>{f.size}B</span>
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </nav>
            <div className="min-w-0 grow">
              {!selected ? (
                <p className="text-sm" style={{ color: "var(--color-muted)" }}>
                  Select a file to inspect it. Files with findings are marked with a count.
                </p>
              ) : !content ? (
                <p className="text-sm" style={{ color: "var(--color-sev-high)" }}>
                  Could not load {selected}.
                </p>
              ) : content.binary ? (
                <p className="text-sm">
                  <Badge tone="warn">binary</Badge>{" "}
                  <span style={{ color: "var(--color-muted)" }}>
                    {content.path} ({content.size} bytes) is not displayable text and is withheld
                    from the viewer.
                  </span>
                </p>
              ) : (
                <>
                  <p className="mb-1 font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                    {content.path} · {content.size} bytes
                    {content.truncated ? " · truncated for display" : ""}
                  </p>
                  <div
                    className="codeview overflow-x-auto rounded-md border text-xs"
                    style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
                  >
                    <table className="w-full border-collapse font-mono">
                      <tbody>
                        {(content.content ?? "").split("\n").map((line, idx) => {
                          const n = idx + 1;
                          const hit = flagged.has(n);
                          return (
                            <tr
                              key={n}
                              id={`L${n}`}
                              style={hit ? { background: "color-mix(in srgb, var(--color-sev-high) 12%, transparent)" } : undefined}
                            >
                              <td
                                className="select-none border-r px-2 text-right align-top"
                                style={{ borderColor: "var(--color-border)", color: hit ? "var(--color-sev-high)" : "var(--color-muted)", width: "1%" }}
                              >
                                {n}
                              </td>
                              <td className="whitespace-pre-wrap px-2 align-top">
                                <RevealText text={line} />
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </Card>

      {/* Manifest */}
      {bundle.manifest && (
        <Card>
          <details>
            <summary className="cursor-pointer font-semibold">Submitted manifest</summary>
            <pre
              className="mt-2 overflow-x-auto rounded-md border px-3 py-2 text-xs"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            >
              {JSON.stringify(bundle.manifest, null, 2)}
            </pre>
          </details>
        </Card>
      )}
    </div>
  );
}

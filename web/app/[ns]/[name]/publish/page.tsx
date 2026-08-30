import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { Card, RefusalCard, StatusBadge } from "@/components/ui";
import type { Agent, AgentVersion } from "@/lib/api";
import { fmtUTC } from "@/lib/format";
import { AccessError, authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Publish" };

// Publish flow (§10.1): pick an existing repo tag → the pipeline scans it →
// watch progress live → verdict. Upload-source publishes stay in the CLI
// (the archive is built client-side there); the web submits git tags.
export default async function PublishPage({
  params,
  searchParams,
}: {
  params: Promise<{ ns: string; name: string }>;
  searchParams: Promise<{ ok?: string; error?: string }>;
}) {
  const { ns, name } = await params;
  const n = encodeURIComponent(ns);
  const a = encodeURIComponent(name);
  const base = `/agents/${n}/${a}`;
  if (!(await currentUser())) redirect(`/login?next=/${n}/${a}/publish`);
  const q = await searchParams;

  let agent: Agent | null = null;
  let versions: AgentVersion[] = [];
  try {
    agent = await authedGet<Agent>(base);
    if (!agent) notFound();
    versions = (await authedGet<AgentVersion[]>(`${base}/versions`)) ?? [];
  } catch (e) {
    if (e instanceof AccessError) {
      return <RefusalCard>You do not have access to {`${ns}/${name}`}.</RefusalCard>;
    }
    throw e;
  }

  const inFlight = versions.filter((v) => v.status === "submitted" || v.status === "scanning");

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">
        Publish{" "}
        <Link href={`/${n}/${a}`} className="hover:underline">
          {`${ns}/${name}`}
        </Link>
      </h1>

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

      {inFlight.length > 0 && (
        <Card>
          <h2 className="mb-2 font-semibold">In the pipeline now</h2>
          <ul className="text-sm">
            {inFlight.map((v) => (
              <li key={v.id}>
                <Link href={`/${n}/${a}/versions/${encodeURIComponent(v.version)}/progress`} className="underline">
                  {v.version}
                </Link>{" "}
                <StatusBadge status={v.status} />
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card>
        <h2 className="mb-2 font-semibold">Submit a repo tag</h2>
        <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
          The tag must exist in the BriefAgent&apos;s git repo (<code>{agent.gitHttpUrl}</code>) and
          look like <code>v1.2.3</code>. Every submission runs the full §8 pipeline — no path
          skips the gate.
        </p>
        <form method="post" action={`/${n}/${a}/publish/submit`} className="flex items-end gap-2 text-sm">
          <label>
            Tag
            <input
              name="tag"
              required
              placeholder="v1.0.0"
              pattern="v.+"
              className="mt-1 rounded-md border px-2 py-1 font-mono"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
            Submit to pipeline
          </button>
        </form>
        <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
          Working from a directory instead? <code>agentry publish ./my-agent</code> uploads and
          streams the same pipeline in your terminal.
        </p>
      </Card>

      <Card>
        <h2 className="mb-2 font-semibold">Version history</h2>
        {versions.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            No versions yet.
          </p>
        ) : (
          <ul className="flex flex-col gap-1 text-sm">
            {versions.map((v) => (
              <li key={v.id} className="flex items-center gap-2">
                <Link href={`/${n}/${a}/versions/${encodeURIComponent(v.version)}`} className="font-mono hover:underline">
                  {v.version}
                </Link>
                <StatusBadge status={v.status} />
                <span className="text-xs" style={{ color: "var(--color-muted)" }}>
                  {fmtUTC(v.createdAt)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

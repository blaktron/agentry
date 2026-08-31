import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "BriefAgent Builder" };

// The BriefAgent Builder (DEV-059): author a BriefAgent in the browser and
// submit it straight into the publication pipeline. One plain HTML form
// (DEV-012 — no client JS): identity, the §5.4 capability contract, the
// instructions, a visibility choice. The submit route renders the
// workspace, packs the tar.zst, uploads it over the same cli-upload path
// the CLI and desktop app use, and the pipeline decides — the Builder
// bypasses nothing.
export default async function BuildPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; ok?: string }>;
}) {
  const params = await searchParams;
  const user = await currentUser();
  if (!user) redirect(`/login?next=${encodeURIComponent("/build")}`);

  const inputClass = "mt-1 w-full rounded-md border px-3 py-1.5";
  const inputStyle = { borderColor: "var(--color-border)", background: "var(--color-surface)" };
  const label = "text-sm";

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-1 text-xl font-semibold">BriefAgent Builder</h1>
      <p className="mb-4 text-sm" style={{ color: "var(--color-muted)" }}>
        One agent, one job. Declare the least it needs — reviewers gate on the contract,
        installs prompt on it, and the runner enforces it. Submitting runs the full security
        pipeline; clean versions publish, findings go to review.
      </p>

      {params.ok && (
        <p role="status" className="mb-4 rounded-md border px-3 py-2 text-sm"
          style={{ borderColor: "var(--color-ok)", color: "var(--color-ok)" }}>
          {params.ok}
        </p>
      )}
      {params.error && (
        <p role="alert" className="mb-4 rounded-md border px-3 py-2 text-sm"
          style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
          {params.error}
        </p>
      )}

      <form method="post" action="/build/submit" className="flex flex-col gap-4">
        <Card>
          <h2 className="mb-2 text-sm font-semibold">Identity</h2>
          <div className="grid grid-cols-2 gap-3">
            <label className={label}>
              Name
              <input name="name" required pattern="[a-z0-9][a-z0-9-]*"
                placeholder="incident-summarizer" className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              Namespace
              <input name="namespace" required defaultValue={user!.handle}
                pattern="[a-z0-9][a-z0-9-]*" className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              Kind
              <select name="kind" className={inputClass} style={inputStyle} defaultValue="skill">
                <option value="skill">skill</option>
                <option value="prompt-agent">prompt-agent</option>
              </select>
            </label>
            <label className={label}>
              Version
              <input name="version" required defaultValue="0.1.0" className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              License (SPDX)
              <input name="license" defaultValue="MIT" className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              Visibility
              <select name="visibility" className={inputClass} style={inputStyle} defaultValue="private">
                <option value="private">private</option>
                <option value="public">public</option>
              </select>
            </label>
          </div>
          <label className={`${label} mt-3 block`}>
            Summary (one line, ≤140 chars)
            <input name="summary" required maxLength={140} className={inputClass} style={inputStyle} />
          </label>
          <label className={`${label} mt-3 block`}>
            Tags (comma-separated, optional)
            <input name="tags" placeholder="security, tickets" className={inputClass} style={inputStyle} />
          </label>
        </Card>

        <Card>
          <h2 className="mb-2 text-sm font-semibold">Capability contract</h2>
          <div className="grid grid-cols-2 gap-3">
            <label className={label}>
              Network egress
              <select name="egressMode" className={inputClass} style={inputStyle} defaultValue="none">
                <option value="none">none</option>
                <option value="hosts">specific hosts</option>
                <option value="all">unrestricted (*)</option>
              </select>
            </label>
            <label className={label}>
              Egress hosts (when “specific hosts”)
              <input name="egressHosts" placeholder="api.example.com, github.com"
                className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              Filesystem read
              <select name="fsRead" className={inputClass} style={inputStyle} defaultValue="workspace">
                <option value="none">none</option>
                <option value="workspace">workspace</option>
                <option value="paths">paths</option>
              </select>
            </label>
            <label className={label}>
              Read paths (when “paths”)
              <input name="fsReadPaths" className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              Filesystem write
              <select name="fsWrite" className={inputClass} style={inputStyle} defaultValue="none">
                <option value="none">none</option>
                <option value="workspace">workspace</option>
                <option value="paths">paths</option>
              </select>
            </label>
            <label className={label}>
              Write paths (when “paths”)
              <input name="fsWritePaths" placeholder="out" className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              Exec commands (single tokens; empty = none)
              <input name="execCommands" placeholder="git, jq" className={inputClass} style={inputStyle} />
            </label>
            <label className={label}>
              Secret NAMES (env vars; never values)
              <input name="secrets" placeholder="MY_API_TOKEN" className={inputClass} style={inputStyle} />
            </label>
          </div>
          <label className={`${label} mt-3 block`}>
            Data-access categories (comma-separated:{" "}
            <span className="font-mono text-xs">email calendar files tickets code messages payments other</span>)
            <input name="dataAccess" className={inputClass} style={inputStyle} />
          </label>
          <label className={`${label} mt-3 block`}>
            MCP servers (one per line, exact versions — pinned to this release and installed
            per-signature by the runner; format:{" "}
            <span className="font-mono text-xs">npm:pkg@1.2.3 tools=a,b secrets=X egress=host</span>)
            <textarea
              name="mcpServers"
              rows={3}
              className={`${inputClass} font-mono text-xs`}
              style={inputStyle}
              placeholder={"npm:@modelcontextprotocol/server-github@2026.1.2 tools=list_issues secrets=GITHUB_PAT egress=api.github.com\npypi:mcp-server-fetch@0.6.2 egress=*"}
            />
          </label>
          <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
            Unrestricted egress is refused by runners unless the operator's policy allows it, and
            routes the version to review by default.
          </p>
        </Card>

        <Card>
          <h2 className="mb-2 text-sm font-semibold">Instructions</h2>
          <p className="mb-2 text-xs" style={{ color: "var(--color-muted)" }}>
            The entrypoint file (SKILL.md for a skill, AGENT.md for a prompt-agent). Task in,
            result out, report via write_report.
          </p>
          <textarea name="instructions" required rows={14}
            className={`${inputClass} font-mono text-xs`} style={inputStyle}
            defaultValue={"# my-briefagent\n\nDescribe the one job this agent does.\n"} />
        </Card>

        <div className="flex items-center justify-end gap-3">
          <span className="text-xs" style={{ color: "var(--color-muted)" }}>
            Submitting packs agent.yaml + instructions + README + LICENSE and runs the pipeline.
          </span>
          <button type="submit" className="rounded-md px-4 py-2 text-sm font-medium"
            style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}>
            Create &amp; submit
          </button>
        </div>
      </form>
    </div>
  );
}

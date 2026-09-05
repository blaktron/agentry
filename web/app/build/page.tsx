import type { Metadata } from "next";
import Link from "next/link";
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
  // Signed-out visitors can build and download; publishing needs an
  // account, because a submission has an author.
  const user = await currentUser();

  const inputClass = "mt-1 w-full rounded-md border px-3 py-1.5";
  const inputStyle = { borderColor: "var(--color-border)", background: "var(--color-surface)" };
  const label = "text-sm";

  return (
    <div className="max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">BriefAgent Builder</h1>
        <p className="mt-2 text-sm" style={{ color: "var(--color-muted)" }}>
        One agent, one job. Declare the least it needs — reviewers gate on the contract,
        installs prompt on it, and the runner enforces it. <strong>Download</strong> packs the
        BriefAgent as the canonical archive for your own machine (run it with{" "}
        <code>agentry run --local</code>, or <code>agentry publish</code> it later).{" "}
        <strong>Publishing</strong> submits it to this registry&apos;s security pipeline: clean
        versions publish, findings go to review.
        </p>
      </header>

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
              <input name="namespace" required defaultValue={user?.handle ?? ""}
                placeholder={user ? undefined : "your-handle"}
                pattern="[a-z0-9][a-z0-9-]*" className={inputClass} style={inputStyle} />
            </label>
            <fieldset>
              <legend className={label}>Run modes (one or both)</legend>
              <label className={`${label} mt-1 flex items-center gap-2`}>
                <input type="checkbox" name="modes" value="autonomous" defaultChecked />
                autonomous <span style={{ color: "var(--color-muted)" }}>— runs from its files and ends</span>
              </label>
              <label className={`${label} mt-1 flex items-center gap-2`}>
                <input type="checkbox" name="modes" value="interactive" />
                interactive <span style={{ color: "var(--color-muted)" }}>— a chat session under the same controls</span>
              </label>
            </fieldset>
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
          <fieldset className="mt-3">
            <legend className={label}>
              MCP servers (exact versions — pinned to this release and installed per-signature by
              the runner)
            </legend>
            {/* Structured rows, plain form controls (DEV-012: no client JS);
                more than three servers go in the advanced field below (agentry#52). */}
            {[0, 1, 2].map((i) => (
              <div key={i} className="mt-2 grid gap-2 md:grid-cols-6">
                <select name={`mcp${i}Source`} className={inputClass} style={inputStyle} aria-label={`Server ${i + 1} registry`}>
                  <option value="npm">npm</option>
                  <option value="pypi">PyPI</option>
                </select>
                <input name={`mcp${i}Pkg`} placeholder="package" className={`${inputClass} md:col-span-2`} style={inputStyle} aria-label={`Server ${i + 1} package`} />
                <input name={`mcp${i}Version`} placeholder="exact version" className={inputClass} style={inputStyle} aria-label={`Server ${i + 1} version`} />
                <input name={`mcp${i}Tools`} placeholder="tools (optional)" className={inputClass} style={inputStyle} aria-label={`Server ${i + 1} tool allowlist`} />
                <input name={`mcp${i}Secrets`} placeholder="SECRET_NAMES" className={inputClass} style={inputStyle} aria-label={`Server ${i + 1} secret names`} />
                <input name={`mcp${i}Egress`} placeholder="egress hosts" className={`${inputClass} md:col-span-6`} style={inputStyle} aria-label={`Server ${i + 1} egress hosts`} />
              </div>
            ))}
          </fieldset>
          <label className={`${label} mt-3 block`}>
            More servers (advanced, one per line:{" "}
            <span className="font-mono text-xs">npm:pkg@1.2.3 tools=a,b secrets=X egress=host</span>)
            <textarea
              name="mcpServers"
              rows={2}
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
          <h2 className="mb-2 text-sm font-semibold">Up-front questions (intake)</h2>
          <p className="mb-2 text-xs" style={{ color: "var(--color-muted)" }}>
            Asked before a run starts, in either mode; the answers are staged read-only for the agent at
            /inputs/intake.json. A secret answer is carried by a declared secret of the same upper-cased name.
          </p>
          <fieldset>
            <legend className={label}>Questions (up to three here; more in the advanced field below)</legend>
            {[0, 1, 2].map((i) => (
              <div key={i} className="mt-2 grid gap-2 md:grid-cols-6">
                <input name={`intake${i}Id`} placeholder="id (a-z0-9_)" pattern="[a-z0-9_]*" className={inputClass} style={inputStyle} aria-label={`Question ${i + 1} id`} />
                <input name={`intake${i}Prompt`} placeholder="prompt" className={`${inputClass} md:col-span-2`} style={inputStyle} aria-label={`Question ${i + 1} prompt`} />
                <select name={`intake${i}Type`} className={inputClass} style={inputStyle} aria-label={`Question ${i + 1} type`} defaultValue="text">
                  <option value="text">text</option>
                  <option value="choice">choice</option>
                  <option value="file">file</option>
                  <option value="secret">secret</option>
                </select>
                <input name={`intake${i}Choices`} placeholder="choices (a, b)" className={inputClass} style={inputStyle} aria-label={`Question ${i + 1} choices`} />
                <label className={`${label} flex items-center gap-2`}>
                  <input type="checkbox" name={`intake${i}Required`} value="1" /> required
                </label>
              </div>
            ))}
          </fieldset>
          <label className={`${label} mt-3 block`}>
            More questions (advanced, one per line:{" "}
            <span className="font-mono text-xs">id: prompt type=choice choices=a,b required</span>)
            <textarea name="intake" rows={2} className={`${inputClass} font-mono text-xs`} style={inputStyle}
              placeholder={"region: Which region? type=choice choices=emea,apac required"} />
          </label>
          <label className={`${label} mt-3 block`}>
            Opening line for interactive sessions (the agent&apos;s first message when no task is given; only with interactive checked)
            <input name="opening" maxLength={500} placeholder="What should I look at?" className={inputClass} style={inputStyle} />
          </label>
        </Card>

        <Card>
          <h2 className="mb-2 text-sm font-semibold">Instructions</h2>
          <p className="mb-2 text-xs" style={{ color: "var(--color-muted)" }}>
            The instruction file (AGENT.md). Task in, result out, report via write_report; in an
            interactive session the agent can ask for what it needs.
          </p>
          <label className={`${label} block`}>
            AGENT.md contents
            <textarea name="instructions" required rows={14}
              className={`${inputClass} font-mono text-xs`} style={inputStyle}
              defaultValue={"# my-briefagent\n\nDescribe the one job this agent does.\n"} />
          </label>
        </Card>

        <div className="flex flex-wrap items-center justify-end gap-3">
          <span className="mr-auto text-xs" style={{ color: "var(--color-muted)" }}>
            Both pack agent.yaml + instructions + README + LICENSE — the same archive either way.
          </span>
          <button type="submit" formAction="/build/download"
            className="rounded-md border px-4 py-2 text-sm font-medium"
            style={{ borderColor: "var(--color-accent)", color: "var(--color-accent)" }}>
            Download package
          </button>
          {user ? (
            <button type="submit" className="rounded-md px-4 py-2 text-sm font-medium"
              style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}>
              Create &amp; submit
            </button>
          ) : (
            <Link href={`/login?next=${encodeURIComponent("/build")}`}
              className="rounded-md px-4 py-2 text-sm font-medium"
              style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}>
              Sign in to publish
            </Link>
          )}
        </div>
      </form>
    </div>
  );
}

import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "New BriefAgent" };

// New-agent wizard (§10.1 authed row): create the agent record + its git
// repo, then hand off to `agentry init` / `git push` for content. Publishing
// always goes through the pipeline regardless of how content arrives.
export default async function NewAgentPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/new");
  const q = await searchParams;
  const namespaces = [user.handle, ...(user.orgs ?? []).map((o) => o.handle)];

  return (
    <div className="mx-auto flex max-w-xl flex-col gap-6">
      <h1 className="text-xl font-semibold">New BriefAgent</h1>
      {q.error && (
        <p role="alert" className="rounded-md border px-3 py-2 text-sm" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
          {q.error}
        </p>
      )}
      <Card>
        <form method="post" action="/new/create" className="flex flex-col gap-3 text-sm">
          <label>
            Namespace
            <select name="namespace" className="mt-1 w-full rounded-md border px-2 py-1.5" style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}>
              {namespaces.map((ns) => (
                <option key={ns} value={ns}>
                  {ns}
                </option>
              ))}
            </select>
          </label>
          <label>
            Name
            <input
              name="name"
              required
              pattern="[a-z0-9][a-z0-9-]*"
              placeholder="my-briefagent"
              className="mt-1 w-full rounded-md border px-2 py-1.5 font-mono"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <fieldset>
            <legend className="mb-1">Kind</legend>
            <div className="flex gap-4">
              {(["skill", "prompt-agent", "mcp-server"] as const).map((k) => (
                <label key={k} className="flex items-center gap-1">
                  <input type="radio" name="kind" value={k} defaultChecked={k === "skill"} required />
                  {k}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend className="mb-1">Visibility</legend>
            <div className="flex gap-4">
              <label className="flex items-center gap-1">
                <input type="radio" name="visibility" value="public" defaultChecked required /> public
              </label>
              <label className="flex items-center gap-1">
                <input type="radio" name="visibility" value="private" /> private
              </label>
            </div>
          </fieldset>
          <label>
            Summary
            <input
              name="summary"
              required
              maxLength={200}
              placeholder="One sentence: what does it do?"
              className="mt-1 w-full rounded-md border px-2 py-1.5"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <div>
            <button type="submit" className="rounded-md px-3 py-1.5 font-medium" style={{ background: "var(--color-accent)", color: "var(--color-accent-fg)" }}>
              Create agent
            </button>
          </div>
        </form>
      </Card>
      <p className="text-sm" style={{ color: "var(--color-muted)" }}>
        Creating a BriefAgent provisions its git repo. Next steps: <code>agentry init</code> a
        workspace, push to the repo, then publish a <code>v*</code> tag or run{" "}
        <code>agentry publish</code>.
      </p>
    </div>
  );
}

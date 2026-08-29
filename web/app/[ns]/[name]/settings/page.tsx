import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { Badge, Card, KindBadge, RefusalCard } from "@/components/ui";
import type { Agent, AgentGrant, AgentRole, AgentVersion, Org } from "@/lib/api";
import { fmtUTC } from "@/lib/format";
import { AccessError, authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Agent settings" };

const ROLES: AgentRole[] = ["read", "write", "maintain", "publish"];

function inputStyle() {
  return { borderColor: "var(--color-border)", background: "var(--color-surface)" } as const;
}

// Agent settings (§9.2, §6.3, §12.2): visibility and summary, the auto-publish
// toggle, the explicit grant table, and deletion of a never-published draft.
//
// Nothing here decides authorization. The API serializes `autoPublishTags`
// only to callers with maintain and refuses the mutations outright otherwise,
// so this page reads that answer and renders a refusal when it is "no".
export default async function AgentSettingsPage({
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
  if (!(await currentUser())) redirect(`/login?next=/${n}/${a}/settings`);
  const q = await searchParams;

  let agent: Agent | null = null;
  let grants: AgentGrant[] = [];
  try {
    agent = await authedGet<Agent>(base);
    if (!agent) notFound();
    grants = (await authedGet<AgentGrant[]>(`${base}/grants`)) ?? [];
  } catch (e) {
    if (e instanceof AccessError) {
      return <RefusalCard>Managing {`${ns}/${name}`} requires the maintain role on the agent.</RefusalCard>;
    }
    throw e;
  }

  // Present iff the caller has maintain. A reader with plain read access can
  // reach the page but must not be shown editable controls.
  if (agent.autoPublishTags === undefined) {
    return <RefusalCard>Managing {`${ns}/${name}`} requires the maintain role on the agent.</RefusalCard>;
  }

  const [versions, org] = await Promise.all([
    authedGet<AgentVersion[]>(`${base}/versions`).catch(() => [] as AgentVersion[]),
    authedGet<Org>(`/orgs/${n}`).catch(() => null),
  ]);
  const history = versions ?? [];
  // §9.2 / DEV-021: deletion is refused once ANY version row exists, whatever
  // its state. Say so before the button is pressed rather than only in the 409.
  const deletable = history.length === 0;
  const isOrg = org !== null;

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-xl font-semibold">
          <Link href={`/${n}/${a}`} className="hover:underline">
            {`${agent.namespace}/${agent.name}`}
          </Link>{" "}
          settings
        </h1>
        <KindBadge kind={agent.kind} />
        <Badge tone={agent.visibility === "public" ? "neutral" : "warn"}>{agent.visibility}</Badge>
        <span className="text-sm" style={{ color: "var(--color-muted)" }}>
          created {fmtUTC(agent.createdAt)}
        </span>
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

      <Card>
        <h2 className="mb-2 font-semibold">Summary and visibility</h2>
        <form method="post" action={`/${n}/${a}/settings/save`} className="flex flex-col gap-3 text-sm">
          <input type="hidden" name="action" value="profile" />
          <label>
            Summary
            <input
              name="summary"
              defaultValue={agent.summary}
              maxLength={140}
              className="mt-1 w-full rounded-md border px-2 py-1.5"
              style={inputStyle()}
            />
          </label>
          <fieldset>
            <legend className="mb-1">Visibility</legend>
            <div className="flex gap-4">
              <label className="flex items-center gap-1">
                <input type="radio" name="visibility" value="public" defaultChecked={agent.visibility === "public"} /> public
              </label>
              <label className="flex items-center gap-1">
                <input type="radio" name="visibility" value="private" defaultChecked={agent.visibility === "private"} /> private
              </label>
            </div>
          </fieldset>
          <p className="text-xs" style={{ color: "var(--color-muted)" }}>
            Making an agent private hides it from search and anonymous reads. It does not un-publish
            versions that are already out there, and it does not remove copies people installed.
          </p>
          <div>
            <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
              Save
            </button>
          </div>
        </form>
      </Card>

      <Card>
        <h2 className="mb-2 font-semibold">Publish on tag push</h2>
        <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
          When enabled, pushing a <code>v*</code> tag submits that version to the pipeline
          automatically (§6.3). It changes who starts a publish, never whether one is scanned: the
          full §8 pipeline runs either way, and a gated version still waits for a reviewer.
        </p>
        <form method="post" action={`/${n}/${a}/settings/save`} className="flex items-center gap-3 text-sm">
          <input type="hidden" name="action" value="autopublish" />
          <input type="hidden" name="autoPublishTags" value={agent.autoPublishTags ? "false" : "true"} />
          <Badge tone={agent.autoPublishTags ? "ok" : "neutral"}>
            {agent.autoPublishTags ? "enabled" : "disabled"}
          </Badge>
          <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
            {agent.autoPublishTags ? "Disable" : "Enable"}
          </button>
        </form>
      </Card>

      <Card>
        <h2 className="mb-2 font-semibold">Access ({grants.length} explicit grant{grants.length === 1 ? "" : "s"})</h2>
        <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
          Grants are additive on top of namespace-derived access (§12.2): read &lt; write &lt;
          maintain &lt; publish. Owners and org admins already have access without appearing here.
        </p>
        {grants.length > 0 && (
          <table className="mb-3 w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
                <th className="py-1 pr-4 font-medium">Grantee</th>
                <th className="py-1 pr-4 font-medium">Kind</th>
                <th className="py-1 pr-4 font-medium">Role</th>
                <th className="py-1 font-medium" aria-label="grant actions"></th>
              </tr>
            </thead>
            <tbody>
              {grants.map((g) => (
                <tr key={`${g.kind}:${g.grantee}`} className="border-b last:border-0" style={{ borderColor: "var(--color-border)" }}>
                  <td className="py-2 pr-4 font-mono text-xs">{g.grantee}</td>
                  <td className="py-2 pr-4">{g.kind}</td>
                  <td className="py-2 pr-4">{g.role}</td>
                  <td className="py-2">
                    <form method="post" action={`/${n}/${a}/settings/grants`} className="flex flex-wrap items-center gap-2">
                      <input type="hidden" name="kind" value={g.kind} />
                      <input type="hidden" name="grantee" value={g.grantee} />
                      <label>
                        <span className="sr-only">Role for {g.grantee}</span>
                        <select name="role" defaultValue={g.role} className="rounded-md border px-2 py-1 text-xs" style={inputStyle()}>
                          {ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                      </label>
                      <button type="submit" name="action" value="set" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                        Set
                      </button>
                      <button type="submit" name="action" value="remove" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                        Remove
                      </button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <form method="post" action={`/${n}/${a}/settings/grants`} className="flex flex-wrap items-end gap-2 text-sm">
          <input type="hidden" name="action" value="set" />
          <label>
            <span className="mr-1">Grant to</span>
            <select name="kind" defaultValue="user" className="rounded-md border px-2 py-1 text-xs" style={inputStyle()}>
              <option value="user">user handle</option>
              {isOrg && <option value="team">org team slug</option>}
            </select>
          </label>
          <label>
            <span className="sr-only">Grantee</span>
            <input
              name="grantee"
              required
              pattern="[a-z0-9][a-z0-9-]*"
              placeholder={isOrg ? "handle or team-slug" : "handle"}
              className="rounded-md border px-2 py-1 text-xs"
              style={inputStyle()}
            />
          </label>
          <label>
            <span className="sr-only">Role</span>
            <select name="role" defaultValue="read" className="rounded-md border px-2 py-1 text-xs" style={inputStyle()}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
            Add
          </button>
        </form>
        {!isOrg && (
          <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
            Team grants apply to org-owned agents only; this one lives in a personal namespace.
          </p>
        )}
      </Card>

      <Card>
        <h2 className="mb-2 font-semibold" style={{ color: "var(--color-sev-high)" }}>
          Delete this agent
        </h2>
        {deletable ? (
          <>
            <p className="mb-3 text-sm">
              This agent has no version rows, so it can still be deleted along with its hosted
              repository. This cannot be undone, and the name becomes available again.
            </p>
            <form method="post" action={`/${n}/${a}/settings/delete`} className="flex flex-wrap items-end gap-2 text-sm">
              <label className="grow">
                Type <code>{agent.name}</code> to confirm
                <input
                  name="confirm"
                  required
                  autoComplete="off"
                  className="mt-1 w-full rounded-md border px-2 py-1 font-mono text-xs"
                  style={inputStyle()}
                />
              </label>
              <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                Delete agent
              </button>
            </form>
          </>
        ) : (
          <p className="text-sm">
            Not available: this agent has {history.length} version
            {history.length === 1 ? "" : "s"} on record. §4.3 forbids deleting version rows — a
            published version is history that consumers may depend on, and a version still in the
            pipeline is mid-flight. Published agents are{" "}
            <Link href={`/${n}/${a}`} className="underline">
              yanked or blocked
            </Link>
            , never deleted.
          </p>
        )}
      </Card>
    </div>
  );
}

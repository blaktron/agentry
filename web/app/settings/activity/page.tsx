import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Badge, Card } from "@/components/ui";
import type { ActivityPage } from "@/lib/api";
import { actionLabel } from "@/lib/audit";
import { fmtUTC } from "@/lib/format";
import { authedGet, currentUser } from "@/lib/session";
import { SettingsShell, type UserSession } from "../_lib";

export const metadata: Metadata = { title: "Settings · Activity" };

// Settings → Activity (agentry#192): what this account did lately — sign-ins,
// tokens and keys, publishes, reviews, with where each came from — and the
// browser sessions that are open right now.
export default async function SettingsActivityPage({
  searchParams,
}: {
  searchParams: Promise<{ ok?: string; error?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/settings/activity");
  const q = await searchParams;

  // `undefined` means the endpoint is absent on this server; `[]` would mean
  // it answered with nothing, which is a different statement.
  const [activity, sessions] = await Promise.all([
    authedGet<ActivityPage>("/user/activity?limit=50")
      .then((p) => p?.events)
      .catch(() => undefined),
    authedGet<{ sessions: UserSession[] }>("/user/sessions")
      .then((r) => r?.sessions)
      .catch(() => undefined),
  ]);

  const detailLine = (e: NonNullable<typeof activity>[number]): string => {
    const d = (e.detail ?? {}) as Record<string, unknown>;
    const parts: string[] = [];
    for (const k of ["name", "title", "handle", "org", "agent", "to", "decision", "scopes"]) {
      const v = d[k];
      if (typeof v === "string" && v) parts.push(`${k} ${v}`);
      else if (Array.isArray(v) && v.length > 0) parts.push(`${k} ${v.join(" ")}`);
    }
    if (e.version) parts.push(`version ${e.version}`);
    return parts.join(" · ");
  };

  return (
    <SettingsShell current="/settings/activity" ok={q.ok} error={q.error}>
      <div className="grid gap-6">
        <Card>
          <h2 className="mb-2 font-semibold">Recent activity</h2>
          <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
            What this account did, newest first, with the address and client each action came
            from. Something here you do not recognise is the moment to revoke sessions and tokens
            (below and under Authentication) and change your password.
          </p>
          {activity === undefined ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              Activity is not available on this server (it needs the <code>/user/activity</code> endpoint).
            </p>
          ) : activity.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>Nothing recorded yet.</p>
          ) : (
            <ul className="flex flex-col gap-1 text-sm">
              {activity.map((e) => (
                <li key={e.id} className="flex flex-wrap items-baseline gap-x-2">
                  <span className="font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                    {fmtUTC(e.occurredAt)}
                  </span>
                  <span className="font-medium">{actionLabel(e.action)}</span>
                  {detailLine(e) && (
                    <span className="text-xs" style={{ color: "var(--color-muted)" }}>{detailLine(e)}</span>
                  )}
                  {e.ip && <span className="font-mono text-xs">{e.ip}</span>}
                  {e.userAgent && (
                    <span className="max-w-xs truncate text-xs" style={{ color: "var(--color-muted)" }} title={e.userAgent}>
                      {e.userAgent}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <h2 className="mb-2 font-semibold">Sessions</h2>
          {sessions === undefined ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              Session listing is not available on this server. Signing out ends the session you are
              using. Revoking the others needs the <code>/user/sessions</code> endpoint, and this
              registry build does not serve it.
            </p>
          ) : sessions.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--color-muted)" }}>
              No sessions are recorded. That is unusual, since you are signed in with one.
            </p>
          ) : (
            <>
              <ul className="mb-3 flex flex-col gap-2 text-sm">
                {sessions.map((s) => (
                  <li key={s.id} className="flex flex-wrap items-center gap-2">
                    {s.current && <Badge tone="ok">this browser</Badge>}
                    <span className="text-xs" style={{ color: "var(--color-muted)" }}>
                      started {fmtUTC(s.createdAt)}
                      {s.lastSeenAt ? ` · last seen ${fmtUTC(s.lastSeenAt)}` : ""}
                    </span>
                    {s.ip && <span className="font-mono text-xs">{s.ip}</span>}
                    {s.userAgent && (
                      <span className="max-w-xs truncate text-xs" style={{ color: "var(--color-muted)" }} title={s.userAgent}>
                        {s.userAgent}
                      </span>
                    )}
                    {!s.current && (
                      <form method="post" action="/settings/sessions">
                        <input type="hidden" name="action" value="revoke" />
                        <input type="hidden" name="sessionId" value={s.id} />
                        <button type="submit" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                          Revoke
                        </button>
                      </form>
                    )}
                  </li>
                ))}
              </ul>
              {sessions.length > 1 && (
                <form method="post" action="/settings/sessions">
                  <input type="hidden" name="action" value="revoke-others" />
                  <button type="submit" className="rounded-md border px-3 py-1.5 text-sm" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                    Sign out everywhere else
                  </button>
                </form>
              )}
              <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
                Revoking a session invalidates its cookie immediately. It does not revoke personal
                access tokens; those live under Authentication and are revoked separately.
              </p>
            </>
          )}
        </Card>
      </div>
    </SettingsShell>
  );
}

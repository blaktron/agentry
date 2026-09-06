import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Card } from "@/components/ui";
import { type NotificationSettings } from "@/lib/api";
import { authedGet, currentUser } from "@/lib/session";
import { SettingsShell } from "./_lib";

export const metadata: Metadata = { title: "Settings · Profile" };

// Settings → Profile (agentry#192): who you are on the registry and how its
// alerts reach you. Authentication and Activity are their own sections.
export default async function SettingsProfilePage({
  searchParams,
}: {
  searchParams: Promise<{ ok?: string; error?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/settings");
  const q = await searchParams;
  // Notification settings (agentry#190); a server without the endpoint
  // answers 404 → null, shown as everything on.
  const notifications: NotificationSettings = (await authedGet<NotificationSettings>("/user/notifications").catch(() => null)) ?? {
    email: { dependencyAlerts: true, quarantine: true, reviewDecisions: true, advisories: true, orgInvites: true },
    web: { dependencyAlerts: true },
  };

  return (
    <SettingsShell current="/settings" ok={q.ok} error={q.error}>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <h2 className="mb-2 font-semibold">Profile</h2>
          <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
            {user.handle} · {user.email} {user.emailVerified ? "(verified)" : "(unverified)"}
          </p>
          <form method="post" action="/settings/profile" className="flex items-end gap-2 text-sm">
            <label className="grow">
              Display name
              <input
                name="displayName"
                defaultValue={user.displayName ?? ""}
                maxLength={100}
                className="mt-1 w-full rounded-md border px-2 py-1"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </label>
            <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
              Save
            </button>
          </form>
          <p className="mt-3 text-xs" style={{ color: "var(--color-muted)" }}>
            Your handle and email are held by the sign-in service and cannot be changed here.
          </p>
        </Card>

        <Card>
          <h2 className="mb-2 font-semibold">Notifications</h2>
          <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
            How the registry&apos;s alerts reach you. Email goes to {user.email}; the banner is the
            notice shown on every page while one of your published versions has a dependency alert.
            Your dashboard lists alerts either way, and organizations&apos; webhooks and the audit
            trail are not affected by these switches.
          </p>
          <form method="post" action="/settings/notifications" className="flex flex-col gap-2 text-sm">
            <fieldset className="flex flex-col gap-1">
              <legend className="mb-1 text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Email me when
              </legend>
              {(
                [
                  ["email.dependencyAlerts", "a published version of mine declares an MCP server with a newly known vulnerability", notifications.email.dependencyAlerts],
                  ["email.quarantine", "a published version of mine is quarantined by a rescan", notifications.email.quarantine],
                  ["email.reviewDecisions", "a reviewer decides one of my submissions", notifications.email.reviewDecisions],
                  ["email.advisories", "an advisory naming one of my BriefAgents is published", notifications.email.advisories],
                  ["email.orgInvites", "I am added to an organization", notifications.email.orgInvites],
                ] as [string, string, boolean][]
              ).map(([name, label, on]) => (
                <label key={name} className="flex items-baseline gap-2">
                  <input type="checkbox" name={name} value="on" defaultChecked={on} />
                  <span>{label}</span>
                </label>
              ))}
            </fieldset>
            <fieldset className="flex flex-col gap-1">
              <legend className="mb-1 text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                In the web app
              </legend>
              <label className="flex items-baseline gap-2">
                <input type="checkbox" name="web.dependencyAlerts" value="on" defaultChecked={notifications.web.dependencyAlerts} />
                <span>Show the dependency-alert banner on every page while an alert is open</span>
              </label>
            </fieldset>
            <div>
              <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
                Save notifications
              </button>
            </div>
          </form>
        </Card>
      </div>
    </SettingsShell>
  );
}

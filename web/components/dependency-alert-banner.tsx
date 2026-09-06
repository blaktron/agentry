import Link from "next/link";
import type { DependencyAlert, NotificationSettings } from "@/lib/api";
import { authedGet, type SessionUser } from "@/lib/session";

// The sign-in banner for dependency alerts (agentry#177): while a signed-in
// user has a published version that declares an MCP server with a newly
// known high or critical vulnerability, every page says so above the
// content. Server component, no client JS; one authed request per render,
// which the layout already pays for the account nav.
export async function DependencyAlertBanner({ user }: { user: SessionUser | null }) {
  if (!user) return null;
  const alerts = (await authedGet<DependencyAlert[]>("/user/dependency-alerts").catch(() => null)) ?? [];
  if (alerts.length === 0) return null;
  // The person may have switched the banner off (Settings → Notifications,
  // agentry#190); the dashboard still lists the alerts.
  const prefs = await authedGet<NotificationSettings>("/user/notifications").catch(() => null);
  if (prefs && !prefs.web.dependencyAlerts) return null;
  const agents = new Set(alerts.map((a) => a.agent));
  const worst = alerts.some((a) => a.severity === "critical") ? "critical" : "high";
  return (
    <div
      role="alert"
      className="border-b"
      style={{ background: "var(--color-sev-high-bg, transparent)", borderColor: "var(--color-sev-high)" }}
    >
      <div className="mx-auto flex max-w-6xl flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-2 text-sm">
        <span className="font-semibold" style={{ color: "var(--color-sev-high)" }}>
          Package issue ({worst})
        </span>
        <span>
          {alerts.length === 1
            ? `${alerts[0].agent}@${alerts[0].version} declares ${alerts[0].ecosystem}:${alerts[0].package}@${alerts[0].packageVersion}, which now has a known vulnerability.`
            : `${alerts.length} published versions across ${agents.size} of your BriefAgents declare an MCP server with a known vulnerability.`}{" "}
          Publish a version that pins a fixed server, then yank the affected ones.
        </span>
        <Link href="/dashboard#dependency-alerts" className="underline">
          See the affected versions
        </Link>
      </div>
    </div>
  );
}

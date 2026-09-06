import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Badge, Card, RefusalCard } from "@/components/ui";
import { fmtUTC, fmtUTCDate } from "@/lib/format";
import { apiGet, type NotificationSettings } from "@/lib/api";
import { AccessError, authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Settings" };

// User settings (§10.1 authed row): profile, 2FA, personal access tokens,
// and active sessions.

interface Pat {
  id: string;
  name: string;
  scopes: string[];
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
}

interface SshKey {
  id: string;
  title: string;
  keyType: string;
  fingerprint: string;
  createdAt: string;
  lastUsedAt?: string;
}

// Session listing contract, agreed with the API workstream this wave:
//   GET    /user/sessions       -> { sessions: [...] }
//   DELETE /user/sessions/{id}  -> 204
//   DELETE /user/sessions       -> 204 (revoke every other session)
// A server that has not shipped it answers 404, which apiGet/authedGet map
// to null; the section then says so instead of pretending there are none.
interface UserSession {
  id: string;
  createdAt: string;
  lastSeenAt?: string;
  current?: boolean;
  ip?: string;
  userAgent?: string;
}

interface UserDirectory {
  managed: boolean;
  accountUrl?: string;
  passwordChangeUrl?: string;
  totpSetupUrl?: string;
  webauthnSetupUrl?: string;
  devices?: { id?: string; kind: string; name: string; createdAt?: string }[];
  devicesError?: string;
}

const DEVICE_LABEL: Record<string, string> = {
  totp: "Authenticator app (TOTP)",
  webauthn: "Security key / passkey (WebAuthn)",
  static: "Recovery codes",
  duo: "Duo push",
  sms: "SMS",
  email: "Email code",
  other: "Authenticator",
};

const SCOPES = [
  "repo:read",
  "repo:write",
  "agent:publish",
  "agent:read",
  "org:admin",
  "review:act",
  "audit:read",
  "user:profile",
];

export default async function SettingsPage({
  searchParams,
}: {
  searchParams: Promise<{ ok?: string; error?: string; totp?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/settings");
  // Notification settings (agentry#190); a server without the endpoint
  // answers 404 → null, shown as everything on.
  const notifications: NotificationSettings = (await authedGet<NotificationSettings>("/user/notifications").catch(() => null)) ?? {
    email: { dependencyAlerts: true, quarantine: true, reviewDecisions: true, advisories: true, orgInvites: true },
    web: { dependencyAlerts: true },
  };
  const q = await searchParams;

  let tokens: Pat[] = [];
  let sshKeys: SshKey[] = [];
  try {
    tokens = (await authedGet<Pat[]>("/user/tokens")) ?? [];
    sshKeys = (await authedGet<SshKey[]>("/user/ssh-keys")) ?? [];
  } catch (e) {
    if (e instanceof AccessError) {
      return <RefusalCard>Your session is no longer accepted. Sign in again to manage this account.</RefusalCard>;
    }
    throw e;
  }

  // `undefined` means the endpoint is absent on this server; `[]` would mean
  // it answered with no sessions, which is a different statement.
  const sessions = await authedGet<{ sessions: UserSession[] }>("/user/sessions")
    .then((r) => r?.sessions)
    .catch(() => undefined);

  // With accounts in a directory service (DEV-057) the native TOTP endpoints
  // answer 410; offering the form would be a dead end (agentry#21). /meta
  // says which world this is.
  const meta = await apiGet<{ features?: Record<string, boolean> }>("/meta", { revalidate: 60 }).catch(() => null);
  const externalOnly = meta?.features?.externalOnly === true;
  // Where password, MFA and profile live when the directory owns them
  // (agentry#113): the API derives the directory's flow URLs and lists the
  // enrolled authenticators through its admin access.
  const directory = externalOnly
    ? await authedGet<UserDirectory>("/user/directory").catch(() => null)
    : null;

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">Settings</h1>

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

      {/* Same responsive shell as the other authed pages: one column on
          phones, profile and security side by side from lg up, tokens and
          sessions full width (agentry#111). */}
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
      </Card>

      <Card>
        <h2 className="mb-2 font-semibold">{externalOnly ? "Password and two-factor authentication" : "Two-factor authentication"}</h2>
        {externalOnly && directory?.managed ? (
          <div className="flex flex-col gap-3 text-sm">
            <p style={{ color: "var(--color-muted)" }}>
              Your password and authenticators are kept by the sign-in service. Each action below
              opens one short step there and brings you straight back here.
            </p>
            <div className="flex flex-wrap gap-2">
              {directory.passwordChangeUrl && (
                <a href={directory.passwordChangeUrl} className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
                  Change password
                </a>
              )}
              {directory.totpSetupUrl && (
                <a href={directory.totpSetupUrl} className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
                  Add authenticator app
                </a>
              )}
              {directory.webauthnSetupUrl && (
                <a href={directory.webauthnSetupUrl} className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
                  Add security key / passkey
                </a>
              )}
            </div>
            <div>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide" style={{ color: "var(--color-muted)" }}>
                Enrolled authenticators
              </h3>
              {directory.devicesError ? (
                <p style={{ color: "var(--color-muted)" }}>{directory.devicesError}</p>
              ) : directory.devices === undefined ? (
                <p style={{ color: "var(--color-muted)" }}>
                  Not shown: this server has no directory admin access (AGENTRY_IDP_ADMIN_URL).
                </p>
              ) : directory.devices.length === 0 ? (
                <p>
                  <Badge tone="warn">none</Badge>{" "}
                  <span style={{ color: "var(--color-muted)" }}>
                    No second factor is enrolled. Publishing publicly requires one (§12.1).
                  </span>
                </p>
              ) : (
                <ul className="flex flex-col gap-1">
                  {directory.devices.map((d, i) => (
                    <li key={i} className="flex flex-wrap items-center gap-2">
                      <Badge tone="ok">{DEVICE_LABEL[d.kind] ?? DEVICE_LABEL.other}</Badge>
                      <span>{d.name}</span>
                      {d.createdAt && (
                        <span className="text-xs" style={{ color: "var(--color-muted)" }}>added {fmtUTCDate(d.createdAt)}</span>
                      )}
                      {d.id && (
                        <form method="post" action="/settings/directory" className="inline">
                          <input type="hidden" name="action" value="remove-device" />
                          <input type="hidden" name="kind" value={d.kind} />
                          <input type="hidden" name="deviceId" value={d.id} />
                          <button type="submit" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-border)" }}>
                            Remove
                          </button>
                        </form>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : externalOnly ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>
            Your password and two-factor authentication are managed by the directory service you
            sign in through, not here. Use its account page (the sign-in provider&apos;s settings)
            to change your password or enrol an authenticator.
          </p>
        ) : user.totpEnabled ? (
          <p className="text-sm">
            <Badge tone="ok">enabled</Badge>{" "}
            <span style={{ color: "var(--color-muted)" }}>TOTP is active on this account.</span>
          </p>
        ) : q.totp === "verify" ? (
          <form method="post" action="/settings/totp" className="flex items-end gap-2 text-sm">
            <input type="hidden" name="action" value="verify" />
            <label>
              Code from your authenticator
              <input
                name="code"
                required
                inputMode="numeric"
                autoComplete="one-time-code"
                className="mt-1 rounded-md border px-2 py-1"
                style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
              />
            </label>
            <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
              Verify &amp; enable
            </button>
          </form>
        ) : (
          <form method="post" action="/settings/totp">
            <input type="hidden" name="action" value="setup" />
            <p className="mb-2 text-sm" style={{ color: "var(--color-muted)" }}>
              2FA is required before publishing public BriefAgents (§19).
            </p>
            <button type="submit" className="rounded-md border px-3 py-1.5 text-sm" style={{ borderColor: "var(--color-border)" }}>
              Set up TOTP
            </button>
          </form>
        )}
      </Card>

      <Card className="lg:col-span-2">
        <h2 className="mb-2 font-semibold">Personal access tokens</h2>
        {tokens.length === 0 ? (
          <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
            No tokens. <code>agentry login</code> signs in through the browser and mints its own; create one here only for scripts (<code>agentry login --paste</code>).
          </p>
        ) : (
          <ul className="mb-3 flex flex-col gap-2 text-sm">
            {tokens.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{t.name}</span>
                <span className="font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                  {t.scopes.join(" ")}
                </span>
                {t.lastUsedAt && (
                  <span className="text-xs" style={{ color: "var(--color-muted)" }}>
                    last used {fmtUTCDate(t.lastUsedAt)}
                  </span>
                )}
                <form method="post" action="/settings/tokens">
                  <input type="hidden" name="action" value="revoke" />
                  <input type="hidden" name="tokenId" value={t.id} />
                  <button type="submit" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                    Revoke
                  </button>
                </form>
              </li>
            ))}
          </ul>
        )}
        <form method="post" action="/settings/tokens" className="flex flex-col gap-2 text-sm">
          <input type="hidden" name="action" value="create" />
          <label>
            Token name
            <input
              name="name"
              required
              maxLength={60}
              className="mt-1 w-full rounded-md border px-2 py-1"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <fieldset>
            <legend className="mb-1">Scopes</legend>
            <div className="flex flex-wrap gap-3">
              {SCOPES.map((s) => (
                <label key={s} className="flex items-center gap-1 font-mono text-xs">
                  <input type="checkbox" name="scopes" value={s} defaultChecked={s === "agent:read"} />
                  {s}
                </label>
              ))}
            </div>
          </fieldset>
          <div>
            <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
              Create token
            </button>
          </div>
        </form>
      </Card>

      <Card className="lg:col-span-2">
        <h2 className="mb-2 font-semibold">SSH keys</h2>
        <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
          For <code>git clone ssh://git@…/ns/name.git</code> and pushes over SSH (§6.1). A key is worth
          repository read/write and the release tag your role allows — never the API. Organizations
          that enforce SSO still take pushes only over HTTPS with an org-bound token.
        </p>
        {sshKeys.length === 0 ? (
          <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>No SSH keys.</p>
        ) : (
          <ul className="mb-3 flex flex-col gap-2 text-sm">
            {sshKeys.map((k) => (
              <li key={k.id} className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{k.title}</span>
                <span className="font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                  {k.keyType} {k.fingerprint}
                </span>
                {k.lastUsedAt && (
                  <span className="text-xs" style={{ color: "var(--color-muted)" }}>
                    last used {fmtUTCDate(k.lastUsedAt)}
                  </span>
                )}
                <form method="post" action="/settings/ssh-keys">
                  <input type="hidden" name="action" value="remove" />
                  <input type="hidden" name="keyId" value={k.id} />
                  <button type="submit" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                    Remove
                  </button>
                </form>
              </li>
            ))}
          </ul>
        )}
        <form method="post" action="/settings/ssh-keys" className="flex flex-col gap-2 text-sm">
          <input type="hidden" name="action" value="add" />
          <label>
            Title
            <input
              name="title"
              required
              maxLength={120}
              placeholder="laptop"
              className="mt-1 w-full rounded-md border px-2 py-1"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <label>
            Public key
            <textarea
              name="publicKey"
              required
              rows={3}
              placeholder="ssh-ed25519 AAAA… comment"
              className="mt-1 w-full rounded-md border px-2 py-1 font-mono text-xs"
              style={{ borderColor: "var(--color-border)", background: "var(--color-surface)" }}
            />
          </label>
          <div>
            <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
              Add key
            </button>
          </div>
        </form>
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


      <Card className="lg:col-span-2">
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
              access tokens. Those are listed above and revoked separately.
            </p>
          </>
        )}
      </Card>
      </div>
    </div>
  );
}

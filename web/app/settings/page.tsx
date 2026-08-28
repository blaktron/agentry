import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Badge, Card } from "@/components/ui";
import { authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Settings" };

// User settings (§10.1 authed row): profile, personal access tokens, 2FA.
// Session listing ships when the API grows a sessions endpoint (WG-B note).

interface Pat {
  id: string;
  name: string;
  scopes: string[];
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
}

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
  const q = await searchParams;
  const tokens = (await authedGet<Pat[]>("/user/tokens")) ?? [];

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
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
        <h2 className="mb-2 font-semibold">Two-factor authentication</h2>
        {user.totpEnabled ? (
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
              2FA is required before publishing public agents (§19).
            </p>
            <button type="submit" className="rounded-md border px-3 py-1.5 text-sm" style={{ borderColor: "var(--color-border)" }}>
              Set up TOTP
            </button>
          </form>
        )}
      </Card>

      <Card>
        <h2 className="mb-2 font-semibold">Personal access tokens</h2>
        {tokens.length === 0 ? (
          <p className="mb-3 text-sm" style={{ color: "var(--color-muted)" }}>
            No tokens. The CLI signs in with one (<code>agentry login</code>).
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
                    last used {new Date(t.lastUsedAt).toLocaleDateString()}
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
    </div>
  );
}

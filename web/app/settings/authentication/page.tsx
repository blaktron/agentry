import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Badge, Card, RefusalCard } from "@/components/ui";
import { fmtUTCDate } from "@/lib/format";
import { apiGet } from "@/lib/api";
import { AccessError, authedGet, currentUser } from "@/lib/session";
import { DEVICE_LABEL, SCOPES, SettingsShell, type Pat, type SshKey, type UserDirectory } from "../_lib";

export const metadata: Metadata = { title: "Settings · Authentication" };

// Settings → Authentication (agentry#192): password and two-factor
// authentication, personal access tokens, SSH keys.
export default async function SettingsAuthenticationPage({
  searchParams,
}: {
  searchParams: Promise<{ ok?: string; error?: string; totp?: string }>;
}) {
  const user = await currentUser();
  if (!user) redirect("/login?next=/settings/authentication");
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

  // With accounts in a directory service (DEV-057) the native TOTP endpoints
  // answer 410; offering the form would be a dead end (agentry#21). /meta
  // says which world this is.
  const meta = await apiGet<{ features?: Record<string, boolean> }>("/meta", { revalidate: 60 }).catch(() => null);
  const externalOnly = meta?.features?.externalOnly === true;
  // Where password and MFA live when the directory owns them (agentry#113,
  // DEV-089): the API derives the directory's flow URLs and lists the
  // enrolled authenticators through its admin access.
  const directory = externalOnly ? await authedGet<UserDirectory>("/user/directory").catch(() => null) : null;

  return (
    <SettingsShell current="/settings/authentication" ok={q.ok} error={q.error}>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="lg:col-span-2">
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

        <Card>
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

        <Card>
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
      </div>
    </SettingsShell>
  );
}

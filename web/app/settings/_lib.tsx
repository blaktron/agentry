// Shared pieces of the three Settings sections (agentry#192): Profile
// (/settings), Authentication (/settings/authentication) and Activity
// (/settings/activity). Types mirror the API contract the pages read.
import Link from "next/link";

export interface Pat {
  id: string;
  name: string;
  scopes: string[];
  createdAt: string;
  expiresAt?: string;
  lastUsedAt?: string;
}

export interface SshKey {
  id: string;
  title: string;
  keyType: string;
  fingerprint: string;
  createdAt: string;
  lastUsedAt?: string;
}

// Session listing contract:
//   GET    /user/sessions       -> { sessions: [...] }
//   DELETE /user/sessions/{id}  -> 204
//   DELETE /user/sessions       -> 204 (revoke every other session)
// A server that has not shipped it answers 404, which authedGet maps to
// null; the section then says so instead of pretending there are none.
export interface UserSession {
  id: string;
  createdAt: string;
  lastSeenAt?: string;
  current?: boolean;
  ip?: string;
  userAgent?: string;
}

export interface UserDirectory {
  managed: boolean;
  accountUrl?: string;
  passwordChangeUrl?: string;
  totpSetupUrl?: string;
  webauthnSetupUrl?: string;
  devices?: { id?: string; kind: string; name: string; createdAt?: string }[];
  devicesError?: string;
}

export const DEVICE_LABEL: Record<string, string> = {
  totp: "Authenticator app (TOTP)",
  webauthn: "Security key / passkey (WebAuthn)",
  static: "Recovery codes",
  duo: "Duo push",
  sms: "SMS",
  email: "Email code",
  other: "Authenticator",
};

export const SCOPES = [
  "repo:read",
  "repo:write",
  "agent:publish",
  "agent:read",
  "org:admin",
  "review:act",
  "audit:read",
  "user:profile",
];

export const SECTIONS = [
  { href: "/settings", label: "Profile", blurb: "name, notifications" },
  { href: "/settings/authentication", label: "Authentication", blurb: "password, two-factor, tokens, keys" },
  { href: "/settings/activity", label: "Activity", blurb: "recent activity, sessions" },
] as const;

export type SectionHref = (typeof SECTIONS)[number]["href"];

// SettingsShell is the heading, the section nav and the flash notices every
// section shares; the current section is marked for readers and for
// assistive tech (aria-current), with no client JS.
export function SettingsShell({
  current,
  ok,
  error,
  children,
}: {
  current: SectionHref;
  ok?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h1 className="text-xl font-semibold">Settings</h1>
        <nav aria-label="Settings sections" className="flex flex-wrap gap-1 text-sm">
          {SECTIONS.map((s) => {
            const active = s.href === current;
            return (
              <Link
                key={s.href}
                href={s.href}
                aria-current={active ? "page" : undefined}
                title={s.blurb}
                className="rounded-md border px-3 py-1.5"
                style={{
                  borderColor: active ? "var(--color-accent)" : "var(--color-border)",
                  background: active ? "var(--color-accent)" : "transparent",
                  color: active ? "var(--color-accent-fg)" : "inherit",
                }}
              >
                {s.label}
              </Link>
            );
          })}
        </nav>
      </div>
      {ok && (
        <p role="status" className="rounded-md border px-3 py-2 text-sm" style={{ borderColor: "var(--color-ok)", color: "var(--color-ok)" }}>
          {ok}
        </p>
      )}
      {error && (
        <p role="alert" className="rounded-md border px-3 py-2 text-sm" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
          {error}
        </p>
      )}
      {children}
    </div>
  );
}

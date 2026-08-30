import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { Badge, Card, RefusalCard } from "@/components/ui";
import type { WebhookDelivery } from "@/lib/api";
import { fmtUTC, fmtUTCDate } from "@/lib/format";
import { AccessError, authedGet, currentUser } from "@/lib/session";

export const metadata: Metadata = { title: "Org admin" };

// Org administration (§10.1 Org admin row): members & teams, policy editor,
// SSO config, SCIM tokens, domain verification, webhooks, audit browser.
// Server-rendered forms over the tested M1/M6 APIs. Authorization lives at
// the API chokepoint; this page renders refusals, it does not gate.

interface Membership {
  user: { handle: string; displayName: string };
  role: string;
  viaScim?: boolean;
}
interface Team {
  id: string;
  slug: string;
}
interface SsoConnection {
  kind: "saml" | "oidc";
  enabled: boolean;
  config?: Record<string, unknown>;
}
interface ScimToken {
  id: string;
  createdAt: string;
  expiresAt?: string;
}
interface DomainClaim {
  domain: string;
  recordName?: string;
  recordValue?: string;
  verified: boolean;
}
interface Webhook {
  id: string;
  url: string;
  events: string[];
  active: boolean;
}
interface AuditEvent {
  id: string;
  occurredAt: string;
  actorKind: string;
  actorHandle?: string;
  action: string;
  targetKind?: string;
}
interface AuditExport {
  id: string;
  status: string;
  eventCount?: number;
  downloadPath?: string;
  error?: string;
}
interface OrgInfo {
  handle: string;
  displayName: string;
  ssoRequired?: boolean;
  verifiedDomain?: string;
}

const ROLES = ["owner", "admin", "maintainer", "security_reviewer", "member"];
const WEBHOOK_EVENTS = ["version.published", "version.rejected", "version.yanked", "agent.quarantined"];

function inputStyle() {
  return { borderColor: "var(--color-border)", background: "var(--color-surface)" } as const;
}

export default async function OrgAdminPage({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ ok?: string; error?: string; export?: string; deliveries?: string }>;
}) {
  const { org } = await params;
  const o = encodeURIComponent(org);
  const q = await searchParams;
  if (!(await currentUser())) redirect(`/login?next=/orgs/${o}/admin`);

  let orgInfo: OrgInfo | null = null;
  let members: Membership[] = [];
  try {
    orgInfo = await authedGet<OrgInfo>(`/orgs/${o}`);
    if (!orgInfo) notFound();
    members = (await authedGet<Membership[]>(`/orgs/${o}/members`)) ?? [];
  } catch (e) {
    if (e instanceof AccessError) {
      return <RefusalCard>Org administration requires the admin or owner role in {org}.</RefusalCard>;
    }
    throw e;
  }

  // The sections below tolerate individual 403s (e.g. an admin who is not
  // owner cannot read SSO/SCIM config, which is owner-only) by rendering the refusal.
  const safe = async <T,>(p: Promise<T | null>): Promise<T | null | "forbidden"> => {
    try {
      return await p;
    } catch (e) {
      if (e instanceof AccessError) return "forbidden";
      throw e;
    }
  };

  const [teams, policy, baseline, sso, scim, domains, webhooks, audit] = await Promise.all([
    safe(authedGet<Team[]>(`/orgs/${o}/teams`)),
    safe(authedGet<Record<string, unknown>>(`/orgs/${o}/policy`)),
    safe(authedGet<Record<string, unknown>>(`/platform/policy`)),
    safe(authedGet<SsoConnection[]>(`/orgs/${o}/sso/connections`)),
    safe(authedGet<ScimToken[]>(`/orgs/${o}/scim/tokens`)),
    safe(authedGet<DomainClaim[]>(`/orgs/${o}/domain-claims`)),
    safe(authedGet<Webhook[]>(`/orgs/${o}/webhooks`)),
    safe(authedGet<{ events: AuditEvent[]; nextCursor?: string }>(`/orgs/${o}/audit?limit=50`)),
  ]);
  const exportStatus =
    q.export && /^[0-9a-f-]{36}$/.test(q.export)
      ? await safe(authedGet<AuditExport>(`/orgs/${o}/audit/exports/${encodeURIComponent(q.export)}`))
      : null;

  // Delivery history for the endpoint the admin asked about (?deliveries=id),
  // which is where a "send test delivery" lands: the ping travels the ordinary
  // webhook path, so its recorded attempt shows up here like any other.
  const deliveriesFor = q.deliveries && /^[0-9a-f-]{36}$/.test(q.deliveries) ? q.deliveries : null;
  const deliveries = deliveriesFor
    ? await safe(
        authedGet<WebhookDelivery[]>(
          `/orgs/${o}/webhooks/${encodeURIComponent(deliveriesFor)}/deliveries?limit=20`,
        ),
      )
    : null;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-baseline gap-3">
        <h1 className="text-xl font-semibold">
          <Link href={`/${org}`} className="hover:underline">
            {org}
          </Link>{" "}
          admin
        </h1>
        {orgInfo.ssoRequired && <Badge tone="accent">SSO enforced</Badge>}
        {orgInfo.verifiedDomain && <Badge tone="ok">domain: {orgInfo.verifiedDomain}</Badge>}
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

      {/* Members */}
      <Card>
        <h2 className="mb-2 font-semibold">Members ({members.length})</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
              <th className="py-1 pr-4 font-medium">Handle</th>
              <th className="py-1 pr-4 font-medium">Role</th>
              <th className="py-1 font-medium" aria-label="member actions"></th>
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.user.handle} className="border-b last:border-0" style={{ borderColor: "var(--color-border)" }}>
                <td className="py-2 pr-4">
                  {m.user.handle}
                  {m.viaScim && (
                    <>
                      {" "}
                      <Badge>SCIM</Badge>
                    </>
                  )}
                </td>
                <td className="py-2 pr-4">{m.role}</td>
                <td className="py-2">
                  <form method="post" action={`/orgs/${o}/admin/members`} className="flex flex-wrap items-center gap-2">
                    <input type="hidden" name="handle" value={m.user.handle} />
                    <label>
                      <span className="sr-only">Role for {m.user.handle}</span>
                      <select name="role" defaultValue={m.role} className="rounded-md border px-2 py-1 text-xs" style={inputStyle()}>
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button type="submit" name="action" value="set" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                      Set role
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
        <form method="post" action={`/orgs/${o}/admin/members`} className="mt-3 flex flex-wrap items-end gap-2 text-sm">
          <input type="hidden" name="action" value="set" />
          <label>
            Add member (existing handle)
            <input name="handle" required className="mt-1 rounded-md border px-2 py-1 text-xs" style={inputStyle()} />
          </label>
          <label>
            <span className="sr-only">Role</span>
            <select name="role" defaultValue="member" className="rounded-md border px-2 py-1 text-xs" style={inputStyle()}>
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
      </Card>

      {/* Teams */}
      <Card>
        <h2 className="mb-2 font-semibold">Teams</h2>
        {teams === "forbidden" ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>Not visible to your role.</p>
        ) : (
          <>
            <ul className="flex flex-col gap-1 text-sm">
              {(teams ?? []).map((t) => (
                <li key={t.id} className="flex items-center gap-2">
                  <span className="font-mono">{t.slug}</span>
                  <form method="post" action={`/orgs/${o}/admin/teams`}>
                    <input type="hidden" name="slug" value={t.slug} />
                    <button type="submit" name="action" value="delete" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                      Delete
                    </button>
                  </form>
                </li>
              ))}
              {(teams ?? []).length === 0 && (
                <li style={{ color: "var(--color-muted)" }}>No teams.</li>
              )}
            </ul>
            <form method="post" action={`/orgs/${o}/admin/teams`} className="mt-3 flex items-end gap-2 text-sm">
              <input type="hidden" name="action" value="create" />
              <label>
                New team slug
                <input name="slug" required pattern="[a-z0-9][a-z0-9-]*" className="mt-1 rounded-md border px-2 py-1 text-xs" style={inputStyle()} />
              </label>
              <button type="submit" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                Create
              </button>
            </form>
          </>
        )}
      </Card>

      {/* Policy */}
      <Card>
        <h2 className="mb-2 font-semibold">Publication policy</h2>
        {policy === "forbidden" ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>Not visible to your role.</p>
        ) : (
          <>
            <p className="mb-2 text-sm" style={{ color: "var(--color-muted)" }}>
              Org policy may only tighten the platform baseline (§8.6). Baseline:{" "}
              <code className="text-xs">{baseline && baseline !== "forbidden" ? JSON.stringify(baseline) : "…"}</code>
            </p>
            <form method="post" action={`/orgs/${o}/admin/policy`} className="flex flex-col gap-2">
              <label className="text-sm">
                Policy document (JSON)
                <textarea
                  name="policy"
                  rows={4}
                  className="mt-1 w-full rounded-md border px-3 py-2 font-mono text-xs"
                  style={inputStyle()}
                  defaultValue={JSON.stringify(policy ?? {}, null, 2)}
                />
              </label>
              <div>
                <button type="submit" className="rounded-md border px-3 py-1.5 text-sm" style={{ borderColor: "var(--color-border)" }}>
                  Save policy
                </button>
              </div>
            </form>
          </>
        )}
      </Card>

      {/* SSO */}
      <Card>
        <h2 className="mb-2 font-semibold">Single sign-on</h2>
        {sso === "forbidden" ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>SSO configuration is owner-only.</p>
        ) : (
          <>
            <ul className="mb-3 flex flex-col gap-1 text-sm">
              {(sso ?? []).map((c) => (
                <li key={c.kind} className="flex items-center gap-2">
                  <Badge tone={c.enabled ? "ok" : "neutral"}>{c.kind}</Badge>
                  <span style={{ color: "var(--color-muted)" }}>{c.enabled ? "enabled" : "configured, disabled"}</span>
                  <form method="post" action={`/orgs/${o}/admin/sso`}>
                    <input type="hidden" name="kind" value={c.kind} />
                    <button type="submit" name="action" value="delete" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                      Delete
                    </button>
                  </form>
                </li>
              ))}
              {(sso ?? []).length === 0 && <li style={{ color: "var(--color-muted)" }}>No connections configured.</li>}
            </ul>
            <details className="mb-2">
              <summary className="cursor-pointer text-sm font-medium">Configure SAML</summary>
              <form method="post" action={`/orgs/${o}/admin/sso`} className="mt-2 flex flex-col gap-2 text-sm">
                <input type="hidden" name="kind" value="saml" />
                <input type="hidden" name="action" value="put" />
                <label>
                  IdP metadata XML
                  <textarea name="idpMetadataXml" rows={4} required className="mt-1 w-full rounded-md border px-3 py-2 font-mono text-xs" style={inputStyle()} />
                </label>
                <label className="flex items-center gap-2">
                  <input type="checkbox" name="enabled" value="true" defaultChecked /> Enabled
                </label>
                <div>
                  <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
                    Save SAML connection
                  </button>
                </div>
              </form>
            </details>
            <details>
              <summary className="cursor-pointer text-sm font-medium">Configure OIDC</summary>
              <form method="post" action={`/orgs/${o}/admin/sso`} className="mt-2 flex flex-col gap-2 text-sm">
                <input type="hidden" name="kind" value="oidc" />
                <input type="hidden" name="action" value="put" />
                <label>
                  Issuer URL
                  <input name="issuer" required className="mt-1 w-full rounded-md border px-2 py-1 text-xs" style={inputStyle()} />
                </label>
                <label>
                  Client ID
                  <input name="clientId" required className="mt-1 w-full rounded-md border px-2 py-1 text-xs" style={inputStyle()} />
                </label>
                <label>
                  Client secret (stored sealed; leave blank to keep current)
                  <input name="clientSecret" type="password" autoComplete="off" className="mt-1 w-full rounded-md border px-2 py-1 text-xs" style={inputStyle()} />
                </label>
                <label className="flex items-center gap-2">
                  <input type="checkbox" name="enabled" value="true" defaultChecked /> Enabled
                </label>
                <div>
                  <button type="submit" className="rounded-md border px-3 py-1.5" style={{ borderColor: "var(--color-border)" }}>
                    Save OIDC connection
                  </button>
                </div>
              </form>
            </details>
            <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
              SP metadata: <code>/api/v1/orgs/{org}/sso/saml/metadata</code> · Enforced SSO is enabled
              separately once a connection is verified (org settings API).
            </p>
          </>
        )}
      </Card>

      {/* SCIM */}
      <Card>
        <h2 className="mb-2 font-semibold">SCIM provisioning</h2>
        {scim === "forbidden" ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>SCIM configuration is owner-only.</p>
        ) : (
          <>
            <ul className="mb-3 flex flex-col gap-1 text-sm">
              {(scim ?? []).map((t) => (
                <li key={t.id} className="flex items-center gap-2">
                  <span className="font-mono text-xs">{t.id}</span>
                  <span style={{ color: "var(--color-muted)" }}>created {fmtUTCDate(t.createdAt)}</span>
                  <form method="post" action={`/orgs/${o}/admin/scim`}>
                    <input type="hidden" name="tokenId" value={t.id} />
                    <button type="submit" name="action" value="revoke" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                      Revoke
                    </button>
                  </form>
                </li>
              ))}
              {(scim ?? []).length === 0 && <li style={{ color: "var(--color-muted)" }}>No SCIM tokens.</li>}
            </ul>
            <form method="post" action={`/orgs/${o}/admin/scim`}>
              <button type="submit" name="action" value="create" className="rounded-md border px-3 py-1.5 text-sm" style={{ borderColor: "var(--color-border)" }}>
                Create SCIM token
              </button>
            </form>
            <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
              The token is shown exactly once, on creation. Base URL: <code>/scim/v2</code>.
            </p>
          </>
        )}
      </Card>

      {/* Domains */}
      <Card>
        <h2 className="mb-2 font-semibold">Domain verification</h2>
        {domains === "forbidden" ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>Not visible to your role.</p>
        ) : (
          <>
            <ul className="mb-3 flex flex-col gap-2 text-sm">
              {(domains ?? []).map((d) => (
                <li key={d.domain}>
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{d.domain}</span>
                    {d.verified ? (
                      <Badge tone="ok">verified</Badge>
                    ) : (
                      <form method="post" action={`/orgs/${o}/admin/domains`} className="inline">
                        <input type="hidden" name="domain" value={d.domain} />
                        <button type="submit" name="action" value="verify" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-border)" }}>
                          Verify now
                        </button>
                      </form>
                    )}
                  </div>
                  {!d.verified && d.recordName && (
                    <p className="mt-1 font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                      TXT {d.recordName} = {d.recordValue}
                    </p>
                  )}
                </li>
              ))}
              {(domains ?? []).length === 0 && <li style={{ color: "var(--color-muted)" }}>No domain claims.</li>}
            </ul>
            <form method="post" action={`/orgs/${o}/admin/domains`} className="flex items-end gap-2 text-sm">
              <input type="hidden" name="action" value="claim" />
              <label>
                Claim domain
                <input name="domain" required placeholder="example.com" className="mt-1 rounded-md border px-2 py-1 text-xs" style={inputStyle()} />
              </label>
              <button type="submit" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                Claim
              </button>
            </form>
          </>
        )}
      </Card>

      {/* Webhooks */}
      <Card>
        <h2 className="mb-2 font-semibold">Webhooks</h2>
        {webhooks === "forbidden" ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>Not visible to your role.</p>
        ) : (
          <>
            <ul className="mb-3 flex flex-col gap-1 text-sm">
              {(webhooks ?? []).map((wh) => (
                <li key={wh.id} className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs">{wh.url}</span>
                  <span style={{ color: "var(--color-muted)" }}>{wh.events.join(", ")}</span>
                  {!wh.active && <Badge tone="warn">inactive</Badge>}
                  <form method="post" action={`/orgs/${o}/admin/webhooks`} className="flex items-center gap-2">
                    <input type="hidden" name="id" value={wh.id} />
                    {/* A ping goes through the ordinary delivery machinery
                        (same envelope, HMAC signature, SSRF guard and retry
                        ladder), so it answers "does my endpoint work" with the
                        code that will actually call it (DEV-021). */}
                    <button type="submit" name="action" value="ping" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-border)" }}>
                      Send test delivery
                    </button>
                    <button type="submit" name="action" value="delete" className="rounded-md border px-2 py-0.5 text-xs" style={{ borderColor: "var(--color-sev-high)", color: "var(--color-sev-high)" }}>
                      Delete
                    </button>
                  </form>
                  <Link
                    href={`/orgs/${o}/admin?deliveries=${encodeURIComponent(wh.id)}`}
                    className="text-xs underline"
                  >
                    {deliveriesFor === wh.id ? "deliveries (shown below)" : "deliveries"}
                  </Link>
                </li>
              ))}
              {(webhooks ?? []).length === 0 && <li style={{ color: "var(--color-muted)" }}>No webhook endpoints.</li>}
            </ul>
            <form method="post" action={`/orgs/${o}/admin/webhooks`} className="flex flex-wrap items-end gap-2 text-sm">
              <input type="hidden" name="action" value="create" />
              <label className="grow">
                HTTPS endpoint
                <input name="url" required type="url" placeholder="https://…" className="mt-1 w-full rounded-md border px-2 py-1 text-xs" style={inputStyle()} />
              </label>
              <fieldset className="flex items-center gap-2">
                <legend className="sr-only">Events</legend>
                {WEBHOOK_EVENTS.map((ev) => (
                  <label key={ev} className="flex items-center gap-1 text-xs">
                    <input type="checkbox" name="events" value={ev} defaultChecked={ev === "version.published"} />
                    {ev}
                  </label>
                ))}
              </fieldset>
              <button type="submit" className="rounded-md border px-2 py-1 text-xs" style={{ borderColor: "var(--color-border)" }}>
                Create
              </button>
            </form>
            <p className="mt-2 text-xs" style={{ color: "var(--color-muted)" }}>
              Deliveries are HMAC-signed; the secret is shown once on creation (§9.3).
            </p>

            {deliveriesFor && deliveries !== "forbidden" && (
              <div className="mt-4">
                <h3 className="mb-2 text-sm font-semibold">
                  Recent deliveries{" "}
                  <span className="font-normal" style={{ color: "var(--color-muted)" }}>
                    for <code className="text-xs">{deliveriesFor.slice(0, 8)}</code>
                  </span>
                </h3>
                {(deliveries ?? []).length === 0 ? (
                  <p className="text-sm" style={{ color: "var(--color-muted)" }}>
                    No delivery attempts recorded yet. Send a test delivery to make one.
                  </p>
                ) : (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
                        <th className="py-1 pr-4 font-medium">Queued</th>
                        <th className="py-1 pr-4 font-medium">Event</th>
                        <th className="py-1 pr-4 font-medium">Attempt</th>
                        <th className="py-1 font-medium">Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(deliveries ?? []).map((d) => (
                        <tr key={d.id} className="border-b last:border-0" style={{ borderColor: "var(--color-border)" }}>
                          <td className="py-1 pr-4 whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                            {fmtUTC(d.createdAt)}
                          </td>
                          <td className="py-1 pr-4 font-mono text-xs">{d.eventType}</td>
                          <td className="py-1 pr-4">{d.attempt}</td>
                          <td className="py-1">
                            {d.statusCode ? (
                              <Badge tone={d.statusCode < 300 ? "ok" : "danger"}>{d.statusCode}</Badge>
                            ) : d.error ? (
                              <Badge tone="danger" title={d.error}>
                                failed
                              </Badge>
                            ) : (
                              <Badge tone="neutral">pending</Badge>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </>
        )}
      </Card>

      {/* Audit */}
      <Card>
        <h2 className="mb-2 font-semibold">Audit log</h2>
        {audit === "forbidden" ? (
          <p className="text-sm" style={{ color: "var(--color-muted)" }}>Audit access requires admin.</p>
        ) : (
          <>
            <div className="mb-3 flex items-center gap-3">
              <form method="post" action={`/orgs/${o}/admin/audit`}>
                <button type="submit" className="rounded-md border px-3 py-1.5 text-sm" style={{ borderColor: "var(--color-border)" }}>
                  Export as NDJSON
                </button>
              </form>
              {exportStatus && exportStatus !== "forbidden" && (
                <span className="text-sm">
                  export <code className="text-xs">{exportStatus.id.slice(0, 8)}</code>:{" "}
                  <Badge tone={exportStatus.status === "completed" ? "ok" : exportStatus.status === "failed" ? "danger" : "neutral"}>
                    {exportStatus.status}
                  </Badge>{" "}
                  {exportStatus.status === "completed" && (
                    <span style={{ color: "var(--color-muted)" }}>
                      {exportStatus.eventCount} events → {exportStatus.downloadPath}
                    </span>
                  )}
                </span>
              )}
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left" style={{ borderColor: "var(--color-border)" }}>
                  <th className="py-1 pr-4 font-medium">When</th>
                  <th className="py-1 pr-4 font-medium">Actor</th>
                  <th className="py-1 pr-4 font-medium">Action</th>
                  <th className="py-1 font-medium">Target</th>
                </tr>
              </thead>
              <tbody>
                {(audit?.events ?? []).map((ev) => (
                  <tr key={ev.id} className="border-b last:border-0" style={{ borderColor: "var(--color-border)" }}>
                    <td className="py-1 pr-4 whitespace-nowrap" style={{ color: "var(--color-muted)" }}>
                      {fmtUTC(ev.occurredAt)}
                    </td>
                    <td className="py-1 pr-4">{ev.actorHandle ?? ev.actorKind}</td>
                    <td className="py-1 pr-4 font-mono text-xs">{ev.action}</td>
                    <td className="py-1 font-mono text-xs" style={{ color: "var(--color-muted)" }}>
                      {ev.targetKind ?? ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </Card>
    </div>
  );
}
